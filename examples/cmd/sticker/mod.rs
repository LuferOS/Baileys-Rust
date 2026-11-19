use baileys_rs::defaults::MediaType;
use baileys_rs::proto::message::{ExtendedTextMessage, ImageMessage, StickerMessage};
use baileys_rs::proto::Message;
use baileys_rs::socket::MessagesSocket;
use baileys_rs::types::WaMessage;
use baileys_rs::utils::{
    download_content_from_message, encrypted_stream, normalize_message_content,
    unix_timestamp_seconds, upload_media_to_server, AnyMessageContent, DownloadableMessage,
    MediaDownloadOptions, MessageGenerationOptions, WaMediaUpload,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::BotContext;

static STICKER_SEQ: AtomicU64 = AtomicU64::new(0);

struct StickerTimings {
    dl_ms: f64,
    webp_ms: f64,
    enc_ms: f64,
    up_ms: f64,
}

fn find_image_message(msg: &WaMessage) -> Option<ImageMessage> {
    let proto = msg.message.as_ref()?;
    let norm = normalize_message_content(proto);
    if let Some(ref img) = norm.image_message {
        let inner: &ImageMessage = Borrow::borrow(img);
        return Some(inner.clone());
    }
    if let Some(ref ext) = norm.extended_text_message {
        let inner: &ExtendedTextMessage = Borrow::borrow(ext);
        if let Some(ref ctx) = inner.context_info {
            if let Some(ref quoted_msg) = ctx.quoted_message {
                let q_norm = normalize_message_content(quoted_msg);
                if let Some(ref q_img) = q_norm.image_message {
                    let q_inner: &ImageMessage = Borrow::borrow(q_img);
                    return Some(q_inner.clone());
                }
            }
        }
    }
    None
}

async fn encode_sticker_webp(
    raw_bytes: &[u8],
    img: &ImageMessage,
    tmp_dir: &Path,
) -> Result<Vec<u8>, String> {
    let seq = STICKER_SEQ.fetch_add(1, Ordering::Relaxed);
    let stamp = format!("{}_{}_{}", std::process::id(), unix_timestamp_seconds(), seq);
    let in_img = tmp_dir.join(format!("aura_in_{}.img", stamp));
    let out_webp = tmp_dir.join(format!("aura_out_{}.webp", stamp));

    tokio::fs::write(&in_img, raw_bytes)
        .await
        .map_err(|e| format!("tmp img: {}", e))?;

    let w = img.width.unwrap_or(0);
    let h = img.height.unwrap_or(0);

    let ffmpeg_ok = tokio::process::Command::new("ffmpeg")
        .arg("-y")
        .arg("-loglevel")
        .arg("error")
        .arg("-threads")
        .arg("8")
        .arg("-filter_threads")
        .arg("8")
        .arg("-i")
        .arg(&in_img)
        .arg("-vf")
        .arg("scale=512:512:force_original_aspect_ratio=decrease:flags=fast_bilinear,pad=512:512:(ow-iw)/2:(oh-ih)/2:color=0x00000000")
        .arg("-c:v")
        .arg("libwebp")
        .arg("-quality")
        .arg("72")
        .arg("-compression_level")
        .arg("0")
        .arg(&out_webp)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ffmpeg_ok {
        let bytes = tokio::fs::read(&out_webp)
            .await
            .map_err(|e| format!("read webp: {}", e))?;
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(in_img).await;
            let _ = tokio::fs::remove_file(out_webp).await;
        });
        return Ok(bytes);
    }

    let resize_args: (&str, &str) = if h > w && h > 0 {
        ("0", "512")
    } else {
        ("512", "0")
    };

    let cwebp_ok = tokio::process::Command::new("cwebp")
        .arg("-q")
        .arg("72")
        .arg("-m")
        .arg("0")
        .arg("-mt")
        .arg("-resize")
        .arg(resize_args.0)
        .arg(resize_args.1)
        .arg(&in_img)
        .arg("-o")
        .arg(&out_webp)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if cwebp_ok {
        let bytes = tokio::fs::read(&out_webp)
            .await
            .map_err(|e| format!("read webp: {}", e))?;
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(in_img).await;
            let _ = tokio::fs::remove_file(out_webp).await;
        });
        return Ok(bytes);
    }

    tokio::spawn(async move {
        let _ = tokio::fs::remove_file(in_img).await;
        let _ = tokio::fs::remove_file(out_webp).await;
    });
    Ok(raw_bytes.to_vec())
}

async fn build_sticker_from_image(
    messages: &Arc<MessagesSocket>,
    img: &ImageMessage,
) -> Result<(StickerMessage, StickerTimings), String> {
    let t_dl = Instant::now();
    let dl_msg = DownloadableMessage {
        media_key: img.media_key.clone(),
        direct_path: img.direct_path.clone(),
        url: img.url.clone(),
    };
    let dl_opts = MediaDownloadOptions {
        timeout_ms: Some(8_000),
        ..Default::default()
    };

    let raw_bytes = download_content_from_message(&dl_msg, MediaType::Image, &dl_opts)
        .await
        .map_err(|e| format!("descarga: {}", e))?;
    let dl_ms = t_dl.elapsed().as_secs_f64() * 1000.0;

    let t_webp = Instant::now();
    let tmp_dir = std::env::var_os("PREFIX")
        .map(|p| PathBuf::from(p).join("tmp"))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;

    let sticker_bytes = encode_sticker_webp(&raw_bytes, img, &tmp_dir).await?;
    let webp_ms = t_webp.elapsed().as_secs_f64() * 1000.0;

    let t_enc = Instant::now();
    let (sha_vec, final_bytes) = tokio::task::spawn_blocking(move || {
        let mut h = Sha256::new();
        h.update(&sticker_bytes);
        (h.finalize().to_vec(), sticker_bytes)
    })
    .await
    .map_err(|e| format!("hash task: {}", e))?;

    let upload_input = WaMediaUpload::Bytes(final_bytes);
    let enc = encrypted_stream(&upload_input, MediaType::Sticker, false)
        .await
        .map_err(|e| format!("cifrado: {}", e))?;

    let enc_len = tokio::fs::metadata(&enc.enc_file_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let enc_ms = t_enc.elapsed().as_secs_f64() * 1000.0;

    let t_up = Instant::now();
    let file_enc_sha256_b64 = BASE64.encode(&enc.file_enc_sha256);
    let headers = HashMap::new();
    let upload_res = upload_media_to_server(
        &enc.enc_file_path,
        MediaType::Sticker,
        &file_enc_sha256_b64,
        messages,
        &[],
        &headers,
        Some(8_000),
    )
    .await;
    let up_ms = t_up.elapsed().as_secs_f64() * 1000.0;

    let enc_path = enc.enc_file_path.clone();
    let orig_path = enc.original_file_path.clone();
    tokio::spawn(async move {
        let _ = tokio::fs::remove_file(enc_path).await;
        if let Some(p) = orig_path {
            let _ = tokio::fs::remove_file(p).await;
        }
    });

    let up = upload_res.map_err(|e| format!("upload: {}", e))?;

    let sticker = StickerMessage {
        url: Some(up.media_url),
        direct_path: Some(up.direct_path),
        media_key: Some(enc.media_key),
        file_enc_sha256: Some(enc.file_enc_sha256),
        file_sha256: Some(sha_vec),
        file_length: Some(enc_len),
        mimetype: Some("image/webp".to_string()),
        width: Some(512),
        height: Some(512),
        is_animated: Some(false),
        ..Default::default()
    };

    Ok((
        sticker,
        StickerTimings {
            dl_ms,
            webp_ms,
            enc_ms,
            up_ms,
        },
    ))
}

async fn send_text(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    remote_jid: &str,
    quoted: WaMessage,
    user_jid: Option<String>,
    text: String,
) {
    let opts = MessageGenerationOptions {
        user_jid,
        message_id: None,
        timestamp: None,
        quoted: Some(Box::new(quoted)),
        ephemeral_expiration: None,
        mentions: Vec::new(),
        view_once: false,
        edit: None,
        context_info: None,
        background_color: None,
        font: None,
    };
    if let Err(err) = messages
        .send_message(remote_jid, AnyMessageContent::Text(text), opts)
        .await
    {
        ctx.debug
            .record_error("sticker_text", format!("{}: {}", remote_jid, err))
            .await;
    }
}

pub async fn run(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    message: WaMessage,
    cmd: &str,
    _args: &str,
    me_jid: Option<String>,
) -> bool {
    if !matches!(cmd, "s" | "sticker") {
        return false;
    }

    let Some(remote_jid) = message.key.remote_jid.clone() else {
        return true;
    };
    let Some(img) = find_image_message(&message) else {
        send_text(
            messages,
            ctx,
            &remote_jid,
            message,
            me_jid,
            "Envia o responde a una imagen con `.s`.".to_string(),
        )
        .await;
        return true;
    };

    let t_total = Instant::now();
    let (sticker_msg, timings) = match build_sticker_from_image(messages, &img).await {
        Ok(res) => res,
        Err(err) => {
            ctx.debug.record_error("sticker", &err).await;
            send_text(
                messages,
                ctx,
                &remote_jid,
                message,
                me_jid,
                format!("Error sticker: {}", err),
            )
            .await;
            return true;
        }
    };

    let opts = MessageGenerationOptions {
        user_jid: me_jid.clone(),
        message_id: None,
        timestamp: None,
        quoted: Some(Box::new(message.clone())),
        ephemeral_expiration: None,
        mentions: Vec::new(),
        view_once: false,
        edit: None,
        context_info: None,
        background_color: None,
        font: None,
    };

    let t_send = Instant::now();
    match messages
        .send_message(
            &remote_jid,
            AnyMessageContent::Raw(Message {
                sticker_message: Some(sticker_msg.into()),
                ..Default::default()
            }),
            opts,
        )
        .await
    {
        Ok(_) => {
            let send_ms = t_send.elapsed().as_secs_f64() * 1000.0;
            let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;
            let summary = format!(
                "total={:.0}ms (dl={:.0} webp={:.0} enc={:.0} up={:.0} send={:.0})",
                total_ms, timings.dl_ms, timings.webp_ms, timings.enc_ms, timings.up_ms, send_ms
            );
            ctx.debug.record_timing("sticker", &summary).await;
            send_text(
                messages,
                ctx,
                &remote_jid,
                message,
                me_jid,
                format!(
                    "*Sticker listo* en *{:.2} ms*\n`dl {:.0} | webp {:.0} | enc {:.0} | up {:.0} | send {:.0}`",
                    total_ms, timings.dl_ms, timings.webp_ms, timings.enc_ms, timings.up_ms, send_ms
                ),
            )
            .await;
        }
        Err(err) => {
            ctx.debug
                .record_error("sticker_send", format!("{}", err))
                .await;
            send_text(
                messages,
                ctx,
                &remote_jid,
                message,
                me_jid,
                format!("Error envio sticker: {}", err),
            )
            .await;
        }
    }

    true
}
