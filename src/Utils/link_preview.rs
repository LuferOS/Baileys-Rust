use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

pub const THUMBNAIL_WIDTH_PX: u32 = 192;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Error)]
pub enum LinkPreviewError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

#[derive(Debug, Clone)]
pub struct UrlGenerationOptions {
    pub thumbnail_width: u32,
    pub timeout_ms: u64,
    pub headers: HashMap<String, String>,
    pub fetch_thumbnail: bool,
}

impl Default for UrlGenerationOptions {
    fn default() -> Self {
        Self {
            thumbnail_width: THUMBNAIL_WIDTH_PX,
            timeout_ms: 3000,
            headers: HashMap::new(),
            fetch_thumbnail: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaUrlInfo {
    pub canonical_url: String,
    pub matched_text: String,
    pub title: String,
    pub description: Option<String>,
    pub original_thumbnail_url: Option<String>,
    pub jpeg_thumbnail: Option<Vec<u8>>,
}

fn is_allowed_redirect_host(base_host: &str, forwarded_host: &str) -> bool {
    forwarded_host.eq_ignore_ascii_case(base_host)
        || forwarded_host.eq_ignore_ascii_case(&format!("www.{}", base_host))
        || base_host.eq_ignore_ascii_case(&format!("www.{}", forwarded_host))
}

fn decode_html_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{}=", attr_name.to_ascii_lowercase());
    let mut search_start = 0;

    while let Some(pos) = lower[search_start..].find(&needle) {
        let abs_pos = search_start + pos;
        let prev_ok = abs_pos == 0
            || lower.as_bytes()[abs_pos - 1].is_ascii_whitespace();
        if !prev_ok {
            search_start = abs_pos + needle.len();
            continue;
        }
        let val_start = abs_pos + needle.len();
        let rest = tag[val_start..].trim_start();
        if let Some(quote) = rest.chars().next().filter(|&c| c == '"' || c == '\'') {
            let after_quote = &rest[1..];
            if let Some(end) = after_quote.find(quote) {
                return Some(decode_html_entities(&after_quote[..end]));
            }
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .unwrap_or(rest.len());
            return Some(decode_html_entities(&rest[..end]));
        }
        break;
    }
    None
}

pub fn parse_html_link_metadata(
    html: &str,
    canonical_url: &str,
    matched_text: &str,
) -> Option<WaUrlInfo> {
    let mut og_title: Option<String> = None;
    let mut og_description: Option<String> = None;
    let mut meta_description: Option<String> = None;
    let mut og_image: Option<String> = None;

    let lower_html = html.to_ascii_lowercase();
    let mut cursor = 0;
    while let Some(rel_start) = lower_html[cursor..].find("<meta") {
        let start = cursor + rel_start;
        let Some(rel_end) = lower_html[start..].find('>') else {
            break;
        };
        let tag = &html[start..=start + rel_end];
        cursor = start + rel_end + 1;

        let prop = extract_attr(tag, "property")
            .or_else(|| extract_attr(tag, "name"))
            .map(|s| s.to_ascii_lowercase());
        let content = extract_attr(tag, "content").filter(|s| !s.is_empty());

        if let (Some(p), Some(c)) = (prop, content) {
            match p.as_str() {
                "og:title" | "twitter:title" if og_title.is_none() => og_title = Some(c),
                "og:description" | "twitter:description" if og_description.is_none() => {
                    og_description = Some(c);
                }
                "description" if meta_description.is_none() => meta_description = Some(c),
                "og:image" | "twitter:image" if og_image.is_none() => og_image = Some(c),
                _ => {}
            }
        }
    }

    let html_title = lower_html.find("<title").and_then(|t_start| {
        let open_end = lower_html[t_start..].find('>')? + t_start + 1;
        let close_start = lower_html[open_end..].find("</title>")? + open_end;
        let raw = decode_html_entities(&html[open_end..close_start]);
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    });

    let title = og_title.or(html_title)?;
    let description = og_description.or(meta_description);

    let resolved_image = og_image.and_then(|img| {
        if img.starts_with("http://") || img.starts_with("https://") {
            Some(img)
        } else {
            Url::parse(canonical_url)
                .ok()
                .and_then(|base| base.join(&img).ok())
                .map(|u| u.to_string())
        }
    });

    Some(WaUrlInfo {
        canonical_url: canonical_url.to_string(),
        matched_text: matched_text.to_string(),
        title,
        description,
        original_thumbnail_url: resolved_image,
        jpeg_thumbnail: None,
    })
}

pub async fn get_url_info(
    text: &str,
    opts: &UrlGenerationOptions,
) -> Result<Option<WaUrlInfo>, LinkPreviewError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let preview_link = if text.starts_with("https://") || text.starts_with("http://") {
        text.to_string()
    } else {
        format!("https://{}", text)
    };

    let mut current_url =
        Url::parse(&preview_link).map_err(|_| LinkPreviewError::InvalidUrl(preview_link.clone()))?;

    let mut headers = HeaderMap::new();
    for (k, v) in &opts.headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            headers.insert(name, val);
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(opts.timeout_ms))
        .redirect(Policy::none())
        .build()?;

    let mut redirects = 0usize;
    let final_resp = loop {
        let resp = client
            .get(current_url.clone())
            .headers(headers.clone())
            .send()
            .await?;

        if resp.status().is_redirection() {
            if redirects >= MAX_REDIRECTS {
                return Ok(None);
            }
            let Some(loc) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) else {
                break resp;
            };
            let Ok(next_url) = current_url.join(loc) else {
                return Ok(None);
            };
            let (Some(base_host), Some(next_host)) = (current_url.host_str(), next_url.host_str())
            else {
                return Ok(None);
            };
            if !is_allowed_redirect_host(base_host, next_host) {
                return Ok(None);
            }
            current_url = next_url;
            redirects += 1;
            continue;
        }

        break resp;
    };

    if !final_resp.status().is_success() {
        return Ok(None);
    }

    let canonical_url = final_resp.url().to_string();
    let html = final_resp.text().await?;
    let Some(mut info) = parse_html_link_metadata(&html, &canonical_url, text) else {
        return Ok(None);
    };

    if opts.fetch_thumbnail {
        if let Some(ref img_url) = info.original_thumbnail_url {
            if let Ok(img_resp) = client
                .get(img_url)
                .headers(headers)
                .send()
                .await
            {
                if img_resp.status().is_success() {
                    if let Ok(bytes) = img_resp.bytes().await {
                        info.jpeg_thumbnail = Some(bytes.to_vec());
                    }
                }
            }
        }
    }

    Ok(Some(info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_html_link_metadata_and_redirect_guard() {
        let html = r#"
            <html>
                <head>
                    <title>Fallback Title</title>
                    <meta property="og:title" content="Baileys &amp; Rust" />
                    <meta property="og:description" content="Port nativo en Rust" />
                    <meta property="og:image" content="/assets/preview.jpg" />
                </head>
            </html>
        "#;

        let info = parse_html_link_metadata(
            html,
            "https://github.com/LuferOS/Baileys-Rust",
            "github.com/LuferOS/Baileys-Rust",
        )
        .unwrap();

        assert_eq!(info.title, "Baileys & Rust");
        assert_eq!(info.description.as_deref(), Some("Port nativo en Rust"));
        assert_eq!(
            info.original_thumbnail_url.as_deref(),
            Some("https://github.com/assets/preview.jpg")
        );

        assert!(is_allowed_redirect_host("github.com", "www.github.com"));
        assert!(is_allowed_redirect_host("www.github.com", "github.com"));
        assert!(!is_allowed_redirect_host("github.com", "evil.com"));
    }
}
