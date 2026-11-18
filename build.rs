use std::env;
use std::fs;
use std::path::PathBuf;

fn sanitize_proto3_enums(src: &str) -> String {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + 1024);
    let mut i = 0;
    let mut zero_counter = 0usize;

    while i < len {
        // Copiar comentarios de línea intactos
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            let start = i;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            out.push_str(&src[start..i]);
            continue;
        }

        // Detectar palabra clave `enum `
        let is_enum_kw = src[i..].starts_with("enum")
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
            && i + 4 < len
            && bytes[i + 4].is_ascii_whitespace();

        if is_enum_kw {
            if let Some(rel_open) = src[i..].find('{') {
                let open_idx = i + rel_open;
                if let Some(rel_close) = src[open_idx + 1..].find('}') {
                    let close_idx = open_idx + 1 + rel_close;
                    let header = &src[i..=open_idx];
                    let body = &src[open_idx + 1..close_idx];

                    let fixed_body = fix_enum_body(body, &mut zero_counter);
                    out.push_str(header);
                    out.push_str(&fixed_body);
                    out.push('}');
                    i = close_idx + 1;
                    continue;
                }
            }
        }

        let ch = src[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn parse_enum_value_num(stmt: &str) -> Option<i64> {
    let trimmed = stmt.trim();
    if trimmed.is_empty() || trimmed.starts_with("option ") || trimmed.starts_with("reserved ") {
        return None;
    }
    // Quitar comentarios iniciales dentro del bloque
    let mut clean = trimmed;
    while clean.starts_with("//") {
        if let Some(nl) = clean.find('\n') {
            clean = clean[nl + 1..].trim();
        } else {
            return None;
        }
    }
    if clean.is_empty() || clean.starts_with("option ") || clean.starts_with("reserved ") {
        return None;
    }
    let (_, rhs) = clean.split_once('=')?;
    let num_str = rhs
        .split('[')
        .next()
        .unwrap_or(rhs)
        .split("//")
        .next()
        .unwrap_or(rhs)
        .trim();
    num_str.parse::<i64>().ok()
}

fn fix_enum_body(body: &str, zero_counter: &mut usize) -> String {
    let mut statements: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = body.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            cur.push(c);
            for nc in chars.by_ref() {
                cur.push(nc);
                if nc == '\n' {
                    break;
                }
            }
            continue;
        }
        cur.push(c);
        if c == ';' {
            statements.push(std::mem::take(&mut cur));
        }
    }
    let tail = cur;

    let first_val_idx = statements
        .iter()
        .position(|s| parse_enum_value_num(s).is_some());

    let Some(first_idx) = first_val_idx else {
        return body.to_string();
    };

    if parse_enum_value_num(&statements[first_idx]) == Some(0) {
        return body.to_string();
    }

    if let Some(zero_idx) = statements
        .iter()
        .position(|s| parse_enum_value_num(s) == Some(0))
    {
        let zero_stmt = statements.remove(zero_idx);
        statements.insert(first_idx, zero_stmt);
    } else {
        *zero_counter += 1;
        statements.insert(
            first_idx,
            format!(" PROTO3_AUTO_ZERO_{} = 0;", *zero_counter),
        );
    }

    let mut result = statements.concat();
    result.push_str(&tail);
    result
}

fn main() {
    println!("cargo:rerun-if-changed=WAProto/WAProto.proto");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_out = out_dir.join("waproto_gen");
    let _ = fs::remove_dir_all(&proto_out);
    fs::create_dir_all(&proto_out).unwrap();

    let raw_proto = fs::read_to_string("WAProto/WAProto.proto")
        .expect("Failed to read WAProto/WAProto.proto");
    let sanitized_proto = sanitize_proto3_enums(&raw_proto);
    let sanitized_path = out_dir.join("WAProto.sanitized.proto");
    fs::write(&sanitized_path, sanitized_proto).unwrap();

    prost_build::Config::new()
        .out_dir(&proto_out)
        .default_package_filename("proto")
        .compile_protos(&[&sanitized_path], &[&out_dir])
        .expect("Failed to compile WAProto.proto");

    let mut generated: Vec<PathBuf> = fs::read_dir(&proto_out)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("rs"))
        .collect();
    generated.sort();

    let mut include_file = String::new();
    for path in generated {
        include_file.push_str(&format!("include!({:?});\n", path.to_string_lossy()));
    }
    fs::write(out_dir.join("waproto.rs"), include_file).unwrap();
}
