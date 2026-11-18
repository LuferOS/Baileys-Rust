use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=WAProto/WAProto.proto");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_out = out_dir.join("waproto_gen");
    let _ = fs::remove_dir_all(&proto_out);
    fs::create_dir_all(&proto_out).unwrap();

    prost_build::Config::new()
        .out_dir(&proto_out)
        .default_package_filename("proto")
        .compile_protos(&["WAProto/WAProto.proto"], &["WAProto"])
        .expect("Failed to compile WAProto/WAProto.proto");

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
