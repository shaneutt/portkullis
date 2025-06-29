use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("anomaly_detection_engine")
        .join("proto")
        .join("anomaly.proto");

    tonic_build::compile_protos(&proto_file)?;
    Ok(())
}
