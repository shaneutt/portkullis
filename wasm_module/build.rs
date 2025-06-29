fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "anomaly_detection_engine")]
    {
        let proto_file = "../anomaly_detection_engine/proto/anomaly.proto";

        tonic_build::configure()
            .build_server(false)
            .build_client(false)
            .compile_protos(&[proto_file], &["../anomaly_detection_engine/proto"])?;
    }

    Ok(())
}
