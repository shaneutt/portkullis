use std::env;
use std::fs;

use qdrant_client::{
    Qdrant,
    qdrant::{
        CreateCollection, Distance, PointStruct, VectorParams, VectorsConfig,
        vectors_config::Config,
    },
};
use serde_json;

// ----------------------------------------------------------------------------
// gRPC Client
// ----------------------------------------------------------------------------

pub mod anomaly {
    tonic::include_proto!("anomaly");
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo xtask <task>");
        eprintln!("Available tasks:");
        eprintln!("  setup-qdrant        create collection and populate");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "setup-qdrant" => setup_qdrant_collection().await?,
        _ => {
            eprintln!("Unknown task: {}", args[1]);
            eprintln!("Available tasks:");
            eprintln!("  setup-qdrant        create collection and populate");
            std::process::exit(1);
        }
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// xtasks
// ----------------------------------------------------------------------------

async fn setup_qdrant_collection() -> Result<(), Box<dyn std::error::Error>> {
    let client = Qdrant::from_url("http://localhost:6334").build()?;
    let collection_name = "normal_headers";
    client
        .create_collection(CreateCollection {
            collection_name: collection_name.to_string(),
            vectors_config: Some(VectorsConfig {
                config: Some(Config::Params(VectorParams {
                    size: 386,
                    distance: Distance::Cosine.into(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        })
        .await?;
    println!("collection '{}' created", collection_name);

    let normal_headers = get_test_headers("config/test_headers.json")?;
    println!("populating {}", collection_name);

    let mut points = Vec::new();
    for (i, headers) in normal_headers.iter().enumerate() {
        let header_text = fmt_headers(headers);
        println!("processing header {}: {}", i + 1, header_text);

        match anomaly_detection_engine::embeddings::generate_embeddings(&header_text, Some(386)) {
            Ok(embedding) => {
                println!("generated embedding ({} dimensions)", embedding.len());

                let point = PointStruct::new(
                    (i + 1) as u64,
                    embedding,
                    [("headers".to_string(), header_text.into())],
                );
                points.push(point);
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    let points_len = points.len();
    println!("inserting {} points into {}", points_len, collection_name);
    client
        .upsert_points(qdrant_client::qdrant::UpsertPoints {
            collection_name: collection_name.to_string(),
            points,
            ..Default::default()
        })
        .await?;

    let info = client.collection_info(collection_name).await?;
    println!("collection info: {:?}", info);

    println!("✅ successfully populated collection {}", collection_name);

    Ok(())
}

// ----------------------------------------------------------------------------
// xtasks - helper functions
// ----------------------------------------------------------------------------

fn fmt_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name, value))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn get_test_headers(
    filename: &str,
) -> Result<Vec<Vec<(String, String)>>, Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(filename)?;
    let headers_data: Vec<Vec<(String, String)>> = serde_json::from_str(&file_content)?;
    Ok(headers_data)
}
