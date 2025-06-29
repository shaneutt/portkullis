pub mod embeddings;

use anomaly::anomaly_detection_server::{AnomalyDetection, AnomalyDetectionServer};
use anomaly::{Detection, HeaderDetectionRequest, HeaderDetectionResponse};

use qdrant_client::Qdrant;
use tonic::{Request, Response, Status, transport::Server};
use tonic_reflection::server::Builder;

// ----------------------------------------------------------------------------
// gRPC Service
// ----------------------------------------------------------------------------

pub mod anomaly {
    tonic::include_proto!("anomaly");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("anomaly_descriptor");
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:10764".parse()?;
    let anomaly_service = AnomalyDetectionEngine::default();

    let reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(anomaly::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    println!("AnomalyDetectionServer listening on {}", addr);
    println!("gRPC reflection enabled");

    Server::builder()
        .add_service(AnomalyDetectionServer::new(anomaly_service))
        .add_service(reflection_service)
        .serve(addr)
        .await?;

    Ok(())
}

// ----------------------------------------------------------------------------
// Anomaly Detection Engine
// ----------------------------------------------------------------------------

const VECTOR_DATABASE_URL: &str = "http://localhost:6334";
const COLLECTION_NAME: &str = "normal_headers";
const DIMENSIONS: usize = 386;
const SCORE_THRESHOLD: f32 = 0.79;
const SEARCH_COUNT: u64 = 100;

const ANOMALY_DETECTED_MESSAGE: &str = "anomaly detected: no similar patterns found";

#[derive(Debug, Default)]
pub struct AnomalyDetectionEngine {}

#[tonic::async_trait]
impl AnomalyDetection for AnomalyDetectionEngine {
    async fn run_header_detection(
        &self,
        request: Request<HeaderDetectionRequest>,
    ) -> Result<Response<HeaderDetectionResponse>, Status> {
        let headers = &request.get_ref().headers;

        let header_pairs: Vec<(String, String)> = headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();

        let header_text = format_headers_for_embedding(&header_pairs);

        match self.detect_anomaly_with_vectors(&header_text).await {
            Ok((is_anomaly, score, message)) => {
                let detection = Detection {
                    anomaly_detected: is_anomaly,
                    message: format!("{} (similarity score: {:.4})", message, score),
                };

                let response = HeaderDetectionResponse {
                    detection: Some(detection),
                };

                Ok(Response::new(response))
            }
            Err(e) => {
                return Err(Status::internal(format!("anomaly detection error: {}", e)));
            }
        }
    }
}

impl AnomalyDetectionEngine {
    async fn detect_anomaly_with_vectors(
        &self,
        header_text: &str,
    ) -> Result<(bool, f32, String), Box<dyn std::error::Error + Send + Sync>> {
        let client = Qdrant::from_url(VECTOR_DATABASE_URL).build()?;
        let collection_name = COLLECTION_NAME;

        let embedding = crate::embeddings::generate_embeddings(header_text, Some(DIMENSIONS))?;
        let search_result = client
            .search_points(qdrant_client::qdrant::SearchPoints {
                collection_name: collection_name.to_string(),
                vector: embedding,
                limit: SEARCH_COUNT,
                with_payload: Some(false.into()),
                score_threshold: Some(SCORE_THRESHOLD),
                ..Default::default()
            })
            .await?;

        if search_result.result.is_empty() {
            return Ok((true, 0.0, ANOMALY_DETECTED_MESSAGE.to_string()));
        }

        let top_score = search_result
            .result
            .iter()
            .map(|point| point.score)
            .fold(f32::NEG_INFINITY, f32::max);

        let (is_anomaly, message) = if top_score >= SCORE_THRESHOLD {
            (false, "normal traffic match".to_string())
        } else {
            (true, ANOMALY_DETECTED_MESSAGE.to_string())
        };

        Ok((is_anomaly, top_score, message))
    }
}

fn format_headers_for_embedding(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name, value))
        .collect::<Vec<_>>()
        .join(" | ")
}
