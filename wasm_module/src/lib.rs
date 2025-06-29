use std::sync::{Arc, OnceLock};
use std::time::Duration;

use signature_detection_engine::SignatureBasedDetectionEngine as FirewallEngine;

use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// -----------------------------------------------------------------------------
// setup
// -----------------------------------------------------------------------------

static FIREWALL_ENGINE: OnceLock<Arc<FirewallEngine>> = OnceLock::new();

fn initialize(_context_id: u32) -> Box<dyn RootContext> {
    let engine = FIREWALL_ENGINE.get_or_init(|| Arc::new(FirewallEngine::new_example()));
    let firewall = Firewall::new(engine.clone()).expect("Failed to initialize firewall");
    Box::new(firewall)
}

#[cfg(feature = "anomaly_detection_engine")]
use prost::Message;

#[cfg(feature = "anomaly_detection_engine")]
pub mod anomaly {
    include!(concat!(env!("OUT_DIR"), "/anomaly.rs"));
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(initialize);
}}

// -----------------------------------------------------------------------------
// Firewall
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Firewall {
    engine: Arc<FirewallEngine>,
}

impl Firewall {
    fn new(engine: Arc<FirewallEngine>) -> Result<Self, String> {
        Ok(Firewall { engine })
    }

    fn run_signature_based_header_detection(&mut self, headers: Vec<(String, String)>) -> Action {
        match self.engine.run_header_phase(headers) {
            Ok(detection_result) => {
                if let Some(blocked_rule) = detection_result {
                    info!(
                        "request blocked by signature-based firewall rule: {:?}",
                        blocked_rule
                    );
                    self.send_blocked_response(&format!(
                        "(signature-based detection): {}",
                        blocked_rule.message.as_deref().unwrap_or("no message")
                    ));
                    return Action::Pause;
                }
                info!("request headers passed signature-based firewall checks");
            }
            Err(e) => {
                info!("(signature-based detection): engine error: {:?}", e);
                self.send_blocked_response("(signature-based detection): engine error");
                return Action::Pause;
            }
        }
        Action::Continue
    }

    fn run_signature_based_body_detection(&mut self, body: &str) -> Action {
        match self.engine.run_body_phase(body) {
            Ok(detection_result) => {
                if let Some(blocked_rule) = detection_result {
                    info!(
                        "request blocked by signature-based firewall rule: {:?}",
                        blocked_rule
                    );
                    self.send_blocked_response(&format!(
                        "(signature-based detection): {}",
                        blocked_rule.message.as_deref().unwrap_or("No message")
                    ));
                    return Action::Pause;
                }
                info!("request body passed signature-based firewall checks");
            }
            Err(e) => {
                info!("signature-based firewall engine error: {:?}", e);
                self.send_blocked_response("(signature-based detection): engine error");
                return Action::Pause;
            }
        }
        Action::Continue
    }

    fn run_signature_based_args_detection(&mut self, query_string: &str) -> Action {
        match self.engine.run_args_phase(query_string) {
            Ok(detection_result) => {
                if let Some(blocked_rule) = detection_result {
                    info!(
                        "request blocked by signature-based firewall rule: {:?}",
                        blocked_rule
                    );
                    self.send_blocked_response(&format!(
                        "(signature-based) detection: {}",
                        blocked_rule.message.as_deref().unwrap_or("no message")
                    ));
                    return Action::Pause;
                }
                info!("query arguments passed signature-based firewall checks");
            }
            Err(e) => {
                info!("signature-based firewall engine error: {:?}", e);
                self.send_blocked_response("(signature-based detection): engine error");
                return Action::Pause;
            }
        }
        Action::Continue
    }

    fn send_blocked_response(&self, reason: &str) {
        self.send_http_response(
            403,
            vec![("content-type", "text/plain")],
            Some(format!("the firewall was very displeased with you {}\n", reason).as_bytes()),
        );
    }

    fn process_query_string(&mut self) -> Action {
        if let Some(path) = self.get_http_request_header(":path") {
            if let Some(query_start) = path.find('?') {
                let query_string = &path[query_start + 1..];
                info!("processing query string: {}", query_string);
                return self.run_signature_based_args_detection(query_string);
            }
        }
        Action::Continue
    }

    fn run_header_detection(&mut self, headers: Vec<(String, String)>) -> Action {
        let signature_result = self.run_signature_based_header_detection(headers.clone());
        if signature_result != Action::Continue {
            return signature_result;
        }

        let args_result = self.process_query_string();
        if args_result != Action::Continue {
            return args_result;
        }

        #[cfg(feature = "anomaly_detection_engine")]
        {
            self.run_anomaly_header_detection(headers)
        }

        #[cfg(not(feature = "anomaly_detection_engine"))]
        {
            Action::Continue
        }
    }

    fn run_body_detecion(&mut self, body: &str) -> Action {
        let signature_result = self.run_signature_based_body_detection(body);
        if signature_result != Action::Continue {
            return signature_result;
        }

        // TODO: implement anomaly detection for body
        Action::Continue
    }
}

// -----------------------------------------------------------------------------
// Anomaly Detection
// -----------------------------------------------------------------------------

#[cfg(feature = "anomaly_detection_engine")]
impl Firewall {
    fn run_anomaly_header_detection(&mut self, headers: Vec<(String, String)>) -> Action {
        use anomaly::{Header, HeaderDetectionRequest};

        let grpc_headers: Vec<Header> = headers
            .iter()
            .map(|(name, value)| Header {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();

        let request = HeaderDetectionRequest {
            headers: grpc_headers,
        };

        let encoded_request = request.encode_to_vec();

        match self.dispatch_grpc_call(
            "anomaly_detection_cluster",
            "anomaly.AnomalyDetection",
            "RunHeaderDetection",
            vec![],
            Some(&encoded_request),
            Duration::from_secs(5),
        ) {
            Ok(call_id) => {
                info!(
                    "header anomaly detection gRPC call dispatched with ID: {}",
                    call_id
                );
                return Action::Pause;
            }
            Err(e) => {
                panic!("failed to dispatch: {:?}", e);
            }
        }
    }

    fn handle_anomaly_detection_response(&mut self, response_data: &[u8]) -> Action {
        match anomaly::HeaderDetectionResponse::decode(response_data) {
            Ok(response) => {
                if let Some(detection) = response.detection {
                    info!(
                        "header detection: anomaly {}, message {}",
                        detection.anomaly_detected, detection.message
                    );

                    if detection.anomaly_detected {
                        info!("ANOMALY DETECTED: {}", detection.message);
                        self.send_blocked_response(&format!(
                            "(anomaly detection): {}",
                            detection.message
                        ));
                        return Action::Pause;
                    } else {
                        info!("no anomalies detected in headers");
                        self.resume_http_request();
                        return Action::Continue;
                    }
                } else {
                    info!("no detection data in anomaly response");
                    self.resume_http_request();
                    return Action::Continue;
                }
            }
            Err(e) => {
                info!("failed to decode HeaderDetectionResponse: {:?}", e);
                self.resume_http_request();
                return Action::Continue;
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Context Implementations
// -----------------------------------------------------------------------------

impl Context for Firewall {
    #[cfg(feature = "anomaly_detection_engine")]
    fn on_grpc_call_response(&mut self, token_id: u32, status_code: u32, response_size: usize) {
        info!("gRPC response: id {}, status {}", token_id, status_code);

        if status_code == 0 {
            if let Some(response_data) = self.get_grpc_call_response_body(0, response_size) {
                self.handle_anomaly_detection_response(&response_data);
                return;
            } else {
                info!("no response body received from gRPC call");
            }
        } else {
            info!("gRPC call failed with status code: {}", status_code);
        }

        self.resume_http_request();
    }
}

impl RootContext for Firewall {
    fn on_vm_start(&mut self, _: usize) -> bool {
        info!("firewall engine started successfully");
        #[cfg(feature = "anomaly_detection_engine")]
        {
            info!("anomaly detection engine is enabled");
        }
        self.set_tick_period(Duration::from_secs(5));
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(self.clone()))
    }
}

impl HttpContext for Firewall {
    fn on_http_request_headers(&mut self, num_headers: usize, _end_of_stream: bool) -> Action {
        {
            let mut counter = self.engine.counter.lock().unwrap();
            *counter += 1;
            info!(
                "firewall processing request headers (request counter {})",
                *counter
            );
        }

        let headers = self.get_http_request_headers();

        info!("processing {} request headers", num_headers);
        info!("request headers: {:?}", headers);

        self.run_header_detection(headers)
    }

    fn on_http_request_body(&mut self, body_size: usize, _end_of_stream: bool) -> Action {
        {
            let mut counter = self.engine.counter.lock().unwrap();
            *counter += 1;
            info!("firewall processing request body (counter {})", *counter);
        }

        if let Some(body_bytes) = self.get_http_request_body(0, body_size) {
            let body = String::from_utf8_lossy(&body_bytes);
            info!("processing request body: {}", body);
            return self.run_body_detecion(&body);
        }

        Action::Continue
    }
}
