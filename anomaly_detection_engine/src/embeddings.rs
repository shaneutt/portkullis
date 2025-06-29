use std::sync::OnceLock;
use std::time::Instant;

use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE, HiddenAct};
use hf_hub::{Repo, RepoType, api::sync::Api};
use tokenizers::Tokenizer;

use anyhow::{Error as E, Result};

// ----------------------------------------------------------------------------
// Embeddings Generator
// ----------------------------------------------------------------------------

static EMBEDDINGS_GENERATOR: OnceLock<Result<EmbeddingsGenerator, anyhow::Error>> = OnceLock::new();

pub fn generate_embeddings(text: &str, dimensions: Option<usize>) -> Result<Vec<f32>> {
    let generator_result = EMBEDDINGS_GENERATOR.get_or_init(|| {
        EmbeddingsGenerator::new("sentence-transformers/all-MiniLM-L6-v2", "main", true)
    });

    match generator_result {
        Ok(generator) => generator.generate(text, dimensions),
        Err(e) => Err(anyhow::anyhow!("embeddings engine failed: {}", e)),
    }
}

struct EmbeddingsGenerator {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

impl EmbeddingsGenerator {
    fn new(model_id: &str, revision: &str, cpu: bool) -> Result<Self> {
        let device = if cpu {
            Device::Cpu
        } else {
            Device::cuda_if_available(0)?
        };

        let repo = Repo::with_revision(model_id.to_string(), RepoType::Model, revision.to_string());
        let (config_filename, tokenizer_filename, weights_filename) = {
            let api = Api::new()?;
            let api = api.repo(repo);
            let config = api.get("config.json")?;
            let tokenizer = api.get("tokenizer.json")?;
            let weights = api.get("model.safetensors")?;
            (config, tokenizer, weights)
        };

        let config_str = std::fs::read_to_string(config_filename)?;
        let mut bert_config: Config = serde_json::from_str(&config_str)?;
        bert_config.hidden_act = HiddenAct::GeluApproximate;
        let tokenizer = Tokenizer::from_file(tokenizer_filename).map_err(E::msg)?;
        let vb =
            unsafe { VarBuilder::from_mmaped_safetensors(&[weights_filename], DTYPE, &device)? };

        let model = BertModel::load(vb, &bert_config)?;

        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }

    fn generate(&self, text: &str, dimensions: Option<usize>) -> Result<Vec<f32>> {
        let start_time = Instant::now();

        let tokens = self
            .tokenizer
            .encode(text, true)
            .map_err(E::msg)?
            .get_ids()
            .to_vec();

        let token_ids = Tensor::new(&tokens[..], &self.device)?.unsqueeze(0)?;
        let token_type_ids = token_ids.zeros_like()?;

        let embeddings = self.model.forward(&token_ids, &token_type_ids, None)?;

        let (_batch_size, n_tokens, _hidden_size) = embeddings.dims3()?;
        let pooled_embeddings = (embeddings.sum(1)? / (n_tokens as f64))?;
        let raw_embeddings: Vec<f32> = pooled_embeddings.squeeze(0)?.to_vec1()?;

        let result_embeddings = if let Some(target_dims) = dimensions {
            if target_dims < raw_embeddings.len() {
                raw_embeddings[..target_dims].to_vec()
            } else if target_dims > raw_embeddings.len() {
                let mut padded = raw_embeddings;
                padded.resize(target_dims, 0.0);
                padded
            } else {
                raw_embeddings
            }
        } else {
            raw_embeddings
        };

        println!(
            "embeddings generated in {:.3}s",
            start_time.elapsed().as_secs_f64()
        );

        Ok(result_embeddings)
    }
}
