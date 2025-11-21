use alloy::transports::http::reqwest;
use serde::Deserialize;
use tracing::info;

/// Client for fetching 4byte error signatures.
///
/// 4byte.directory is a service that maps 4-byte function signatures to human-readable function
/// names. See https://www.4byte.directory/ for more.
///
/// Note: This client is more reliable for error handling than for fn signature parsing. The latter
/// contains many spam entries.
pub struct FourByteClient {
    url: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct FourByteResponse {
    results: Vec<SignatureResult>,
}

#[derive(Debug, Deserialize)]
struct SignatureResult {
    text_signature: String,
}

impl FourByteClient {
    pub fn new() -> Self {
        Self {
            url: "https://www.4byte.directory/api/v1/signatures/".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_signature(&self, hex_sig: &str) -> Result<String, Box<dyn std::error::Error>> {
        info!("Fetching signature from 4Byte.directory");
        let response = self
            .client
            .get(&self.url)
            .query(&[("hex_signature", hex_sig)])
            .send()
            .await?;
        let result: FourByteResponse = response.json().await?;

        if result.results.is_empty() {
            return Err("No signatures found!".into());
        }

        Ok(result.results[0].text_signature.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires internet connection"]
    async fn test_fourbyte_client() {
        let client = FourByteClient::new();
        let signature = client.get_signature("0x90bfb865").await;

        assert!(signature.is_ok());
        let sig_text = signature.unwrap();
        assert_eq!(sig_text, "WrappedError(address,bytes4,bytes,bytes)");
    }
}
