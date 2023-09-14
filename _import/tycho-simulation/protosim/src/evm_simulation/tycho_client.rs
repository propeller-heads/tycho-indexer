#[derive(Error, Debug)]
pub enum TychoClientError {
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    #[error("Failed to format request: {0}")]
    FormatRequest(String),
    #[error("Unexpected HTTP client error: {0}")]
    HttpClient(String),
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),
}
pub struct TychoVmStateClient {
    http_client: Client<HttpConnector>,
    base_uri: Uri,
}

impl TychoVmStateClient {
    pub fn new(base_url: &str) -> Result<Self, TychoClientError> {
        let base_uri = base_url
            .parse::<Uri>()
            .map_err(|e| TychoClientError::UriParsing(base_url.to_string(), e.to_string()))?;

        // No need for references anymore
        Ok(Self {
            http_client: Client::new(),
            base_uri,
        })
    }
