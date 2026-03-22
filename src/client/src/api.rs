use std::collections::HashMap;

use reqwest::{header::HeaderMap, Client, Error, RequestBuilder, Response};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use rustls_pki_types::CertificateDer;
use serde::Serialize;
use serde_json::Error as SerdeError;
use thiserror::Error;
use url::Url;

use crate::{errors::ApiError, types::ApiData};

#[derive(Debug)]
pub struct ApiClient {
    base_url: String,
    #[allow(dead_code)]
    pub token: uuid::Uuid,
    client: Client,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("bad base url")]
    BadUrl(#[from] url::ParseError),

    #[error("api error")]
    ApiError(#[from] ApiError),

    #[error("reqwest error")]
    ReqwestError(#[from] Error),

    #[error("json error")]
    ParseError(#[from] SerdeError),

    #[error("missing data in response")]
    MissingData,

    #[error("TLS error: {0}")]
    TlsError(String),
}

impl ApiClient {
    pub fn new(base_url: String, token: uuid::Uuid) -> Result<Self, ClientError> {
        let _api_url = Url::parse(&base_url)?;

        let client = build_rustls_client_from_bytes(CA_CERT)
            .map_err(|e| ClientError::TlsError(e.to_string()))?;

        log::debug!("USING ROOT-CA_CERT!!!!");

        Ok(ApiClient {
            base_url,
            token,
            client,
        })
    }

    pub async fn get(
        &self,
        uri: &str,
        headers: Option<HeaderMap>,
        // query: Option<&HashMap<&str, &str>>,
        query: Option<&HashMap<&str, Vec<&str>>>,
    ) -> Result<ApiData<serde_json::Value>, ClientError> {
        let url = format!("{}{}", self.base_url, uri);
        let mut request = self.client.get(&url).bearer_auth(self.token);

        if let Some(q) = query {
            request = request.query(q);
        }

        self.send(request, headers).await
    }

    pub async fn post<T: Serialize>(
        &self,
        uri: &str,
        headers: Option<HeaderMap>,
        body: &T,
    ) -> Result<ApiData<serde_json::Value>, ClientError> {
        let url = format!("{}{}", self.base_url, uri);
        let request = self.client.post(url).json(body).bearer_auth(self.token);

        self.send(request, headers).await
    }

    pub async fn patch<T: Serialize + std::fmt::Debug>(
        &self,
        uri: &str,
        headers: Option<HeaderMap>,
        body: &T,
    ) -> Result<ApiData<serde_json::Value>, ClientError> {
        let url = format!("{}{}", self.base_url, uri);
        let request = self.client.patch(url).json(body).bearer_auth(self.token);

        self.send(request, headers).await
    }

    async fn send(
        &self,
        mut request: RequestBuilder,
        headers: Option<HeaderMap>,
    ) -> Result<ApiData<serde_json::Value>, ClientError> {
        if let Some(headers) = headers {
            request = request.headers(headers);
        }

        let res = request.send().await?;
        self.handle_response(res).await
    }

    async fn handle_response(
        &self,
        response: Response,
    ) -> Result<ApiData<serde_json::Value>, ClientError> {
        let status = response.status();
        let message = response.text().await?;

        if message.trim().is_empty() {
            return Ok(ApiData::new());
        }

        let body: HashMap<String, serde_json::Value> =
            serde_json::from_str(&message).map_err(ClientError::ParseError)?;

        if status.is_client_error() || status.is_server_error() {
            if let (Some(code), Some(title)) = (
                body.get("code").and_then(|v| v.as_u64()).map(|v| v as u16),
                body.get("title").and_then(|v| v.as_str()),
            ) {
                return Err(ClientError::ApiError(ApiError {
                    code,
                    title: title.to_string(),
                }));
            }

            let mut error_messages = Vec::new();
            if let Some(errors) = body.get("errors").and_then(|v| v.as_array()) {
                for err in errors {
                    let detail = err
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default();
                    error_messages.push(detail.to_string());
                }
            }

            let combined_message = if error_messages.is_empty() {
                format!("Request failed with status {}", status)
            } else {
                error_messages.join("; ")
            };

            return Err(ClientError::ApiError(ApiError::new(
                status.as_u16(),
                combined_message,
            )));
        }

        let mut api_response: ApiData<serde_json::Value> = ApiData::new();
        if status.is_success() {
            api_response.data = body.get("data").cloned();
        }

        Ok(api_response)
    }
}

const CA_CERT: &[u8] = include_bytes!("../../../nginx/certs/data/hybrid/root-ca.crt");

fn build_rustls_client_from_bytes(ca_bytes: &[u8]) -> anyhow::Result<Client> {
    let mut root_store = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(ca_bytes);
    let certs: Vec<CertificateDer> = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    for cert in certs {
        root_store.add(cert)?;
    }

    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(Into::into)
}
