//! The gateway's calls to RDS's RustDWeb API (/v1/device/rustdweb/*), made with this device's own
//! credential and sealed like every other managed RDS call. RDS answers only the device named in
//! its Config (rustdweb.gateway_device_id).

use crate::{hbbs_http::directory_enrollment as directory, managed_sealed::SendSealed};
use hbb_common::{anyhow::anyhow, ResultType};
use serde_json::Value;

pub struct Answer {
    pub status: u16,
    pub body: Value,
}

impl Answer {
    pub fn ok(&self) -> bool {
        self.status == 200
    }

    /// RDS's `detail` text, for the viewer.
    pub fn detail(&self) -> String {
        self.body
            .get("detail")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("RDS answered {}", self.status))
    }
}

async fn call(method: reqwest::Method, path: &str, body: Option<&Value>) -> ResultType<Answer> {
    let (base_url, credential) = directory::current_directory_credential("rustdweb")?;
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let client = crate::hbbs_http::create_http_client_async_with_url_strict(&url)
        .await
        .map_err(|_| anyhow!("no HTTP client for RDS"))?;
    let mut request = client.request(method, &url).bearer_auth(credential);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send_sealed().await?;
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok(Answer { status, body })
}

pub async fn post(path: &str, body: &Value) -> ResultType<Answer> {
    call(reqwest::Method::POST, path, Some(body)).await
}
