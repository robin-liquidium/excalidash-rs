//! AWS SDK v3 default credential chain (`fromNodeProviderChain`), used by the S3 client
//! when `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` are not both configured — exactly
//! when upstream's s3.ts leaves `credentials` unset and the SDK falls back to it.
//!
//! Order: environment (incl. session token) → shared ini files (`AWS_PROFILE`,
//! `~/.aws/credentials`, `~/.aws/config`) → web identity token (STS
//! AssumeRoleWithWebIdentity) → ECS container endpoint → EC2 instance metadata (IMDSv2).
//! Temporary credentials are cached and refreshed 5 minutes before expiry.
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub expiration: Option<SystemTime>,
}

pub const NO_PROVIDER: &str = "Could not load credentials from any providers";

static CACHE: Mutex<Option<AwsCredentials>> = Mutex::new(None);

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn fresh(c: &AwsCredentials) -> bool {
    match c.expiration {
        None => true,
        Some(exp) => exp > SystemTime::now() + Duration::from_secs(300),
    }
}

/// Resolve credentials through the chain (cached).
pub async fn resolve(http: &reqwest::Client) -> Result<AwsCredentials, String> {
    if let Some(c) = CACHE.lock().unwrap().clone() {
        if fresh(&c) {
            return Ok(c);
        }
    }
    let creds = from_env()
        .or_else(from_shared_files)
        .map(Ok)
        .unwrap_or(Err(()));
    let creds = match creds {
        Ok(c) => c,
        Err(()) => match from_web_identity(http).await? {
            Some(c) => c,
            None => match from_container(http).await? {
                Some(c) => c,
                None => match from_imds(http).await {
                    Some(c) => c,
                    None => return Err(NO_PROVIDER.into()),
                },
            },
        },
    };
    *CACHE.lock().unwrap() = Some(creds.clone());
    Ok(creds)
}

fn from_env() -> Option<AwsCredentials> {
    Some(AwsCredentials {
        access_key_id: env("AWS_ACCESS_KEY_ID")?,
        secret_access_key: env("AWS_SECRET_ACCESS_KEY")?,
        session_token: env("AWS_SESSION_TOKEN"),
        expiration: env("AWS_CREDENTIAL_EXPIRATION").and_then(|e| parse_time(&e)),
    })
}

fn home() -> Option<PathBuf> {
    env("HOME").map(PathBuf::from)
}

/// Minimal INI parser: `[section]` and `key = value` lines, `#`/`;` comments.
pub fn parse_ini(text: &str) -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.entry(section.clone()).or_default().insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    out
}

fn from_shared_files() -> Option<AwsCredentials> {
    let profile = env("AWS_PROFILE").unwrap_or_else(|| "default".into());
    let creds_path = env("AWS_SHARED_CREDENTIALS_FILE").map(PathBuf::from).or_else(|| home().map(|h| h.join(".aws/credentials")));
    let config_path = env("AWS_CONFIG_FILE").map(PathBuf::from).or_else(|| home().map(|h| h.join(".aws/config")));
    let mut merged: HashMap<String, String> = HashMap::new();
    // credentials file wins over config file for the same profile.
    if let Some(text) = config_path.and_then(|p| std::fs::read_to_string(p).ok()) {
        let ini = parse_ini(&text);
        let key = if profile == "default" { "default".to_string() } else { format!("profile {profile}") };
        for k in [key.as_str(), profile.as_str()] {
            if let Some(sec) = ini.get(k) {
                merged.extend(sec.clone());
            }
        }
    }
    if let Some(text) = creds_path.and_then(|p| std::fs::read_to_string(p).ok()) {
        if let Some(sec) = parse_ini(&text).get(&profile) {
            merged.extend(sec.clone());
        }
    }
    Some(AwsCredentials {
        access_key_id: merged.get("aws_access_key_id")?.clone(),
        secret_access_key: merged.get("aws_secret_access_key")?.clone(),
        session_token: merged.get("aws_session_token").cloned(),
        expiration: None,
    })
}

fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

fn parse_time(s: &str) -> Option<SystemTime> {
    chrono::DateTime::parse_from_rfc3339(s.trim()).ok().map(|d| d.with_timezone(&chrono::Utc).into())
}

async fn from_web_identity(http: &reqwest::Client) -> Result<Option<AwsCredentials>, String> {
    let (Some(token_file), Some(role_arn)) = (env("AWS_WEB_IDENTITY_TOKEN_FILE"), env("AWS_ROLE_ARN")) else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(&token_file).map_err(|e| format!("web identity token file: {e}"))?;
    let session = env("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| format!("aws-sdk-js-session-{}", crate::util::now_ms()));
    let region = env("AWS_REGION").unwrap_or_else(|| crate::config::config().s3.region.clone());
    let endpoint = env("AWS_STS_ENDPOINT").unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"));
    let res = http
        .post(&endpoint)
        .form(&[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", role_arn.as_str()),
            ("RoleSessionName", session.as_str()),
            ("WebIdentityToken", token.trim()),
        ])
        .send()
        .await
        .map_err(|e| format!("STS AssumeRoleWithWebIdentity: {e}"))?;
    let body = res.text().await.map_err(|e| e.to_string())?;
    let creds = (|| {
        Some(AwsCredentials {
            access_key_id: xml_tag(&body, "AccessKeyId")?.to_string(),
            secret_access_key: xml_tag(&body, "SecretAccessKey")?.to_string(),
            session_token: xml_tag(&body, "SessionToken").map(str::to_string),
            expiration: xml_tag(&body, "Expiration").and_then(parse_time),
        })
    })();
    creds.map(Some).ok_or_else(|| format!("STS AssumeRoleWithWebIdentity failed: {}", xml_tag(&body, "Message").unwrap_or("invalid response")))
}

fn from_json(v: &serde_json::Value) -> Option<AwsCredentials> {
    Some(AwsCredentials {
        access_key_id: v.get("AccessKeyId")?.as_str()?.to_string(),
        secret_access_key: v.get("SecretAccessKey")?.as_str()?.to_string(),
        session_token: v.get("Token").and_then(|t| t.as_str()).map(str::to_string),
        expiration: v.get("Expiration").and_then(|t| t.as_str()).and_then(parse_time),
    })
}

async fn from_container(http: &reqwest::Client) -> Result<Option<AwsCredentials>, String> {
    let url = if let Some(rel) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        format!("http://169.254.170.2{rel}")
    } else if let Some(full) = env("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        full
    } else {
        return Ok(None);
    };
    let mut rb = http.get(&url).timeout(Duration::from_secs(1));
    let token = env("AWS_CONTAINER_AUTHORIZATION_TOKEN").or_else(|| {
        env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").and_then(|f| std::fs::read_to_string(f).ok()).map(|t| t.trim().to_string())
    });
    if let Some(t) = token {
        rb = rb.header("Authorization", t);
    }
    let v: serde_json::Value = rb
        .send()
        .await
        .map_err(|e| format!("container credentials: {e}"))?
        .json()
        .await
        .map_err(|e| format!("container credentials: {e}"))?;
    from_json(&v).map(Some).ok_or_else(|| "container credentials: invalid response".to_string())
}

async fn from_imds(http: &reqwest::Client) -> Option<AwsCredentials> {
    if env("AWS_EC2_METADATA_DISABLED").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        return None;
    }
    let base = env("AWS_EC2_METADATA_SERVICE_ENDPOINT").unwrap_or_else(|| "http://169.254.169.254".into());
    let base = base.trim_end_matches('/');
    let t = Duration::from_secs(1);
    let token = http
        .put(format!("{base}/latest/api/token"))
        .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
        .timeout(t)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let get = |path: String| {
        http.get(format!("{base}{path}")).header("x-aws-ec2-metadata-token", token.clone()).timeout(t).send()
    };
    let role = get("/latest/meta-data/iam/security-credentials/".into()).await.ok()?.text().await.ok()?;
    let role = role.lines().next()?.trim().to_string();
    if role.is_empty() {
        return None;
    }
    let v: serde_json::Value = get(format!("/latest/meta-data/iam/security-credentials/{role}")).await.ok()?.json().await.ok()?;
    from_json(&v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_profiles() {
        let ini = parse_ini("[default]\naws_access_key_id = A\naws_secret_access_key=B\n# c\n[profile dev]\nAWS_SESSION_TOKEN = T\n");
        assert_eq!(ini["default"]["aws_access_key_id"], "A");
        assert_eq!(ini["default"]["aws_secret_access_key"], "B");
        assert_eq!(ini["profile dev"]["aws_session_token"], "T");
    }

    #[test]
    fn sts_and_json_parsing() {
        let xml = "<AssumeRoleWithWebIdentityResponse><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey><SessionToken>ST</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResponse>";
        assert_eq!(xml_tag(xml, "AccessKeyId"), Some("AK"));
        assert!(parse_time(xml_tag(xml, "Expiration").unwrap()).is_some());
        let c = from_json(&serde_json::json!({"AccessKeyId":"a","SecretAccessKey":"s","Token":"t","Expiration":"2030-01-01T00:00:00Z"})).unwrap();
        assert_eq!(c.session_token.as_deref(), Some("t"));
        assert!(fresh(&c));
    }
}
