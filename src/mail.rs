//! mail/* — password-reset delivery via SMTP (lettre) or Resend (HTTP API).
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::config::{config, MailConfig, MailTransport};

pub struct MailMessage {
    pub to: String,
    pub subject: String,
    pub html: String,
    pub text: String,
    /// Accepted for parity; the upstream Resend call passes it inside the payload, where the
    /// SDK ignores it, so it is never sent.
    pub idempotency_key: Option<String>,
}

#[derive(Debug)]
pub enum MailResult {
    Delivered { id: Option<String> },
    NotDelivered { reason: String },
}

pub enum Mailer {
    Disabled { reason: String },
    Smtp { host: String, port: u16, secure: bool, credentials: Option<(String, String)>, from: String, reply_to: Option<String> },
    Resend { api_key: String, from: String, reply_to: Option<String> },
}

impl Mailer {
    /// createMailerFromConfig
    pub fn from_config(mail: &MailConfig) -> Mailer {
        let disabled = |r: &str| Mailer::Disabled { reason: r.to_string() };
        if mail.transport == MailTransport::None {
            return disabled("No mail transport configured");
        }
        let Some(from) = mail.from.clone() else { return disabled("MAIL_FROM is not set") };
        if mail.transport == MailTransport::Smtp {
            let Some(host) = mail.smtp.host.clone() else { return disabled("SMTP_HOST is not set") };
            if mail.smtp.user.is_some() != mail.smtp.password.is_some() {
                return disabled("SMTP_USER and SMTP_PASSWORD must be set together");
            }
            let credentials = match (&mail.smtp.user, &mail.smtp.password) {
                (Some(u), Some(p)) => Some((u.clone(), p.clone())),
                _ => None,
            };
            return Mailer::Smtp {
                host,
                port: mail.smtp.port as u16,
                secure: mail.smtp.secure,
                credentials,
                from,
                reply_to: mail.reply_to.clone(),
            };
        }
        let Some(api_key) = mail.resend_api_key.clone() else { return disabled("RESEND_API_KEY is not set") };
        Mailer::Resend { api_key, from, reply_to: mail.reply_to.clone() }
    }

    pub fn enabled(&self) -> bool {
        !matches!(self, Mailer::Disabled { .. })
    }

    pub async fn send(&self, http: &reqwest::Client, message: MailMessage) -> MailResult {
        match self {
            Mailer::Disabled { reason } => MailResult::NotDelivered { reason: reason.clone() },
            Mailer::Smtp { host, port, secure, credentials, from, reply_to } => {
                match send_smtp(host, *port, *secure, credentials.as_ref(), from, reply_to.as_deref(), &message).await {
                    Ok(id) => MailResult::Delivered { id },
                    Err(reason) => MailResult::NotDelivered { reason },
                }
            }
            Mailer::Resend { api_key, from, reply_to } => {
                send_resend(http, api_key, from, reply_to.as_deref(), &message).await
            }
        }
    }
}

/// The process-wide mailer (auth.ts creates one when building the router).
pub fn mailer() -> &'static Mailer {
    static M: OnceLock<Mailer> = OnceLock::new();
    M.get_or_init(|| Mailer::from_config(&config().mail))
}

async fn send_smtp(
    host: &str,
    port: u16,
    secure: bool,
    credentials: Option<&(String, String)>,
    from: &str,
    reply_to: Option<&str>,
    message: &MailMessage,
) -> Result<Option<String>, String> {
    use lettre::message::{header, Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    crate::net::install_crypto_provider();
    let parse = |s: &str| s.parse::<Mailbox>().map_err(|e| e.to_string());
    let message_id = format!("<{}@{}>", crate::util::uuid_v4(), from_domain(from));
    let mut builder = lettre::Message::builder().from(parse(from)?).to(parse(&message.to)?).subject(&message.subject);
    if let Some(r) = reply_to {
        builder = builder.reply_to(parse(r)?);
    }
    let part = |ct: header::ContentType, body: &str| {
        SinglePart::builder().header(ct).header(header::ContentTransferEncoding::QuotedPrintable).body(body.to_string())
    };
    let email = builder
        .message_id(Some(message_id.clone()))
        .multipart(
            MultiPart::alternative()
                .singlepart(part(header::ContentType::TEXT_PLAIN, &message.text))
                .singlepart(part(header::ContentType::TEXT_HTML, &message.html)),
        )
        .map_err(|e| e.to_string())?;

    let tls_params = TlsParameters::new_rustls(host.to_string()).map_err(|e| e.to_string())?;
    // nodemailer: secure → implicit TLS; otherwise STARTTLS when the server offers it.
    let tls = if secure { Tls::Wrapper(tls_params) } else { Tls::Opportunistic(tls_params) };
    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .port(port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(20)));
    if let Some((user, pass)) = credentials {
        transport = transport.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    let transport = transport.build();
    transport.send(email).await.map_err(|e| e.to_string())?;
    Ok(Some(message_id))
}

fn from_domain(from: &str) -> String {
    let addr = from.rsplit('<').next().unwrap_or(from).trim_end_matches('>').trim();
    addr.rsplit('@').next().filter(|d| !d.is_empty() && *d != addr).unwrap_or("localhost").to_string()
}

/// Resend SDK v6 `emails.send` (RESEND_BASE_URL / RESEND_USER_AGENT are honoured like the SDK).
async fn send_resend(
    http: &reqwest::Client,
    api_key: &str,
    from: &str,
    reply_to: Option<&str>,
    message: &MailMessage,
) -> MailResult {
    let base = std::env::var("RESEND_BASE_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.resend.com".into());
    let ua = std::env::var("RESEND_USER_AGENT").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "resend-node:6.22.0".into());
    // parseEmailToApiOptions key order; undefined keys are dropped by JSON.stringify.
    let mut body = Map::new();
    body.insert("from".into(), json!(from));
    body.insert("html".into(), json!(message.html));
    if let Some(r) = reply_to {
        body.insert("reply_to".into(), json!(r));
    }
    body.insert("subject".into(), json!(message.subject));
    body.insert("text".into(), json!(message.text));
    body.insert("to".into(), json!([message.to]));
    let res = http
        .post(format!("{base}/emails"))
        .header("Authorization", format!("Bearer {api_key}"))
        .header("User-Agent", ua)
        .header("Content-Type", "application/json")
        .body(Value::Object(body).to_string())
        .send()
        .await;
    let fail = |name: &str, msg: &str| MailResult::NotDelivered { reason: format!("{name}: {msg}") };
    let res = match res {
        Ok(r) => r,
        Err(_) => return fail("application_error", "Unable to fetch data. The request could not be resolved."),
    };
    let status = res.status();
    let text = match res.text().await {
        Ok(t) => t,
        Err(_) => return fail("application_error", "Unable to fetch data. The request could not be resolved."),
    };
    if !status.is_success() {
        if !config().is_production {
            eprintln!("[Resend API Error]: {{ status: {}, path: '/emails' }}", status.as_u16());
        }
        return match serde_json::from_str::<Value>(&text) {
            Ok(err) => fail(&js_string(err.get("name")), &js_string(err.get("message"))),
            Err(_) => fail(
                "application_error",
                "Internal server error. We are unable to process your request right now, please try again later.",
            ),
        };
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(data) => MailResult::Delivered { id: data.get("id").and_then(|v| v.as_str()).map(str::to_string) },
        Err(_) => fail("application_error", "Unable to fetch data. The request could not be resolved."),
    }
}

/// `${value}` template-literal formatting for JSON values.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "null".into(),
        Some(Value::Object(_)) => "[object Object]".into(),
        Some(other) => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// mail/templates/passwordReset.ts

fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub struct BuiltMail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub fn build_password_reset_email(reset_url: &str, expires_in_minutes: u32) -> BuiltMail {
    let safe_url = escape_html(reset_url);
    let text = [
        "Reset your ExcaliDash password".to_string(),
        String::new(),
        "Open this link to choose a new password:".to_string(),
        reset_url.to_string(),
        String::new(),
        format!("The link is valid for {expires_in_minutes} minutes and can be used once."),
        "If you did not request this, you can ignore this email. Your password stays unchanged.".to_string(),
    ]
    .join("\n");
    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background:#f8f9fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#1e1e1e">
    <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:8px;padding:32px">
      <h1 style="margin:0 0 16px;font-size:20px">Reset your password</h1>
      <p style="margin:0 0 24px;line-height:1.5">Open the link below to choose a new password for your ExcaliDash account.</p>
      <p style="margin:0 0 24px"><a href="{safe_url}" style="display:inline-block;padding:12px 20px;background:#1e1e1e;color:#fff;text-decoration:none;border-radius:6px">Choose a new password</a></p>
      <p style="margin:0 0 24px;line-height:1.5;font-size:14px;color:#868e96">The link is valid for {expires_in_minutes} minutes and can be used once. If the button does not work, copy this address into your browser:<br><span style="word-break:break-all">{safe_url}</span></p>
      <p style="margin:0;line-height:1.5;font-size:14px;color:#868e96">If you did not request this, you can ignore this email. Your password stays unchanged.</p>
    </div>
  </body>
</html>"#
    );
    BuiltMail { subject: "Reset your ExcaliDash password".into(), text, html }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_text_and_escaping() {
        let m = build_password_reset_email("https://x.test/reset-password-confirm#token=a&b\"<>", 60);
        assert_eq!(m.subject, "Reset your ExcaliDash password");
        assert!(m.text.starts_with("Reset your ExcaliDash password\n\nOpen this link to choose a new password:\nhttps://x.test/reset-password-confirm#token=a&b\"<>\n\nThe link is valid for 60 minutes and can be used once.\n"));
        assert!(m.html.contains(r#"href="https://x.test/reset-password-confirm#token=a&amp;b&quot;&lt;&gt;""#));
        assert!(m.html.starts_with("<!doctype html>\n<html lang=\"en\">\n  <body"));
        assert!(m.html.ends_with("</div>\n  </body>\n</html>"));
    }

    fn mail_cfg(transport: MailTransport) -> MailConfig {
        MailConfig {
            transport,
            resend_api_key: None,
            from: Some("ExcaliDash <no-reply@example.test>".into()),
            reply_to: None,
            smtp: crate::config::SmtpConfig { host: None, port: 587.0, secure: false, user: None, password: None },
        }
    }

    fn reason(m: &Mailer) -> &str {
        match m {
            Mailer::Disabled { reason } => reason,
            _ => "",
        }
    }

    #[test]
    fn mailer_from_config_reasons() {
        assert_eq!(reason(&Mailer::from_config(&mail_cfg(MailTransport::None))), "No mail transport configured");
        let mut c = mail_cfg(MailTransport::Smtp);
        assert_eq!(reason(&Mailer::from_config(&c)), "SMTP_HOST is not set");
        c.smtp.host = Some("127.0.0.1".into());
        c.smtp.user = Some("u".into());
        assert_eq!(reason(&Mailer::from_config(&c)), "SMTP_USER and SMTP_PASSWORD must be set together");
        c.smtp.password = Some("p".into());
        assert!(Mailer::from_config(&c).enabled());
        c.from = None;
        assert_eq!(reason(&Mailer::from_config(&c)), "MAIL_FROM is not set");
        let c = mail_cfg(MailTransport::Resend);
        assert_eq!(reason(&Mailer::from_config(&c)), "RESEND_API_KEY is not set");
    }

    #[test]
    fn from_domain_extracts_domain() {
        assert_eq!(from_domain("ExcaliDash <no-reply@example.test>"), "example.test");
        assert_eq!(from_domain("a@b.c"), "b.c");
        assert_eq!(from_domain("nobody"), "localhost");
    }
}
