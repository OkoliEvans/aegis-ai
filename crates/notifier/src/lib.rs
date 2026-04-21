use std::sync::Arc;

use guardian_core::{GuardianConfig, GuardianPolicyClient, GuardianRepository, RiskFinding};
use lettre::{
    message::{header::ContentType, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use tokio::sync::broadcast;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Notifier {
    email: Option<EmailNotifier>,
    policy: Option<GuardianPolicyClient>,
    sse_tx: broadcast::Sender<String>,
    repository: Arc<dyn GuardianRepository>,
}

#[derive(Clone)]
struct EmailNotifier {
    from: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl Notifier {
    pub fn new(config: &GuardianConfig, repository: Arc<dyn GuardianRepository>) -> Self {
        let (sse_tx, _) = broadcast::channel(512);
        Self {
            email: EmailNotifier::from_config(config),
            policy: GuardianPolicyClient::from_config(config),
            sse_tx,
            repository,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.sse_tx.subscribe()
    }

    pub async fn fire(&self, address: &str, findings: &[RiskFinding], tx_hash: Option<&str>) {
        self.persist_and_broadcast(address, findings, tx_hash).await;

        if let Some(email) = &self.email {
            if let Ok(Some(destination)) = self.repository.notification_email(address).await {
                if let Err(error) = email
                    .send_alert(&destination, address, findings, tx_hash)
                    .await
                {
                    warn!(?error, %address, "failed to send email alert");
                }
            }
        }
    }

    pub async fn publish(&self, address: &str, findings: &[RiskFinding], tx_hash: Option<&str>) {
        self.persist_and_broadcast(address, findings, tx_hash).await;
    }

    async fn persist_and_broadcast(
        &self,
        address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
    ) {
        let payload = serde_json::json!({
            "address": address,
            "findings": findings,
            "timestamp": chrono::Utc::now(),
        });

        for finding in findings {
            let _ = self
                .repository
                .store_risk_event(address, finding, tx_hash)
                .await;
        }

        if let Some(policy) = &self.policy {
            if let Err(error) = policy.sync_findings(address, findings, tx_hash).await {
                warn!(?error, %address, "failed to sync findings to guardian-policy");
            }
        }

        let _ = self.sse_tx.send(payload.to_string());
    }

    pub async fn register_address(
        &self,
        address: &str,
        email_address: &str,
        email_display_name: Option<&str>,
    ) {
        let _ = self
            .repository
            .register_email(address, email_address, email_display_name)
            .await;
    }
}

impl EmailNotifier {
    fn from_config(config: &GuardianConfig) -> Option<Self> {
        let host = config.smtp_host.as_ref()?;
        let from_email = config.smtp_from_email.as_ref()?;
        let from = match parse_mailbox(from_email, config.smtp_from_name.as_deref()) {
            Ok(from) => from,
            Err(error) => {
                warn!(
                    ?error,
                    "invalid SMTP_FROM_EMAIL/SMTP_FROM_NAME configuration"
                );
                return None;
            }
        };

        let mut builder = if config.smtp_port == 465 {
            match AsyncSmtpTransport::<Tokio1Executor>::from_url(&format!("smtps://{host}")) {
                Ok(builder) => builder.port(config.smtp_port),
                Err(error) => {
                    warn!(?error, %host, "failed to create SMTPS transport");
                    return None;
                }
            }
        } else {
            match AsyncSmtpTransport::<Tokio1Executor>::relay(host) {
                Ok(builder) => builder.port(config.smtp_port),
                Err(error) => {
                    warn!(?error, %host, "failed to create SMTP relay transport");
                    return None;
                }
            }
        };

        if let (Some(username), Some(password)) =
            (config.smtp_username.as_ref(), config.smtp_password.as_ref())
        {
            builder =
                builder.credentials(Credentials::new(username.to_string(), password.to_string()));
        }

        Some(Self {
            from,
            transport: builder.build(),
        })
    }

    async fn send_alert(
        &self,
        destination: &str,
        subject_address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
    ) -> anyhow::Result<()> {
        let message =
            build_email_message(&self.from, destination, subject_address, findings, tx_hash)?;
        self.transport.send(message).await?;
        info!(%destination, %subject_address, "email alert accepted by SMTP transport");
        Ok(())
    }
}

fn build_email_message(
    from: &Mailbox,
    destination: &str,
    subject_address: &str,
    findings: &[RiskFinding],
    tx_hash: Option<&str>,
) -> anyhow::Result<Message> {
    let top = findings
        .first()
        .ok_or_else(|| anyhow::anyhow!("cannot send alert email without findings"))?;
    let severity = top.severity.as_str().to_ascii_uppercase();
    let subject = format!("[Guardian][{severity}] {} risk alert", top.module);
    let to = parse_mailbox(destination, None)?;
    let text_body = render_text_email(subject_address, findings, tx_hash);
    let html_body = render_html_email(subject_address, findings, tx_hash);

    Ok(Message::builder()
        .from(from.clone())
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(text_body))
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )?)
}

fn parse_mailbox(address: &str, display_name: Option<&str>) -> anyhow::Result<Mailbox> {
    let parsed = address.parse()?;
    Ok(Mailbox::new(display_name.map(ToOwned::to_owned), parsed))
}

fn render_text_email(
    subject_address: &str,
    findings: &[RiskFinding],
    tx_hash: Option<&str>,
) -> String {
    let top = &findings[0];
    let mut lines = vec![
        "Guardian Security Alert".to_string(),
        String::new(),
        format!("Address: {subject_address}"),
        format!("Severity: {}", top.severity.as_str().to_ascii_uppercase()),
        format!("Primary module: {}", top.module),
    ];

    if let Some(tx_hash) = tx_hash {
        lines.push(format!("Tx hash: {tx_hash}"));
    }

    lines.push(String::new());
    lines.push("Findings:".to_string());
    for finding in findings {
        lines.push(format!(
            "- [{}] {} ({})",
            finding.severity.as_str().to_ascii_uppercase(),
            finding.description,
            finding.module
        ));
    }

    lines.push(String::new());
    lines.push(
        "Open Guardian to review the full event details and decide on next steps.".to_string(),
    );
    lines.join("\n")
}

fn render_html_email(
    subject_address: &str,
    findings: &[RiskFinding],
    tx_hash: Option<&str>,
) -> String {
    let top = &findings[0];
    let findings_html = findings
        .iter()
        .map(|finding| {
            format!(
                "<li><strong>[{}]</strong> {} <span style=\"color:#7a8699\">({})</span></li>",
                escape_html(&finding.severity.as_str().to_ascii_uppercase()),
                escape_html(&finding.description),
                escape_html(&finding.module),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let tx_row = tx_hash.map(|hash| {
        format!(
            "<tr><td style=\"padding:6px 0;color:#5a6472;font-weight:600\">Tx Hash</td><td style=\"padding:6px 0;color:#101828\">{}</td></tr>",
            escape_html(hash)
        )
    }).unwrap_or_default();

    format!(
        "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;font-family:Arial,sans-serif;color:#101828\">\
         <div style=\"max-width:680px;margin:24px auto;padding:0 16px\">\
         <div style=\"background:#ffffff;border:1px solid #d0d5dd;border-radius:16px;overflow:hidden\">\
         <div style=\"padding:24px 28px;background:linear-gradient(135deg,#101828,#1d2939);color:#ffffff\">\
         <p style=\"margin:0 0 8px 0;font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:#cbd5e1\">Guardian Security Alert</p>\
         <h1 style=\"margin:0;font-size:24px;line-height:1.2;color:#fef3c7\">{} risk detected</h1>\
         <p style=\"margin:12px 0 0 0;font-size:15px;color:#f8fafc\">Guardian spotted behavior worth reviewing before it becomes a loss event.</p>\
         </div>\
         <div style=\"padding:24px 28px\">\
         <table style=\"width:100%;border-collapse:collapse\">\
         <tr><td style=\"padding:6px 0;color:#5a6472;font-weight:600\">Address</td><td style=\"padding:6px 0;color:#101828\">{}</td></tr>\
         <tr><td style=\"padding:6px 0;color:#5a6472;font-weight:600\">Primary Module</td><td style=\"padding:6px 0;color:#101828\">{}</td></tr>\
         <tr><td style=\"padding:6px 0;color:#5a6472;font-weight:600\">Severity</td><td style=\"padding:6px 0;color:#b42318;font-weight:700\">{}</td></tr>\
         {}\
         </table>\
         <div style=\"margin-top:20px;padding:18px 20px;background:#f8fafc;border:1px solid #e4e7ec;border-radius:12px\">\
         <h2 style=\"margin:0 0 12px 0;font-size:16px\">Findings</h2>\
         <ul style=\"margin:0;padding-left:18px;line-height:1.6\">{}</ul>\
         </div>\
         <p style=\"margin:20px 0 0 0;font-size:14px;color:#475467\">Open Guardian to inspect the event details, confirm whether the action is expected, and take corrective action if needed.</p>\
         </div></div></div></body></html>",
        escape_html(&top.severity.as_str().to_ascii_uppercase()),
        escape_html(subject_address),
        escape_html(&top.module),
        escape_html(&top.severity.as_str().to_ascii_uppercase()),
        tx_row,
        findings_html
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
