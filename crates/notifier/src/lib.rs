use std::sync::Arc;

use guardian_core::{
    GuardianConfig, GuardianPolicyClient, GuardianRepository, IncomingTx, RiskFinding,
};
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

#[derive(Debug, Clone)]
pub enum AlertContext {
    GuardedTransaction {
        outcome: GuardedTxOutcome,
        tx: AlertTransactionDetails,
    },
    SimulationReport {
        scenario_id: String,
        attack_surface: String,
    },
    ApprovalReview {
        flagged_approvals: usize,
    },
    SecurityUpdate {
        source: String,
    },
    EmailTest,
}

#[derive(Debug, Clone, Copy)]
pub enum GuardedTxOutcome {
    Warned,
    ConfirmationRequired,
    Blocked,
}

#[derive(Debug, Clone)]
pub struct AlertTransactionDetails {
    pub recipient: String,
    pub amount: String,
    pub denom: String,
    pub contract_address: Option<String>,
    pub function_name: Option<String>,
    pub message_type: Option<String>,
}

impl From<&IncomingTx> for AlertTransactionDetails {
    fn from(tx: &IncomingTx) -> Self {
        Self {
            recipient: tx.recipient.clone(),
            amount: tx.amount.clone(),
            denom: tx.denom.clone(),
            contract_address: tx.contract_address.clone(),
            function_name: tx.function_name.clone(),
            message_type: tx.message_type.clone(),
        }
    }
}

struct EmailContent {
    subject: String,
    title: String,
    eyebrow: String,
    status_label: String,
    status_background: &'static str,
    status_border: &'static str,
    status_color: &'static str,
    status_glow: &'static str,
    summary: String,
    metadata: Vec<(String, String)>,
    findings_label: String,
    findings: Vec<String>,
    next_steps: Vec<String>,
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
        self.notify(
            address,
            findings,
            tx_hash,
            AlertContext::SecurityUpdate {
                source: "Guardian security update".to_string(),
            },
        )
        .await;
    }

    pub async fn publish(&self, address: &str, findings: &[RiskFinding], tx_hash: Option<&str>) {
        self.notify(
            address,
            findings,
            tx_hash,
            AlertContext::SecurityUpdate {
                source: "Guardian analysis report".to_string(),
            },
        )
        .await;
    }

    pub async fn notify_guarded_transaction(
        &self,
        tx: &IncomingTx,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
        outcome: GuardedTxOutcome,
    ) {
        self.notify(
            &tx.sender,
            findings,
            tx_hash,
            AlertContext::GuardedTransaction {
                outcome,
                tx: AlertTransactionDetails::from(tx),
            },
        )
        .await;
    }

    pub async fn notify_simulation_report(
        &self,
        address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
        scenario_id: &str,
        attack_surface: &str,
    ) {
        self.notify(
            address,
            findings,
            tx_hash,
            AlertContext::SimulationReport {
                scenario_id: scenario_id.to_string(),
                attack_surface: attack_surface.to_string(),
            },
        )
        .await;
    }

    pub async fn notify_security_update(
        &self,
        address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
        source: impl Into<String>,
    ) {
        self.notify(
            address,
            findings,
            tx_hash,
            AlertContext::SecurityUpdate {
                source: source.into(),
            },
        )
        .await;
    }

    pub async fn notify_approval_review(
        &self,
        address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
        flagged_approvals: usize,
    ) {
        self.notify(
            address,
            findings,
            tx_hash,
            AlertContext::ApprovalReview { flagged_approvals },
        )
        .await;
    }

    pub async fn send_test_email_alert(&self, address: &str, findings: &[RiskFinding]) {
        self.notify(address, findings, None, AlertContext::EmailTest)
            .await;
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

    async fn notify(
        &self,
        address: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
        context: AlertContext,
    ) {
        self.persist_and_broadcast(address, findings, tx_hash).await;

        if findings.is_empty() {
            return;
        }

        if let Some(email) = &self.email {
            if let Ok(Some(destination)) = self.repository.notification_email(address).await {
                if let Err(error) = email
                    .send_alert(&destination, address, findings, tx_hash, &context)
                    .await
                {
                    warn!(?error, %address, "failed to send email alert");
                }
            }
        }
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
        context: &AlertContext,
    ) -> anyhow::Result<()> {
        let message = build_email_message(
            &self.from,
            destination,
            subject_address,
            findings,
            tx_hash,
            context,
        )?;
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
    context: &AlertContext,
) -> anyhow::Result<Message> {
    let to = parse_mailbox(destination, None)?;
    let content = compose_email_content(subject_address, findings, tx_hash, context)?;
    let text_body = render_text_email(&content);
    let html_body = render_html_email(&content);

    Ok(Message::builder()
        .from(from.clone())
        .to(to)
        .subject(content.subject)
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

fn compose_email_content(
    subject_address: &str,
    findings: &[RiskFinding],
    tx_hash: Option<&str>,
    context: &AlertContext,
) -> anyhow::Result<EmailContent> {
    let primary = findings
        .iter()
        .max_by_key(|finding| finding.weight)
        .ok_or_else(|| anyhow::anyhow!("cannot send alert email without findings"))?;
    let severity = primary.severity.as_str().to_ascii_uppercase();

    let mut metadata = vec![
        ("Wallet".to_string(), subject_address.to_string()),
        ("Severity".to_string(), severity.clone()),
        (
            "Primary finding".to_string(),
            humanize_label(&primary.module),
        ),
    ];

    if let Some(hash) = tx_hash {
        metadata.push(("Reference".to_string(), hash.to_string()));
    }

    let (
        subject,
        eyebrow,
        status_label,
        status_background,
        status_border,
        status_color,
        status_glow,
        title,
        summary,
        findings_label,
        next_steps,
    ) = match context {
        AlertContext::GuardedTransaction { outcome, tx } => {
            metadata.push((
                "Operation".to_string(),
                "Guarded transaction screening".to_string(),
            ));
            metadata.push(("Outcome".to_string(), outcome.label().to_string()));
            metadata.push(("Recipient".to_string(), tx.recipient.clone()));
            metadata.push(("Amount".to_string(), format_amount(&tx.amount, &tx.denom)));
            if let Some(contract) = &tx.contract_address {
                metadata.push(("Contract".to_string(), contract.clone()));
            }
            if let Some(function_name) = &tx.function_name {
                metadata.push(("Entry point".to_string(), function_name.clone()));
            }
            if let Some(message_type) = &tx.message_type {
                metadata.push(("Message type".to_string(), message_type.clone()));
            }

            (
                format!(
                    "[Guardian][{}] {}",
                    outcome.subject_tag(),
                    title_case(&primary.module)
                ),
                "Aegis Guard Transaction Review".to_string(),
                outcome.header_badge().to_string(),
                outcome.header_background(),
                outcome.header_border(),
                outcome.header_color(),
                outcome.header_glow(),
                outcome.email_title().to_string(),
                outcome.summary_sentence().to_string(),
                "Why Guardian raised this transaction".to_string(),
                outcome.next_steps(),
            )
        }
        AlertContext::SimulationReport {
            scenario_id,
            attack_surface,
        } => {
            metadata.push(("Operation".to_string(), "Simulation analysis".to_string()));
            metadata.push(("Scenario".to_string(), humanize_label(scenario_id)));
            metadata.push(("Attack surface".to_string(), humanize_label(attack_surface)));
            metadata.push(("Findings published".to_string(), findings.len().to_string()));

            (
                format!(
                    "[Guardian][Analysis Report] {}",
                    humanize_label(scenario_id)
                ),
                "Aegis Guard Analysis Report".to_string(),
                "ANALYSIS REPORT".to_string(),
                "rgba(45, 212, 191, 0.16)",
                "rgba(45, 212, 191, 0.38)",
                "#76ffed",
                "0 0 16px rgba(45,212,191,0.38)",
                "Simulation report is ready".to_string(),
                "Guardian completed the requested analysis run and published the report to the dashboard and audit history."
                    .to_string(),
                "Key findings from this analysis".to_string(),
                vec![
                    "Review the full report in the dashboard before changing policy or trust settings."
                        .to_string(),
                    "Use the findings to explain exactly why Guardian would flag or block similar activity."
                        .to_string(),
                    "Adjust allowlists, approval posture, or operator workflows before repeating the action."
                        .to_string(),
                ],
            )
        }
        AlertContext::ApprovalReview { flagged_approvals } => {
            metadata.push(("Operation".to_string(), "Approval review".to_string()));
            metadata.push((
                "Flagged approvals".to_string(),
                flagged_approvals.to_string(),
            ));

            (
                format!(
                    "[Guardian][Approval Review] {} approval{} need attention",
                    flagged_approvals,
                    if *flagged_approvals == 1 { "" } else { "s" }
                ),
                "Aegis Guard Approval Review".to_string(),
                "APPROVAL REVIEW".to_string(),
                "rgba(251, 191, 36, 0.14)",
                "rgba(251, 191, 36, 0.34)",
                "#ffd76a",
                "0 0 16px rgba(251,191,36,0.34)",
                "Outstanding approvals need review".to_string(),
                "Guardian completed a scheduled approval review and found permissions that should be narrowed or revoked."
                    .to_string(),
                "Approvals that raised concern".to_string(),
                vec![
                    "Revoke stale, unlimited, or unfamiliar approvals from the dashboard as soon as possible."
                        .to_string(),
                    "Keep standing approvals limited to trusted protocols and the minimum amount required."
                        .to_string(),
                    "Re-run the review after cleanup to confirm the wallet is back to a safe baseline."
                        .to_string(),
                ],
            )
        }
        AlertContext::SecurityUpdate { source } => {
            metadata.push(("Operation".to_string(), source.clone()));

            (
                format!(
                    "[Guardian][Security Update] {}",
                    title_case(&primary.module)
                ),
                "Aegis Guard Security Update".to_string(),
                "SECURITY UPDATE".to_string(),
                "rgba(96, 165, 250, 0.14)",
                "rgba(96, 165, 250, 0.32)",
                "#8ec5ff",
                "0 0 16px rgba(96,165,250,0.34)",
                "New wallet activity requires review".to_string(),
                "Guardian detected activity worth reviewing and recorded the result in the protection history."
                    .to_string(),
                "Why this wallet activity was raised".to_string(),
                vec![
                    "Review the event in the dashboard and confirm whether the activity was expected."
                        .to_string(),
                    "Investigate the counterparties, approvals, or contract payload involved before taking follow-up action."
                        .to_string(),
                    "If the activity is legitimate, update the appropriate trust or response policy after review."
                        .to_string(),
                ],
            )
        }
        AlertContext::EmailTest => {
            metadata.push(("Operation".to_string(), "Email delivery test".to_string()));

            (
                "[Guardian][Email Test] Alert delivery confirmed".to_string(),
                "Aegis Guard Email Test".to_string(),
                "EMAIL TEST".to_string(),
                "rgba(45, 212, 191, 0.14)",
                "rgba(45, 212, 191, 0.32)",
                "#76ffed",
                "0 0 16px rgba(45,212,191,0.32)",
                "Email alerts are configured correctly".to_string(),
                "This message confirms that Guardian can deliver professional security updates to the address configured for this wallet."
                    .to_string(),
                "Included sample finding".to_string(),
                vec![
                    "No action is required for this message.".to_string(),
                    "Keep the alert address current in dashboard settings so important analyses and blocks reach the right inbox."
                        .to_string(),
                    "Once SMTP and wallet monitoring are live, Guardian will use the same channel for real alerts and analysis reports."
                        .to_string(),
                ],
            )
        }
    };

    let findings = findings
        .iter()
        .map(|finding| {
            format!(
                "[{} | {} | +{}] {}",
                finding.severity.as_str().to_ascii_uppercase(),
                humanize_label(&finding.module),
                finding.weight,
                finding.description
            )
        })
        .collect();

    Ok(EmailContent {
        subject,
        title,
        eyebrow,
        status_label,
        status_background,
        status_border,
        status_color,
        status_glow,
        summary,
        metadata,
        findings_label,
        findings,
        next_steps,
    })
}

fn render_text_email(content: &EmailContent) -> String {
    let mut lines = vec![
        content.eyebrow.clone(),
        String::new(),
        content.title.clone(),
        content.summary.clone(),
        String::new(),
        "Overview".to_string(),
    ];

    for (label, value) in &content.metadata {
        lines.push(format!("{label}: {value}"));
    }

    lines.push(String::new());
    lines.push(content.findings_label.clone());
    for finding in &content.findings {
        lines.push(format!("- {finding}"));
    }

    lines.push(String::new());
    lines.push("Recommended next steps".to_string());
    for step in &content.next_steps {
        lines.push(format!("- {step}"));
    }

    lines.join("\n")
}

fn render_html_email(content: &EmailContent) -> String {
    let metadata_rows = content
        .metadata
        .iter()
        .map(|(label, value)| {
            format!(
                "<tr><td style=\"padding:7px 0;color:#667085;font-weight:600;vertical-align:top\">{}</td><td style=\"padding:7px 0;color:#101828\">{}</td></tr>",
                escape_html(label),
                escape_html(value)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let findings_html = content
        .findings
        .iter()
        .map(|finding| {
            format!(
                "<li style=\"margin:0 0 10px 0\">{}</li>",
                escape_html(finding)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let steps_html = content
        .next_steps
        .iter()
        .map(|step| format!("<li style=\"margin:0 0 10px 0\">{}</li>", escape_html(step)))
        .collect::<Vec<_>>()
        .join("");

    format!(
        "<!doctype html><html><body style=\"margin:0;background:#eef2f7;font-family:Arial,sans-serif;color:#101828\">\
         <div style=\"max-width:700px;margin:24px auto;padding:0 16px\">\
         <div style=\"background:#ffffff;border:1px solid #d0d5dd;border-radius:18px;overflow:hidden;box-shadow:0 18px 42px rgba(15,23,42,0.08)\">\
         <div style=\"padding:28px 32px;background:radial-gradient(circle at top right,rgba(36,242,209,0.22),transparent 34%),linear-gradient(135deg,#07111f,#0f1e33 54%,#0a2a3c);color:#ffffff;border-bottom:1px solid rgba(92,242,214,0.18)\">\
         <p style=\"display:inline-block;margin:0 0 12px 0;padding:6px 12px;border-radius:999px;background:rgba(92,242,214,0.14);border:1px solid rgba(92,242,214,0.34);font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:#72ffe8;font-weight:700;text-shadow:0 0 14px rgba(92,242,214,0.55)\">{}</p>\
         <h1 style=\"margin:0;font-size:28px;line-height:1.2;color:#ffffff;text-shadow:0 0 18px rgba(126,250,255,0.18)\">{}</h1>\
         <p style=\"display:inline-block;margin:12px 0 0 0;padding:7px 12px;border-radius:999px;background:{};border:1px solid {};font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:{};font-weight:800;box-shadow:{}\">{}</p>\
         <p style=\"margin:14px 0 0 0;font-size:15px;line-height:1.7;color:#8df7ff;font-weight:600;text-shadow:0 0 16px rgba(92,242,214,0.28)\">{}</p>\
         </div>\
         <div style=\"padding:28px 32px\">\
         <div style=\"padding:18px 20px;background:#f8fafc;border:1px solid #e4e7ec;border-radius:14px\">\
         <h2 style=\"margin:0 0 14px 0;font-size:16px;color:#101828\">Overview</h2>\
         <table style=\"width:100%;border-collapse:collapse\">{}</table>\
         </div>\
         <div style=\"margin-top:18px;padding:18px 20px;background:#fcfcfd;border:1px solid #e4e7ec;border-radius:14px\">\
         <h2 style=\"margin:0 0 14px 0;font-size:16px;color:#101828\">{}</h2>\
         <ul style=\"margin:0;padding-left:18px;line-height:1.6;color:#344054\">{}</ul>\
         </div>\
         <div style=\"margin-top:18px;padding:18px 20px;background:#f8fafc;border:1px solid #e4e7ec;border-radius:14px\">\
         <h2 style=\"margin:0 0 14px 0;font-size:16px;color:#101828\">Recommended next steps</h2>\
         <ul style=\"margin:0;padding-left:18px;line-height:1.7;color:#344054\">{}</ul>\
         </div>\
         <p style=\"margin:20px 0 0 0;font-size:13px;line-height:1.6;color:#667085\">This message was generated by Aegis Guard using deterministic alert templates derived from the current analysis results. Richer LLM-assisted narratives can be enabled later when that API path is configured.</p>\
         </div></div></div></body></html>",
        escape_html(&content.eyebrow),
        escape_html(&content.title),
        content.status_background,
        content.status_border,
        content.status_color,
        content.status_glow,
        escape_html(&content.status_label),
        escape_html(&content.summary),
        metadata_rows,
        escape_html(&content.findings_label),
        findings_html,
        steps_html
    )
}

fn title_case(value: &str) -> String {
    humanize_label(value)
}

fn humanize_label(value: &str) -> String {
    match value {
        "approval_intent" => "Approval intent".to_string(),
        "approval_review" => "Approval review".to_string(),
        "contract_llm" => "Contract analysis warning".to_string(),
        "email_test" => "Email test".to_string(),
        "ica" => "ICA abuse".to_string(),
        "wasm_admin" => "Privileged Wasm action".to_string(),
        _ => value
            .split('_')
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                let mut chars = segment.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_ascii_uppercase().to_string()
                            + &chars.as_str().to_ascii_lowercase()
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn format_amount(amount: &str, denom: &str) -> String {
    if amount.is_empty() || amount == "0" {
        "No funds attached".to_string()
    } else {
        format!("{amount} {denom}")
    }
}

impl GuardedTxOutcome {
    fn subject_tag(self) -> &'static str {
        match self {
            Self::Warned => "Review",
            Self::ConfirmationRequired => "Action Required",
            Self::Blocked => "Blocked",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Warned => "Flagged for review",
            Self::ConfirmationRequired => "Stopped pending confirmation",
            Self::Blocked => "Blocked before broadcast",
        }
    }

    fn email_title(self) -> &'static str {
        match self {
            Self::Warned => "Transaction flagged for review",
            Self::ConfirmationRequired => "Transaction requires confirmation",
            Self::Blocked => "Transaction blocked before broadcast",
        }
    }

    fn summary_sentence(self) -> &'static str {
        match self {
            Self::Warned => {
                "Guardian reviewed the transaction, found elevated risk, and forwarded it with a warning for operator follow-up."
            }
            Self::ConfirmationRequired => {
                "Guardian halted the transaction until the wallet owner reviews the findings and confirms the activity is expected."
            }
            Self::Blocked => {
                "Guardian intercepted the transaction and blocked it before broadcast because the risk profile exceeded the configured threshold."
            }
        }
    }

    fn next_steps(self) -> Vec<String> {
        match self {
            Self::Warned => vec![
                "Review the flagged recipient, contract, and payload in the dashboard before treating the activity as safe."
                    .to_string(),
                "Validate the counterparty against your registry and trusted policy entries."
                    .to_string(),
                "If the action is legitimate, document the approval path so future warnings are easier to triage."
                    .to_string(),
            ],
            Self::ConfirmationRequired => vec![
                "Inspect the transaction details in the dashboard and confirm the contract, recipient, and amount are expected."
                    .to_string(),
                "Avoid re-submitting until the reason for the flag is clearly understood."
                    .to_string(),
                "If the activity is safe, update trusted policy entries or operator runbooks before retrying."
                    .to_string(),
            ],
            Self::Blocked => vec![
                "Do not retry the transaction until the payload and counterparty have been validated."
                    .to_string(),
                "Review the relevant contract, approval, or recipient path in Aegis Guard before allowing any follow-up action."
                    .to_string(),
                "If this was a legitimate operation, refine the wallet policy only after a documented security review."
                    .to_string(),
            ],
        }
    }

    fn header_badge(self) -> &'static str {
        match self {
            Self::Warned => "REVIEW REQUIRED",
            Self::ConfirmationRequired => "CONFIRMATION REQUIRED",
            Self::Blocked => "BLOCKED BEFORE BROADCAST",
        }
    }

    fn header_background(self) -> &'static str {
        match self {
            Self::Warned => "rgba(251, 191, 36, 0.14)",
            Self::ConfirmationRequired => "rgba(249, 115, 22, 0.14)",
            Self::Blocked => "rgba(248, 113, 113, 0.16)",
        }
    }

    fn header_border(self) -> &'static str {
        match self {
            Self::Warned => "rgba(251, 191, 36, 0.34)",
            Self::ConfirmationRequired => "rgba(249, 115, 22, 0.36)",
            Self::Blocked => "rgba(248, 113, 113, 0.38)",
        }
    }

    fn header_color(self) -> &'static str {
        match self {
            Self::Warned => "#ffd76a",
            Self::ConfirmationRequired => "#ffb86c",
            Self::Blocked => "#ff8f8f",
        }
    }

    fn header_glow(self) -> &'static str {
        match self {
            Self::Warned => "0 0 16px rgba(251,191,36,0.34)",
            Self::ConfirmationRequired => "0 0 16px rgba(249,115,22,0.34)",
            Self::Blocked => "0 0 18px rgba(248,113,113,0.38)",
        }
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::Severity;

    fn sample_findings() -> Vec<RiskFinding> {
        vec![
            RiskFinding {
                module: "reentrancy".to_string(),
                severity: Severity::Critical,
                weight: 90,
                description: "Contract execution matched a callback-driven drain pattern."
                    .to_string(),
                payload: serde_json::json!({}),
            },
            RiskFinding {
                module: "contract".to_string(),
                severity: Severity::High,
                weight: 70,
                description:
                    "Guardian found privileged execution behavior that should be reviewed."
                        .to_string(),
                payload: serde_json::json!({}),
            },
        ]
    }

    #[test]
    fn blocked_transaction_email_mentions_broadcast_block() {
        let content = compose_email_content(
            "init1examplewallet",
            &sample_findings(),
            Some("ABC123"),
            &AlertContext::GuardedTransaction {
                outcome: GuardedTxOutcome::Blocked,
                tx: AlertTransactionDetails {
                    recipient: "init1counterparty".to_string(),
                    amount: "2500000".to_string(),
                    denom: "umin".to_string(),
                    contract_address: Some("init1contract".to_string()),
                    function_name: Some("execute_attack".to_string()),
                    message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
                },
            },
        )
        .expect("email content should build");

        assert!(content.subject.contains("[Guardian][Blocked]"));
        assert!(content.title.contains("blocked"));
        assert!(content
            .metadata
            .iter()
            .any(|(label, value)| label == "Outcome" && value == "Blocked before broadcast"));
        assert!(render_text_email(&content).contains("Recommended next steps"));
        assert!(render_html_email(&content).contains("BLOCKED BEFORE BROADCAST"));
    }

    #[test]
    fn simulation_report_email_mentions_analysis_context() {
        let content = compose_email_content(
            "init1examplewallet",
            &sample_findings(),
            Some("simulation:reentrancy_pattern"),
            &AlertContext::SimulationReport {
                scenario_id: "reentrancy_pattern".to_string(),
                attack_surface: "contract_execution".to_string(),
            },
        )
        .expect("email content should build");

        assert!(content.subject.contains("[Guardian][Analysis Report]"));
        assert!(content
            .metadata
            .iter()
            .any(|(label, _)| label == "Scenario"));
        assert!(render_html_email(&content).contains("Simulation report is ready"));
        assert!(render_html_email(&content).contains("ANALYSIS REPORT"));
    }
}
