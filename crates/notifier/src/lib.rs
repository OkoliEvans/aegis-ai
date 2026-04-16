use std::sync::Arc;

use guardian_core::{GuardianRepository, RiskFinding};
use teloxide::{prelude::*, types::ParseMode};
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct Notifier {
    bot: Option<Bot>,
    sse_tx: broadcast::Sender<String>,
    repository: Arc<dyn GuardianRepository>,
}

impl Notifier {
    pub fn new(bot_token: Option<&str>, repository: Arc<dyn GuardianRepository>) -> Self {
        let (sse_tx, _) = broadcast::channel(512);
        Self {
            bot: bot_token.map(Bot::new),
            sse_tx,
            repository,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.sse_tx.subscribe()
    }

    pub async fn fire(&self, address: &str, findings: &[RiskFinding], tx_hash: Option<&str>) {
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

        let _ = self.sse_tx.send(payload.to_string());

        if let Some(bot) = &self.bot {
            if let Ok(Some(chat_id)) = self.repository.telegram_chat_id(address).await {
                let message = format_telegram_alert(findings);
                let _ = bot
                    .send_message(ChatId(chat_id), message)
                    .parse_mode(ParseMode::MarkdownV2)
                    .await;
            }
        }
    }

    pub async fn register_address(&self, address: &str, chat_id: i64) {
        let _ = self.repository.register_telegram(address, chat_id).await;
    }
}

fn format_telegram_alert(findings: &[RiskFinding]) -> String {
    let Some(top) = findings.first() else {
        return "Guardian alert".to_string();
    };

    let title = top.severity.as_str().to_ascii_uppercase();
    let description = escape_markdown(&top.description);
    format!(
        "*Guardian Alert*\n\n*{title}* `{}`\n\n{}\n\n_Open dashboard for details_",
        escape_markdown(&top.module),
        description
    )
}

fn escape_markdown(input: &str) -> String {
    input
        .chars()
        .flat_map(|character| match character {
            '_' | '*' | '[' | ']' | '(' | ')' | '~' | '`' | '>' | '#' | '+' | '-' | '=' | '|'
            | '{' | '}' | '.' | '!' => ['\\', character].into_iter().collect::<Vec<_>>(),
            _ => [character].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}
