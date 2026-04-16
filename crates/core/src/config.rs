use std::{env, net::SocketAddr, str::FromStr};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct GuardianConfig {
    pub app_host: String,
    pub app_port: u16,
    pub database_url: Option<String>,
    pub initia_lcd: String,
    pub initia_rpc: String,
    pub initia_ws: String,
    pub anthropic_api_key: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub known_protocols: Vec<String>,
}

impl GuardianConfig {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            app_host: env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            app_port: env::var("APP_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL").ok().filter(|v| !v.is_empty()),
            initia_lcd: env::var("INITIA_LCD").context("INITIA_LCD must be set")?,
            initia_rpc: env::var("INITIA_RPC")
                .unwrap_or_else(|_| "https://rpc.testnet.initia.xyz".to_string()),
            initia_ws: env::var("INITIA_WS").context("INITIA_WS must be set")?,
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok().filter(|v| !v.is_empty()),
            telegram_bot_token: env::var("TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|v| !v.is_empty()),
            known_protocols: env::var("KNOWN_PROTOCOLS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        })
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&format!("{}:{}", self.app_host, self.app_port))
            .context("failed to parse APP_HOST/APP_PORT into a socket address")
    }
}
