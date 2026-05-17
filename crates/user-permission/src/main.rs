use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

#[derive(Parser)]
#[command(
    name = "user-permission",
    about = "UserPermission - centralized user & group management",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the HTTP server
    Serve {
        /// Bind address
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Bind port
        #[arg(long, default_value_t = 8000)]
        port: u16,

        /// SQLite database path
        #[arg(long, default_value = "user_permission.db")]
        database: PathBuf,

        /// Secret-key file path (created on first run)
        #[arg(long, default_value = "secret.key")]
        secret: PathBuf,

        /// API route prefix (e.g. "/api")
        #[arg(long, default_value = "")]
        prefix: String,

        /// Enable HTMX + Tailwind admin UI
        #[arg(long)]
        webui: bool,

        /// WebUI URL prefix
        #[arg(long = "webui-prefix", default_value = "/ui")]
        webui_prefix: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            host,
            port,
            database,
            secret,
            prefix,
            webui,
            webui_prefix,
        } => {
            let db = Database::open_local(&database, Some(&secret))
                .await
                .with_context(|| format!("opening database at {}", database.display()))?;

            let config = WebConfig {
                api_prefix: prefix,
                webui_prefix,
                webui_enabled: webui,
                token_expires: Duration::from_secs(3600),
                webui_token_expires: Duration::from_secs(86_400),
            };
            let app = build_app(db, config);

            let addr = format!("{host}:{port}");
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .with_context(|| format!("binding to {addr}"))?;
            tracing::info!("listening on http://{}", addr);
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
