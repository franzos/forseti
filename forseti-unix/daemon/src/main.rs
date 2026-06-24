use anyhow::Result;
use forseti_unixd::{config, server, Config};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let path = config::resolve_path(std::env::args().nth(1));
    let cfg: Config = Config::load(Path::new(&path))?;
    server::run(cfg).await
}
