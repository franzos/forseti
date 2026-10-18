#[tokio::main]
async fn main() -> anyhow::Result<()> {
    forseti::run_cli().await
}
