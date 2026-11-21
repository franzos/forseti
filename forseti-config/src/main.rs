#[tokio::main]
async fn main() {
    std::process::exit(forseti_config::run().await);
}
