use narcd::listeners::ssh::start_server;

#[tokio::main]
async fn main() {
    pretty_env_logger::init_timed();
    start_server().await.expect("Server exited unsuccessfully!")
}
