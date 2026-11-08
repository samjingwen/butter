//! A local HTTP application with protected probes and checked signal shutdown.

use butter::{
    Application,
    actuator::Actuator,
    core::BoxError,
    web::{Router, routing::get},
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let address: SocketAddr = std::env::var("BUTTER_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let routes = Router::new().route("/", get(|| async { "Smooth like butter.\n" }));
    let running = Application::new(routes)
        .bind(address)
        .actuator(Actuator::builder().build())?
        .start_with_signals()
        .await?;
    println!("Listening on http://{}", running.address());
    let _completed = running.wait().await?;
    Ok(())
}
