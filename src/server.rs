use crate::handler::State;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;

pub struct ServerError(pub String);

pub async fn bind(config: &crate::main_mod::Config, state: Arc<State>) -> Result<(UdpSocket, TcpListener, Arc<State>), ServerError> {
    // placeholder
    let udp = UdpSocket::bind(config.listen).await.map_err(|e| ServerError(e.to_string()))?;
    let tcp = TcpListener::bind(config.listen).await.map_err(|e| ServerError(e.to_string()))?;
    Ok((udp, tcp, state))
}
EOF
echo "not enough"