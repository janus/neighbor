use edcert::meta::Meta;
use edcert::certificate::Certificate;


use bytes::{BytesMut, Buf, Bytes};


pub struct Account {
	pub public_key: String,
	pub private_key: String,
	pub seqnum: usize,
	pub status_num: usize,
	pub tunnel_public_key: String,
	pub tunnel_private_key: String,
	pub end_port: ENDPORT,
}

pub struct ENDPORT {
	pub ip_address: String,
	pub udp_port: String,
	pub tcp_port: String,
}

pub struct Tunnel {
	pub public_key: String,
	pub listen_port: usize,
	pub end_port: ENDPORT,
}

pub struct Neighbor {
	pub active: usize,
	pub public_key: String,
	pub seqnum: usize,
	pub payment_address: String,
	pub tunnel: Option<Tunnel>,
	pub end_port: ENDPORT,
}

// Message types
pub struct MessageMetadata {
	pub source_public_key: Bytes,
	pub destination_public_key: Bytes,
	pub source_ip_address: Bytes,
	pub destination_ip_address: Bytes,
	pub ports: Bytes,
	pub seqnum: usize,
	pub signature: BytesMut,
}

pub struct HelloMessage {
	pub message_metadata: MessageMetadata,
	pub confirm: bool,
	pub created_time_utc: Bytes,
}

pub struct TunnelMessage {
	pub message_metadata: MessageMetadata,
	pub tunnel_public_key: Bytes,
	pub tunnel_end_point: Bytes,
	pub created_time_utc: Bytes,
	pub confirm: bool,
}


// Uti
