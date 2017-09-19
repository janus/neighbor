
use bytes::{BytesMut, Buf, BufMut};
//use std::time::Duration;
//use std::thread;
use std::net::UdpSocket;
use base64::{encode, decode};
use edcert::ed25519;
use mio::{PollOpt, Token};
use neighbor::{Neighbors};
use serialization;
use types::{ENDPORT, Neighbor};



const BUFFER_CAPACITY:usize = 4096;

fn create_socket(
	ipadr: String, 
	port: String
) -> UdpSocket {
	let separation = ":".to_string();
	let ip_and_port = format!(
		"{}{}{}", 
		ipadr, 
		separation, 
		port
	);
	let socket = match UdpSocket::bind(ip_and_port) {
		Ok(s) => s,
		Err(e) => panic!("Failed to establish bind socket {}", e)
	};
	socket
}

pub struct PingUpdNetworkProfile {
	pub tx: UdpSocket,
	pub rx: UdpSocket,
	pub buf: BytesMut,
	pub public_key: String,
	pub private_key: [u8; 64],
	pub seqnum: usize,
	pub status_num: usize,
	pub end_port: ENDPORT,
	pub direct_connected_nodes: Neighbors,
}

impl PingUpdNetworkProfile {
	pub fn new(
		rx_ip_address: String, 
		rx_udp_port: String,
		tx_ip_address: String, 
		tx_udp_port: String, 
		public_key: String, 
		private_key: [u8; 64]
) -> PingUpdNetworkProfile {
		let mbuf = BytesMut::with_capacity(BUFFER_CAPACITY);
		let neighbors = Neighbors::new();
		let cloned_tx_ipadr = tx_ip_address.clone();
		let cloned_tx_udp_port  = tx_udp_port.clone();
		let end_port = ENDPORT {
			ip_address: tx_ip_address,
			udp_port: tx_udp_port,
		};
		PingUpdNetworkProfile {
			tx: create_socket(cloned_tx_ipadr, cloned_tx_udp_port),
			rx: create_socket(rx_ip_address, rx_udp_port),
			buf: mbuf,
			end_port: end_port,
			public_key: public_key,
			private_key: private_key,
			direct_connected_nodes: neighbors,
			status_num: 0,
			seqnum: 0,
		}
	}
	
///To add either threadpool or Eventloop or Poll. 
	fn read_from(&mut self) {
		let sig;
		let pub_key;
		let joined;
		match self.rx.recv_from(&mut self.buf[..]) {
			Ok((nbytes, saddr)) => {},
			Err(e) => panic!("recv_from error: {}", e),
		};
		let msg_buf = self.buf[..].to_vec();
		let str_buf = String::from_utf8(msg_buf).expect("Found invalid UTF-8");
		let mvec = str_buf.split_whitespace().collect::<Vec<&str>>();
		sig = match decode(&mvec[mvec.len() - 1]) {
			Ok(v) => v,
			Err(e) => panic!("Failed to decode signature, {}", e),
		};
		pub_key = match decode(&mvec[mvec.len() - 1]) {
			Ok(v) => v,
			Err(e) => panic!("Failed to decode public key, {}", e),
		};
		joined = mvec[1..mvec.len() - 1].join(" ");
		match ed25519::verify(joined.as_bytes(), &sig, &pub_key) {
			true => {
				match mvec[0] {
					"ipv4_hello_confirm" => {
						self.direct_connected_nodes.add_to_table(serialization::build_neighbor(mvec, 0));
					},
					_ => { panic!("Failed to interpret message"); }
				};
			},
			false => {return;},
		};
	}
	
	pub fn send_data(&self,  buf: &mut BytesMut){
		let addr = self.tx.local_addr().unwrap();
		match self.tx.set_multicast_ttl_v4(1) {
			Ok(n) => n,
			Err(e) => panic!("Failed to set multicast ttl {}", e),
		};
		match self.tx.send_to(&mut buf[..], &addr){
			Ok(n) => {},
			Err(e) => panic!("Failed to send data through the network {}", e),
		};
		buf.clear();
	}
	
	pub fn close(self){
		drop(self.tx);
		drop(self.rx);
	}
}



#[cfg(test)]
mod test {
//use network::create_socket;
//use network::UpdNetworkProfile;


 #[test]
pub fn test_udp_socket_send_recv() {

}

}
