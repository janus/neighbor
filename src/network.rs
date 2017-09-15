
use bytes::{BytesMut, Buf, BufMut};
use std::time::Duration;
use std::thread;
use std::net::UdpSocket;


const BUFFER_CAPACITY: usize = 4096;

fn create_socket(ipadr: String, port: String) -> UdpSocket {
	let separation = ":".to_string();
	let ip_and_port = format!("{}{}{}", ipadr, separation, port);
	let socket = match UdpSocket::bind(ip_and_port) {
		Ok(s) => s,
		Err(e) => panic!("Failed to establish bind socket {}", e),
	};
	match socket.set_multicast_ttl_v4(1) {
		Ok(n) => n,
		Err(e) => panic!("Failed to set multicast ttl {}", e),
	};
	socket
}


pub struct UpdNetwork {
	ipaddress: String,
	portnum: String,
	updsocket: UdpSocket,
	buf: BytesMut,
}

impl UpdNetwork {
	fn new(ipadr: String, port: String) -> UpdNetwork {
		let mbuf = BytesMut::with_capacity(BUFFER_CAPACITY);
		let b = ipadr.clone();
		let d = port.clone();
		UpdNetwork {
			ipaddress: ipadr,
			portnum: port,
			updsocket: create_socket(b, d),
			buf: mbuf,
		}
	}

	///To add either threadpool or Eventloop or Poll.
	fn read_from(&mut self) {
		self.updsocket.set_nonblocking(true);
		match self.updsocket.recv_from(&mut self.buf[..]) {
			Ok((nbytes, saddr)) => (nbytes, saddr),
			Err(e) => panic!("recv_from error: {}", e),
		};

	}

	fn send_data(&self, ipadr: String, port: String, mut buf: BytesMut) {
		let separation = ":".to_string();
		let ip_and_port = format!("{}{}{}", ipadr, separation, port);
		match self.updsocket.send_to(&mut buf[..], ip_and_port) {
			Ok(n) => n,
			Err(e) => panic!("Failed to send data through the network {}", e),
		};
		buf.clear();
	}
}

#[cfg(test)]
mod test {
	use network::create_socket;
	use network::UpdNetwork;

	#[test]
	fn test_udp() {
		println!("UDP");
		let ipad = String::from("127.0.0.1");
		let pot = String::from("4567");
		let udp = UpdNetwork::new(ipad, pot);
		println!("{}:{}", udp.ipaddress, udp.portnum);
	}
}
