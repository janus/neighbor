use base64::{decode, encode};
use bytes::{BufMut, BytesMut};
use edcert::ed25519;
use std::str;
//use std::thread;
use chrono::prelude::*;
//use pongnetwork::PongUpdNetworkProfile;
use pingnetwork::PingUpdNetworkProfile;
use types::{Neighbor, ENDPORT};



const BUFFER_CAPACITY_MESSAGE: usize = 4096;

///To be filtered out a bit

pub fn ping_msg(header: String, ping: &PingUpdNetworkProfile) -> BytesMut {
	let utc: DateTime<Utc> = Utc::now();
	let created_time_utc = format!("{}", utc);
	let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
	let str_tmp = format!(
		"{} {} {} {} {} {}",
		header,
		ping.public_key,
		encode(&ping.end_port.ip_address),
		encode(&ping.end_port.udp_port),
		encode(&created_time_utc),
		ping.seqnum
	);
	let sig = ed25519::sign(str_tmp.as_bytes(), &ping.private_key);
	rslt.put(str_tmp);
	rslt.put(" ");
	rslt.put(encode(&sig));
	rslt
}

///To be completed
fn m_decode(mstr: String) -> String {
	let lstr;
	lstr = match decode(&mstr) {
		Ok(v) => String::from_utf8(v).expect("Found invalid UTF-8"),
		Err(e) => panic!("Failed to decode  {}", mstr),
	};
	lstr
}


pub fn build_neighbor(vec_fields: Vec<&str>, ttnum: usize) -> Neighbor {
	let udp_port = m_decode(vec_fields[vec_fields.len() - 4].to_string());
	let ip_address = m_decode(vec_fields[2].to_string());
	let end_port = ENDPORT {
		udp_port: udp_port,
		ip_address: ip_address,
	};
	Neighbor {
		public_key: vec_fields[1].to_string(),
		payment_address: vec_fields[1].to_string(), //should have the right address
		seqnum: vec_fields[vec_fields.len() - 2].parse::<usize>().unwrap(),
		active: ttnum,
		end_port: end_port,
	}
}


#[cfg(test)]
mod test {
	use std::str;
	use std::vec::Vec;
	use chrono::prelude::*;
	use edcert::ed25519;
	use base64::{decode, encode};
	use pingnetwork::PingUpdNetworkProfile;
	use serialization::{build_neighbor, ping_msg};



	fn build_network(
		rx_ip_address: String,
		rx_udp_port: String,
		tx_ip_address: String,
		tx_udp_port: String,
		psk: String,
		msk: [u8; 64],
	) -> PingUpdNetworkProfile {
		let pg_net = PingUpdNetworkProfile::new(
			tx_ip_address,
			tx_udp_port,
			rx_ip_address,
			rx_udp_port,
			psk,
			msk,
		);
		pg_net
	}


	#[test]
	fn test_send_data() {
		let (psk, msk) = ed25519::generate_keypair();
		let ping_network = build_network(
			"127.0.0.1".to_string(),
			"3456".to_string(),
			"0.0.0.0".to_string(),
			"0".to_string(),
			encode(&psk),
			msk,
		);
		let mut pay_load = ping_msg("ipv4_hello".to_string(), &ping_network);
		ping_network.send_data(&mut pay_load);
		ping_network.close();
	}

	#[test]
	fn test_serialization() {
		let (psk, msk) = ed25519::generate_keypair();
		let ping_network = build_network(
			"127.0.0.3".to_string(),
			"3456".to_string(),
			"0.0.0.0".to_string(),
			"0".to_string(),
			encode(&psk),
			msk,
		);
		let ping_str_buf = ping_msg("ipv4_hello".to_string(), &ping_network);
		let ping_msg_vec = ping_str_buf[..].to_vec();
		let ping_str_payload = String::from_utf8(ping_msg_vec).expect("Found invalid UTF-8");
		let str_vec = ping_str_payload.split_whitespace().collect::<Vec<&str>>();
		println!("Testing Hello Message");
		assert_eq!("ipv4_hello".to_string(), str_vec[0]);

		let ipaddr_byte = decode(str_vec[2]).unwrap();
		let ipaddr_str = String::from_utf8(ipaddr_byte).expect("Found invalid UTF-8");

		println!("Testing IP Address");
		assert_eq!("127.0.0.3".to_string(), ipaddr_str);

		println!("Testing Public key");
		assert_eq!(psk, &decode(str_vec[1]).unwrap()[..]);
		let udp_byte = decode(str_vec[3]).unwrap();
		let udp_str = String::from_utf8(udp_byte).expect("Found invalid UTF-8");

		println!("Testing UDP Port");
		assert_eq!("3456".to_string(), udp_str);
		assert_eq!("0", str_vec[5]);

		let timestamp_byte = decode(str_vec[4]).unwrap();
		let timestamp_str = String::from_utf8(timestamp_byte).expect("Found invalid UTF-8");
		println!("Time this network was created");
		println!("{}", timestamp_str);
		ping_network.close();
	}


	#[test]
	fn test_neighbor() {
		let (psk, msk) = ed25519::generate_keypair();
		let ping_network = build_network(
			"127.0.0.0".to_string(),
			"3456".to_string(),
			"0.0.0.0".to_string(),
			"0".to_string(),
			encode(&psk),
			msk,
		);
		let ping_str_buf = ping_msg("ipv4_hello".to_string(), &ping_network);
		let ping_msg_vec = ping_str_buf[..].to_vec();
		let ping_str_payload = String::from_utf8(ping_msg_vec).expect("Found invalid UTF-8");
		let str_vec = ping_str_payload.split_whitespace().collect::<Vec<&str>>();
		let neighbr = build_neighbor(str_vec, 0);
		ping_network.close();
		println!("Testing Neighbor Public key");
		assert_eq!(psk, &decode(&neighbr.public_key).unwrap()[..]);
	}


	#[test]
	pub fn test_udp_socket_tx_rx() {
		let (psk, msk) = ed25519::generate_keypair();
		let ping_network = build_network(
			"127.0.0.5".to_string(),
			"3456".to_string(),
			"0.0.0.0".to_string(),
			"0".to_string(),
			encode(&psk),
			msk,
		);

		let tx_addr = ping_network.tx.local_addr().unwrap();
		let rx_addr = ping_network.rx.local_addr().unwrap();

		assert!(ping_network.tx.connect(rx_addr).is_ok());
		assert!(ping_network.rx.connect(tx_addr).is_ok());
		ping_network.close();
	}
}
