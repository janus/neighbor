use base64::{encode, decode};
use bytes::{BytesMut, BufMut, Buf};
use edcert::ed25519;
use std::str;
use std::thread;
use chrono::prelude::*;
//use pongnetwork::PongUpdNetworkProfile;
use pingnetwork::PingUpdNetworkProfile;
use types::{ENDPORT, Account, Neighbor, Tunnel};
//use neighbor::Neighbors;




const BUFFER_CAPACITY_MESSAGE:usize = 4096;

///To be filtered out a bit

pub fn ping_msg(
	header: String, 
	ping: &PingUpdNetworkProfile
) -> BytesMut {
	let msg_type: String;
	let utc: DateTime<Utc> = Utc::now();
	let created_time_utc = format!("{}", utc);
	let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
	let str_tmp = format!(
		"{} {} {} {} {} {}", header, 
		ping.public_key,
		encode(&ping.end_port.ip_address),
		encode(&ping.end_port.udp_port),
		encode(&created_time_utc),
		ping.seqnum);
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

pub fn build_neighbor(mvec: Vec<&str> , ttnum: usize) -> Neighbor {
	let tunnel;
	let listen_port;
	if ttnum == 0 {
		tunnel = None;	
	}
	else {
		listen_port = m_decode(mvec[mvec.len() - 3].to_string());
		tunnel = Some(
			Tunnel {
				public_key: mvec[mvec.len() - 4].to_string(),
				listen_port: listen_port,
			}
		);
		
	}
	let udp_port =  m_decode(mvec[mvec.len() - 4].to_string());
	let ip_address = m_decode(mvec[2].to_string());
	let end_port = ENDPORT {
		udp_port: udp_port,
		ip_address: ip_address,
	};
	Neighbor {
		public_key: mvec[1].to_string(),
		payment_address: mvec[1].to_string(), //should have the right address
		seqnum: mvec[mvec.len() - 2].parse::<usize>().unwrap(),
		active:2,
		tunnel: tunnel,
		end_port: end_port,

	}
	
}	


#[cfg(test)]
mod test {
	use bytes::{BytesMut, BufMut};
	use std::str;
	use std::vec::Vec;
	use chrono::prelude::*;
	use edcert::ed25519;
	use base64::{encode, decode};
	use pingnetwork::{PingUpdNetworkProfile};
	use serialization::{ping_msg, build_neighbor};



  #[test]
  fn test_send_data() {
	
	let rx_ip_address = "127.0.0.1".to_string(); 
	let rx_udp_port  = "3456".to_string(); 
	let tx_ip_address = "0.0.0.0".to_string();
	let tx_udp_port = "0".to_string();
	let public_key: String;
	let tunnel_public_key: String;
	let (psk, msk ) = ed25519::generate_keypair();
	let (tpsk, tmsk ) = ed25519::generate_keypair();
	public_key = encode(&psk);
	let public_kay = public_key.clone();
	let public_kay_t = public_kay.clone();
	tunnel_public_key = encode(&tpsk);
	let pip = tx_ip_address.clone();
	let pip_udp = tx_udp_port.clone();
	let mut bg =  PingUpdNetworkProfile::new(
		rx_ip_address,
		rx_udp_port,
		tx_ip_address, 
		tx_udp_port, 
		public_key, 
		msk,
		tmsk,
		tunnel_public_key
	);
	let mut ghh = ping_msg("ipv4_hello".to_string(), &bg);    
	bg.send_data(&mut ghh);
	bg.close();
	
	  
  }
  
  #[test]
  fn test_serialization() {
	let rx_ip_address = "127.0.0.3".to_string(); 
	let rx_udp_port  = "3456".to_string(); 
	let tx_ip_address = "0.0.0.0".to_string();
	let tx_udp_port = "0".to_string();
	let public_key: String;
	let tunnel_public_key: String;
	let (psk, msk ) = ed25519::generate_keypair();
	let (tpsk, tmsk ) = ed25519::generate_keypair();
	public_key = encode(&psk);
	let public_kay = public_key.clone();
	let public_kay_t = public_kay.clone();
	tunnel_public_key = encode(&tpsk);
	let pip = tx_ip_address.clone();
	let pip_udp = tx_udp_port.clone();
	let mut bg =  PingUpdNetworkProfile::new(
		rx_ip_address, 
		rx_udp_port,
		tx_ip_address, 
		tx_udp_port, 
		public_key, 
		msk,
		tmsk,
		tunnel_public_key
	);
	let ghh = ping_msg("ipv4_hello".to_string(), &bg); 
	let mut param = ghh[..].to_vec();
	let mut strnam = String::from_utf8(param).expect("Found invalid UTF-8");
	let mut mvec = strnam.split_whitespace().collect::<Vec<&str>>();
    println!("Testing Hello Message");
	assert_eq!("ipv4_hello".to_string(), mvec[0]);
	
	let bbbb = decode(mvec[2]).unwrap();
	let ffoo = String::from_utf8(bbbb).expect("Found invalid UTF-8");
	println!("Testing IP Address");
	assert_eq!(pip, ffoo);
	println!("Testing Public key");
	assert_eq!(psk, &decode(mvec[1]).unwrap()[..]);
	let cccc = decode(mvec[3]).unwrap();
	let ffuu = String::from_utf8(cccc).expect("Found invalid UTF-8");
	println!("Testing UDP Port");
	assert_eq!(pip_udp, ffuu);	
	assert_eq!("0", mvec[5]);
	let nbnb = decode(mvec[4]).unwrap();
	let xsds = String::from_utf8(nbnb).expect("Found invalid UTF-8");
	println!("Time this network was created");
	println!("{}", xsds);
	bg.close();
	

}
#[test]
  fn test_neighbor() {
	let rx_ip_address = "127.0.0.0".to_string(); 
	let rx_udp_port  = "3456".to_string(); 
	let tx_ip_address = "0.0.0.0".to_string();
	let tx_udp_port = "0".to_string();
	let public_key: String;
	let tunnel_public_key: String;
	let (psk, msk ) = ed25519::generate_keypair();
	let (tpsk, tmsk ) = ed25519::generate_keypair();
	public_key = encode(&psk);
	let public_kay = public_key.clone();
	let public_kay_t = public_kay.clone();
	tunnel_public_key = encode(&tpsk);
	let pip = tx_ip_address.clone();
	let pip_udp = tx_udp_port.clone();
	let mut bg =  PingUpdNetworkProfile::new(
		rx_ip_address, 
		rx_udp_port,
		tx_ip_address, 
		tx_udp_port, 
		public_key, 
		msk,
		tmsk,
		tunnel_public_key
	);
	let ghh = ping_msg("ipv4_hello".to_string(), &bg); 
	let mut param = ghh[..].to_vec();
	let mut strnam = String::from_utf8(param).expect("Found invalid UTF-8");
	let mut mvec = strnam.split_whitespace().collect::<Vec<&str>>();
	let mut bu =  build_neighbor(mvec, 0);
	bg.close();
	println!("Testing Neighbor Public key");
	assert_eq!(psk, &decode(&bu.public_key).unwrap()[..]);
	
	
}


}
