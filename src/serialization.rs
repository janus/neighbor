
use base64::{encode, decode};
use bytes::{BytesMut, BufMut, Buf};
use edcert::ed25519;
use types::HelloMessage;
use types::Account;
use types::Neighbor;
use types::ENDPORT;
use types;

const BUFFER_CAPACITY_MESSAGE:usize = 4096;
///To be filtered out a bit
fn return_hello_msg(msg: types::HelloMessage,private_key: &BytesMut, payment_address: &BytesMut ) ->BytesMut{
	let msg_type: String;
	let str_tmp;
	let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);

	if msg.confirm {
		msg_type = "ipv4_hello_confirm".to_string();
		str_tmp = format!("{} {} {} {} {} {} {} {} {}", msg_type,
			encode(&msg.message_metadata.source_public_key),
			encode(&msg.message_metadata.destination_public_key),
			encode(&msg.message_metadata.source_ip_address),
			encode(&msg.message_metadata.destination_ip_address),
			encode(&payment_address),
			encode(&msg.message_metadata.ports),
			encode(&msg.created_time_utc),
			msg.message_metadata.seqnum);
	} else {
		msg_type = "ipv4_hello".to_string();
		str_tmp = format!("{} {} {} {} {} {}", msg_type, 
			encode(&msg.message_metadata.source_public_key),
			encode(&msg.message_metadata.source_ip_address),
			encode(&msg.message_metadata.ports),
			encode(&msg.created_time_utc),
			msg.message_metadata.seqnum);
	}

	let sig = ed25519::sign(str_tmp.as_bytes(), &private_key);

	rslt.put(str_tmp);
	rslt.put(" ");
	rslt.put(encode(&sig));
	rslt

}


///To be completed

fn return_tunnel_msg(msg: types::TunnelMessage,private_key:&BytesMut ) ->BytesMut{
	let msg_type: String;
	let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
	if msg.confirm {
		msg_type = "ipv4_tunnel_confirm".to_string();
	} else {
		msg_type = "ipv4_tunnel".to_string();
	}

    let str_tmp = format!("{} {} {} {} {} {} {} {}", msg_type,
        encode(&msg.message_metadata.source_public_key),
		encode(&msg.message_metadata.destination_public_key),
		encode(&msg.message_metadata.ports),
		encode(&msg.tunnel_public_key),
		encode(&msg.tunnel_end_point),
		encode(&msg.created_time_utc),
		msg.message_metadata.seqnum);

	let sig = ed25519::sign(str_tmp.as_bytes(), &private_key);

	rslt.put(str_tmp);
	rslt.put(" ");
	rslt.put(encode(&sig));
	rslt
}

fn vec_str(data: &str) ->Vec<&str> {
	let mut itm = data.split_whitespace();
	let s_vec = itm.collect::<Vec<&str>>();
	s_vec
}

fn end_port(ip_address: &str, mvec: Vec<&str>) ->ENDPORT{
	let mut mtcp = "".to_string();
    if mvec.len() == 2 {
		mtcp = mvec[1].to_string();
    }
	ENDPORT{
		ip_address: ip_address.to_string(),
	    udp_port: mvec[0].to_string(),
	    tcp_port: mtcp,
    }
    
}

fn parse_msg(mvec: Vec<&str>, active: usize) ->Neighbor{
	
	let sig = match decode(&mvec[mvec.len() - 1]) {
		Ok(v) => v,
		Err(e) => panic!("Failed to decode signature, {}", e),
	};
	let pub_key = mvec[1];
	let joined = mvec[1..mvec.len() - 1].join(" ");
	if !ed25519::verify(joined.as_bytes(), &sig, pub_key.as_bytes()) {
		panic!("This message is altered");
	}

	if mvec[0] == "ipv4_hello_confirm" {
		///Do some work...
        let mut slipt_ports = mvec[mvec.len() - 3].split(":");
        let port_vec = slipt_ports.collect::<Vec<&str>>();

        Neighbor {
			active: active,
	        public_key: mvec[1].to_string(),
	        seqnum: mvec[mvec.len() - 1].parse::<usize>().unwrap(),
	        payment_address: mvec[mvec.len() - 4].to_string(),
	        end_port: end_port(mvec[3],port_vec),  
	        tunnel: None,

		}
	} 
	else{
        // yet to the completed
        let mut slipt_ports = mvec[mvec.len() - 3].split(":");
        let port_vec = slipt_ports.collect::<Vec<&str>>();

        Neighbor {
			active: active,
	        public_key: mvec[1].to_string(),
	        seqnum: mvec[mvec.len() - 1].parse::<usize>().unwrap(),
	        payment_address: mvec[mvec.len() - 4].to_string(),
	        end_port: end_port(mvec[3],port_vec),  
	        tunnel: None,

		}
	}
		

}


fn parse_response(mvec: Vec<&str>, account_pub_key: &str, created_time_utc: &str, cu_seq: usize, active: usize) {
	if account_pub_key != mvec[2] && created_time_utc == mvec[mvec.len() - 2] {
		//let str_cu_seq = format!("{}",cu_seq);
		if cu_seq.to_string() == mvec[mvec.len() - 1]{
			if mvec[0] == "ipv4_hello_confirm" || mvec[0] == "ipv4_tunnel_confirm" {
				parse_msg(mvec, active);
			}
			
		}
		
	}
}
	

#[cfg(test)]
mod test {
	use serialization::vec_str;
	use bytes::{BytesMut, BufMut};
	use std::str;
	use serialization::parse_msg;
	use chrono::prelude::*;
	


  #[test]
  fn test_serialization() {
	
	let utc: DateTime<Utc> = Utc::now();
	let bb = format!("{}", utc);
    println!("serialization {}",bb);
    let  mut ipad = String::from("127.0.0.1");
    //make_vec_string(ipad.as_bytes());
    let mut ope = BytesMut::with_capacity(50);
    ope.put("ipv_hello Time to Move up");
    let mut mm = match str::from_utf8(&ope){
		Ok(s) => s,
		Err(e) => panic!("Bad {}", e),
	};



}
}
