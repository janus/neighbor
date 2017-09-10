//use bytes::{BytesMut, Buf, Bytes};

use std::collections::HashMap;
use types::{ENDPORT, Account, Neighbor};


pub struct Neighbors {
	members: HashMap<String, Neighbor>,
	host: Account,
}

impl Neighbors {
	pub fn new(status_num: usize,public_key: String, private_key: String, ip_address: String, udp_port: String, tcp_port: String, tunnel_public_key:  String, tunnel_private_key: String, seqnum: usize) -> Neighbors{
			let end_port = ENDPORT {
				ip_address,
				udp_port,
				tcp_port,
			};
			
			let mut members: HashMap<String, Neighbor> = HashMap::new();
			let host = Account {
				public_key,
				private_key,
				seqnum,
				status_num,
				tunnel_public_key,
				tunnel_private_key,
				end_port,
			};
			
			Neighbors{
				members,
				host,
			}
			
	}
	
	pub fn add_to_table(&mut self, member: Neighbor, public_key: String) {
		
			self.members.insert(public_key, member);
	}
		
	pub fn remove_from_table(&mut self,public_key: String){
			self.members.remove(&public_key);
	}
	///https://stackoverflow.com/questions/28909583/removing-entries-from-a-hashmap-based-on-value
	pub fn clean_table(&mut self){
		let empties: Vec<_> = self.members
			.iter()
			.filter(|&(_, ref v)| v.active != self.host.status_num)
			.map(|(k, _)| k.clone())
			.collect();
        for empty in empties { self.members.remove(&empty); }
        

	}
			
			
			
}
	
		

	
