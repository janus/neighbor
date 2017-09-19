//use bytes::{BytesMut, Buf, Bytes};

use std::collections::HashMap;
use types::Neighbor;


pub struct Neighbors {
	members: HashMap<String, Neighbor>,
	host_status_num: usize,
}

impl Neighbors {
	pub fn new() -> Neighbors {
		let members: HashMap<String, Neighbor> = HashMap::new();

		Neighbors {
			members,
			host_status_num: 0,
		}
	}

	pub fn add_to_table(&mut self, member: Neighbor) {
		self.members.insert(member.public_key.clone(), member);
	}

	pub fn remove_from_table(&mut self, public_key: String) {
		self.members.remove(&public_key);
	}
	///https://stackoverflow.com/questions/28909583/removing-entries-from-a-hashmap-based-on-value
	pub fn clean_table(&mut self) {
		let empties: Vec<_> = self.members
			.iter()
			.filter(|&(_, ref v)| v.active != self.host_status_num)
			.map(|(k, _)| k.clone())
			.collect();
		for empty in empties {
			self.members.remove(&empty);
		}
	}
}
