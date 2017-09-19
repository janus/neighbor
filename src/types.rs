



pub struct Account{
	pub public_key: String,
	pub private_key: String,
	pub seqnum: usize,
	pub status_num: usize,
	pub end_port: ENDPORT
}

pub struct ENDPORT {
	pub ip_address: String,
	pub udp_port: String

}



pub struct Neighbor {
	pub active: usize,
	pub public_key: String,
	pub seqnum: usize,
	pub payment_address: String,
	pub end_port: ENDPORT
}
