use types::ENDPOINT;
use base64::decode;
use std::str;


pub fn decode_str(mstr: &str) -> Option<String> {
    match decode(mstr) {
        Ok(v) => {
            match String::from_utf8(v) {
                Ok(v) => {
                    return Some(v);
                }
                Err(e) => {
                    println!("Failed utf8 conversion  {}", e);
                    return None;
                }
            };
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return None;
        }
    };
}

pub struct Neighbor {
    active: i32,
    pub_key: String,
    seqnum: i32,
    payment_address: String,
    end_port: ENDPOINT,
}

impl Neighbor {
    pub fn new(vec_fields: Vec<&str>, ttnum: i32) -> Option<Neighbor> {
        let ip_address;
        let end_port: ENDPOINT;
        let num;
        let udp_port;
        let negh: Neighbor;
        udp_port = match decode_str(vec_fields[4]) {
            Some(v) => v,
            _ => return None,
        };
        ip_address = match decode_str(vec_fields[3]) {
            Some(v) => v,
            _ => return None,
        };
        end_port = ENDPOINT {
            udp_port: udp_port.to_string(),
            ip_address: ip_address.to_string(),
        };
        num = match vec_fields[vec_fields.len() - 2].parse::<i32>() {
            Ok(v) => v,
            Err(e) => {
                println!("Failed to parse num {:?}", e);
                return None;
            }
        };
        negh = Neighbor {
            pub_key: vec_fields[1].to_string(),
            payment_address: vec_fields[2].to_string(), //should have the right address
            seqnum: num,
            active: ttnum,
            end_port: end_port,
        };
        return Some(negh);
    }

    pub fn get_pub_key(&self) -> &String {
        &self.pub_key
    }

    pub fn get_payment_address(&self) -> &String {
        &self.payment_address
    }

    pub fn get_endpoint(&self) -> &ENDPOINT {
        &self.end_port
    }

    pub fn get_seqnum(&self) -> i32 {
        self.seqnum
    }

    pub fn get_active(&self) -> i32 {
        self.active
    }
}

#[cfg(test)]
mod test {
    use base64::{ encode};
    use neighbor::Neighbor;
    use edcert::ed25519;


    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String) {
        let (psk, _) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk));
    }

    fn given_neighbor() -> Option<(Neighbor, String)> {
        let (ip_addr, udp_port, pub_key) = encodeVal("41235", "224.0.0.3");
        let testnum = 45;
        let cloned_pub_key = pub_key.clone();
        let not_applicable = "N/A";
        let sequm = "3";
        let mut vec = Vec::new();
        vec.push(not_applicable.clone());
        vec.push(&pub_key);
        vec.push(&pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        vec.push(sequm);
        vec.push(not_applicable); //This is a hack to take the place of hash
        let ngb = match Neighbor::new(vec, testnum) {
            Some(v) => v,
            _ => {
                println!("Bad protocol");
                return None;
            }
        };
        return Some((ngb, cloned_pub_key));
    }

    #[test]
    fn neighbor_test_pub_key() {
        match given_neighbor() {
            Some((n, k)) => assert_eq!(n.get_pub_key(), &k),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }

    #[test]
    fn neighbor_test_payment_address() {
        match given_neighbor() {
            Some((n, k)) => assert_eq!(n.get_payment_address(), &k),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }

    #[test]
    fn neighbor_test_end_port_udp_port() {
        match given_neighbor() {
            Some((n, _)) => assert_eq!(n.get_endpoint().udp_port, "41235"),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }

    #[test]
    fn neighbor_test_end_port_ip_address() {
        match given_neighbor() {
            Some((n, _)) => assert_eq!(n.get_endpoint().ip_address, "224.0.0.3"),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }

    #[test]
    fn neighbor_test_seqnum() {
        match given_neighbor() {
            Some((n, _)) => assert_eq!(n.get_seqnum(), 3),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }

    #[test]
    fn neighbor_test_active_num() {
        match given_neighbor() {
            Some((n, _)) => assert_eq!(n.get_active(), 45),
            _ => {
                println!("Failed Neighbor asserting false");
                assert!(false);
            }
        };
    }
}