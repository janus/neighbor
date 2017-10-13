use bytes::{BufMut, BytesMut};
use neighbor::Neighbor;
use time;
use edcert::ed25519;
use base64::{decode, encode};

const BUFFER_CAPACITY_MESSAGE: usize = 400;

pub fn decode_key(mstr: String) -> Option<Vec<u8>> { //this could also use the decode_str function I'm pretty sure 
    match decode(&mstr) {                            //String and Vec u8 are equal? Or very close (jkilpatr)
        Ok(v) => {
            return Some(v);
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return None;
        }
    };
}

pub fn payload(
    profile: &Vec<&String>,
    seqnum: i32,
    secret: &[u8; 64],
    header_msg: String,
) -> BytesMut {
    let sig;
    let tme = time::get_time().sec + 70;
    let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
    let msg = format!(
        "{} {} {} {} {} {} {}",
        header_msg,
        profile[0],
        profile[1],
        profile[2],
        profile[3],
        tme,
        seqnum
    );
    sig = ed25519::sign(msg.as_bytes(), secret);
    rslt.put(msg);
    rslt.put(" ");
    rslt.put(encode(&sig));
    rslt
}

pub fn on_pong(packet: BytesMut, active: i32) -> Option<Neighbor> {
    let vec_str: Vec<String>;
    let payload;
    let pub_key;
    let sig;
    let tm;
    let vec: Vec<&str>;
    if check_size(&packet) {
        if match_header(&packet) {
            vec_str = bytes_vec(&packet);
            payload = extract_payload(&vec_str);
            match vec_str[vec_str.len() - 3].parse::<i64>() {
                Ok(v) => {
                    tm = time::get_time().sec;
                    if !time_within(v, tm) {
                        return None;
                    }
                }
                Err(e) => {
                    println!("Poor protocol: failed to extract {:?}", e);// Bad packet is a better error message (jkilpatr)
                    return None;
                }
            };
            pub_key = match decode_key(vec_str[1].clone()) {
                Some(v) => v,
                _ => {
                    return None;
                }
            };
            sig = match decode_key(vec_str[vec_str.len() - 1].clone()) {
                Some(v) => v,
                _ => {
                    return None;
                }
            };
            if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {
                vec = vec_str.iter().map(|s| &**s).collect();
                match Neighbor::new(vec, active) {
                    Some(ngb) => {
                        return Some(ngb);
                    }
                    _ => {
                        return None;
                    }
                };
            }
        }
    }
    return None;
}

pub fn match_header(packet: &BytesMut) -> bool {
    match String::from_utf8(packet[0..18].to_vec()) {
        Ok(v) => {
            if "ipv4_hello_confirm" == v {
                return true;
            } else {
                return false;
            }
        }
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            return false;
        }
    };
}

pub fn check_size(packet: &BytesMut) -> bool {
    if packet.len() > 200 { true } else { false }
}

pub fn time_within(sent_tm: i64, now_tm: i64) -> bool {
    if now_tm <= sent_tm { true } else { false }
}

fn bytes_vec(packet: &BytesMut) -> Vec<String> {
    let vec_str: Vec<String>;
    let ping_msg_vec = packet[..].to_vec();
    let str_buf = match String::from_utf8(ping_msg_vec) {
        Ok(v) => v,
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            "".to_string()
        }
    };
    vec_str = str_buf.split_whitespace().map(|s| s.to_string()).collect();
    vec_str
}

fn extract_payload(vec: &Vec<String>) -> String {
    vec[0..7].join(" ")
}

#[cfg(test)]
mod test {

    use time;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};

    fn encodeVal(udp_port: String, ip_address: String) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);

    }

    fn pong_host() -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41235".to_string(), "224.0.0.3".to_string());
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(&pub_key);
        vec.push(&cloned_pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        let bytes = serialization::payload(&vec, 45, &secret, "ipv4_hello_confirm".to_string());
        return (bytes, pub_key.clone(), secret);
    }

    fn not_time() -> Option<i64> {
        let n = 40;
        if n > 20 {
            return Some(n);
        } else {
            return None;

        }

    }
    fn time_within(sent_tm: i64, now_tm: i64) -> bool {
        if now_tm <= sent_tm { true } else { false }
    }

    #[test]
    fn serialization_test_header_msg() {
        let (mbytes, _, _) = pong_host();
        let header_str = String::from_utf8(mbytes[0..18].to_vec()).expect("Found invalid UTF-8");
        assert_eq!(header_str, "ipv4_hello_confirm");
    }

    #[test]
    fn serialization_test_time() {
        let (mbytes, _, _) = pong_host();
        let vec = serialization::bytes_vec(&mbytes);
        let packet_tm = vec[vec.len() - 3].parse::<i64>().unwrap();
        let now_tm = time::get_time().sec as i64;
        assert_eq!(time_within(packet_tm, now_tm), true);
    }

    #[test]
    fn serialization_test_packet_header() {
        let (mbytes, _, _) = pong_host();
        serialization::on_pong(mbytes.clone(), 8);

        match serialization::on_pong(mbytes, 8) {
            Some(ngb) => assert_eq!(ngb.get_endpoint().ip_address, "224.0.0.3"),
            _ => assert_eq!(false, true),
        };
    }
}
