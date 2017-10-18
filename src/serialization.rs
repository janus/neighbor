use bytes::{BufMut, BytesMut};
use neighbor::Neighbor;
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};

const BUFFER_CAPACITY_MESSAGE: usize = 400;

pub fn decode_key(mstr: &str) -> Option<Vec<u8>> {
    match decode(mstr) {
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
    profile: &Vec<&str>,
    seqnum: i32,
    secret: &[u8; 64],
    header_msg: &str,
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

pub fn on_pong(packet: &BytesMut, active: i32) -> Option<Neighbor> {
    let vec_str: Vec<&str>;
    let payload;
    let pub_key;
    let sig;
    let tm;
    if check_size(&packet) && match_header(&packet) {
        vec_str = bytes_vec(&packet);
        payload = extract_payload(&vec_str);
        match vec_str[vec_str.len() - 3].parse::<i64>() {
            Ok(v) => {
                tm = time::get_time().sec;
                if !time_within(v, tm) {
                    return None;
                }
            },
            Err(e) => {
                println!("Bad protocol: failed to extract {:?}", e);
                return None;
            }
        };
        pub_key = match decode_key(&vec_str[1]) {
            Some(v) => v,
            _ => { return None; }
        };
        sig = match decode_key(&vec_str[vec_str.len() - 1]) {
            Some(v) => v,
            _ => { return None; }
        };
        if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {

            match Neighbor::new(&vec_str, active) {
                Some(ngb) => { return Some(ngb);}
                _ => { return None; }
            };
        }
    }
    return None;
}

pub fn match_header(packet: &BytesMut) -> bool {
    match str::from_utf8(&packet[0..13]) {
        Ok(v) => {
            return  "hello_confirm" == v;
        },
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            return false;
        }
    };
}

pub fn check_size(packet: &BytesMut) -> bool {
    packet.len() > 200
}

pub fn time_within(sent_tm: i64, now_tm: i64) -> bool {
    now_tm <= sent_tm
}

fn bytes_vec(packet: &BytesMut) -> Vec<&str> {
    let str_buf = match str::from_utf8(&packet[..]) {
        Ok(v) => v,
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            ""
        }
    };
    str_buf.split_whitespace().collect()
}

fn extract_payload(vec: &Vec<&str>) -> String {
    vec[0..7].join(" ")
}

#[cfg(test)]
mod test {

    use time;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};

    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);

    }

    fn pong_host() -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41235", "224.0.0.3");
        let mut vec: Vec<&str> = Vec::new();
        let pb_key = pub_key.clone();
        vec.push(&pub_key);
        vec.push(&pub_key); // Used as payment address
        vec.push(&ip_addr);
        vec.push(&udp_port);
        let bytes = serialization::payload(&vec, 45, &secret, "hello_confirm");
        return (bytes, pb_key, secret);
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
        let header_str = String::from_utf8(mbytes[0..13].to_vec()).expect("Found invalid UTF-8");
        assert_eq!(header_str, "hello_confirm");
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

        match serialization::on_pong(&mbytes, 8) {
            Some(ngb) => assert_eq!(ngb.get_endpoint().ip_address, "224.0.0.3"),
            _ => assert!(false),
        };
    }
}