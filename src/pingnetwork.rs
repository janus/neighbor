use bytes::{BytesMut, Buf, BufMut};
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::net::SocketAddr;
use mio::udp::*;
use serialization;
use time;
use neighbors::Neighbors;
use neighbor::decode_str;


const BUFFER_CAPACITY: usize = 800;
const LISTENER: Token = Token(0);
const SENDER: Token = Token(1);


pub fn UDPsocket(ipadr: &String, port: &String) -> (UdpSocket, SocketAddr) {
    let ip_and_port = format!("{}:{}", ipadr.clone(), port);
    let saddr: SocketAddr = ip_and_port.parse().unwrap();
    let socket = match UdpSocket::bind(&saddr) {
        Ok(s) => s,
        Err(e) => panic!("Failed to establish bind socket {}", e),
    };
    (socket, saddr)
}

pub fn dcod(mstr: String) -> String { //why not just call the decode string function instead of wrapping it again in this file? (jkilpatr)
    let dstr = match decode_str(mstr.clone()) {
        Some(v) => v,
        _ => {
            panic!("Failed to decode {}", mstr);
        }
    };
    dstr
}

pub struct Multicast_Net {
    tx: UdpSocket,
    rx: UdpSocket,
    secret: [u8; 64],
    shutdown: bool,
    packet_sent: bool,
    buf: BytesMut,
    st_time: i64,
    ipaddr: SocketAddr,
    pub nodes: Neighbors,
}

impl Multicast_Net {
    pub fn new(
        rx_ip: String,
        rx_udp: String,
        pro_vec: Vec<&String>,
        secret: [u8; 64],
    ) -> Multicast_Net {
        let (rx_udpsock, _) = UDPsocket(&rx_ip, &rx_udp);
        let (tx_udpsock, ip_addr) = UDPsocket(&dcod(pro_vec[2].clone()), &dcod(pro_vec[3].clone()));
        match tx_udpsock.set_multicast_ttl_v4(1) { //what if we use ipv6? (jkilpatr)
            Ok(n) => n,
            Err(e) => panic!("Failed to set multicast ttl {}", e),
        };

        Multicast_Net {
            tx: tx_udpsock,
            rx: rx_udpsock,
            secret: secret,
            ipaddr: ip_addr,
            buf: serialization::payload(&pro_vec, 0, &secret, "ipv4_hello".to_string()),
            shutdown: false,
            packet_sent: false,
            st_time: time::get_time().sec,
            nodes: Neighbors::new(),
        }
    }

    pub fn parse_packet(&mut self, buf: BytesMut) {
        match serialization::on_pong(buf, self.nodes.get_host_status_num()) {
            Some(ngb) => {
                self.nodes.insert_neighbor(ngb);
            }
            _ => {}
        };
    }

    pub fn read_udpsocket(&mut self, _: &mut Poll, token: Token, _: Ready) {
        let mut current_time = 0 as i64;
        match token {
            LISTENER => {
                let mut buf: BytesMut = BytesMut::with_capacity(BUFFER_CAPACITY);
                match self.rx.recv_from(&mut buf[..]) {
                    Ok(Some((len, address))) => {
                        current_time = time::get_time().sec;
                        self.parse_packet(buf);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error reading UDP packet: {:?}", e);
                    }
                };
                if current_time > self.st_time {
                    self.shutdown = true;
                }
            }
            _ => (),
        }
    }

    pub fn send_packet(&mut self, _: &mut Poll, token: Token, _: Ready) {
        if self.packet_sent {
            return;
        }
        match token {
            SENDER => {
                match self.tx.send_to(&self.buf[..], &self.ipaddr) {
                    Ok(Some(size)) if size == self.buf.len() => {
                        self.packet_sent = true;
                        self.st_time = time::get_time().sec + 120;
                    }
                    Ok(Some(_)) => {
                        println!("UDP sent incomplete payload");
                    }
                    Ok(None) => {
                        println!("UDP sent Nothing");;
                    }
                    Err(e) => {
                        println!(
                            "Error send UDP:: {:?} and the sock_addr is {:?}",
                            e,
                            &self.ipaddr
                        );
                    }
                };
            }
            _ => (),
        }
    }

    pub fn start_net(&mut self) {
        let mut poll = Poll::new().unwrap();

        poll.register(&self.tx, SENDER, Ready::writable(), PollOpt::edge())
            .unwrap();

        poll.register(&self.rx, LISTENER, Ready::readable(), PollOpt::edge())
            .unwrap();

        let mut events = Events::with_capacity(1024);

        while !self.shutdown {
            poll.poll(&mut events, None).unwrap();
            for event in &events {
                if event.readiness().is_readable() {
                    self.read_udpsocket(&mut poll, event.token(), event.readiness());
                }
                if event.readiness().is_writable() {
                    self.send_packet(&mut poll, event.token(), event.readiness());
                }
            }
        }
    }

    pub fn close(self) {
        drop(self.tx);
        drop(self.rx);
    }
}


#[cfg(test)]
mod test {
    use time;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use pingnetwork::Multicast_Net;


    fn encodeVal(udp_port: String, ip_address: String) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);

    }

    #[test]
    fn test_network_returned() {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41235".to_string(), "224.0.0.3".to_string());
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(&pub_key);
        vec.push(&cloned_pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        let bytes =
            serialization::payload(&vec.clone(), 45, &secret, "ipv4_hello_confirm".to_string());
        let mut network =
            Multicast_Net::new("224.0.0.8".to_string(), "41239".to_string(), vec, secret);
        network.parse_packet(bytes);
        assert_eq!(1, network.nodes.get_neighbors().len());
    }



}
