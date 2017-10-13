use std::collections::HashMap;
use neighbor::Neighbor;


pub struct Neighbors {
    neighbrs: HashMap<String, Neighbor>,
    host_status_num: i32,
}

impl Neighbors {
    pub fn new() -> Neighbors {
        let neighbrs: HashMap<String, Neighbor> = HashMap::new();
        Neighbors {
            neighbrs,
            host_status_num: 0,
        }
    }

    pub fn insert_neighbor(&mut self, neighbr: Neighbor) {
        self.neighbrs.insert(neighbr.get_pub_key().clone(), neighbr);
    }

    fn delete_with_pub_key(&mut self, pub_key: &String) {
        self.neighbrs.remove(pub_key);
    }

    //Not relevent may be removed later
    pub fn delete_neighbor(&mut self, neighbr: &Neighbor) {
        self.delete_with_pub_key(&neighbr.get_pub_key());
    }

    pub fn get_neighbor(&mut self, pub_key: &String) -> Option<&Neighbor> {
        self.neighbrs.get(pub_key)
    }

    pub fn get_host_status_num(&mut self) -> i32 {
        self.host_status_num
    }

    pub fn set_host_status_num(&mut self, num: i32) {
        self.host_status_num = num;
    }

    pub fn get_neighbors(&mut self) -> Vec<&Neighbor> {
        let neighbors: Vec<&Neighbor> = self.neighbrs.iter().map(|(_, nbr)| nbr.clone()).collect();
        neighbors
    }

    ///https://stackoverflow.com/questions/28909583/removing-entries-from-a-hashmap-based-on-value
    pub fn remove_inactive_neighbors(&mut self) {
        let empties: Vec<_> = self.neighbrs
            .iter()
            .filter(|&(_, ref value)| value.get_active() != self.host_status_num)
            .map(|(key, _)| key.clone())
            .collect();
        for empty in empties {
            self.delete_with_pub_key(&empty);
        }
    }
}



#[cfg(test)]
mod test {
    use types::ENDPOINT;
    use neighbor::Neighbor;
    use neighbors::Neighbors;
    use base64::{decode, encode};
    use edcert::ed25519;


    fn encodeVal(udp_port: String, ip_address: String) -> (String, String, String) {
        let (psk, _) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk));
    }

    fn neighbor_one() -> Option<Neighbor> {
        let (ip_addr, udp_port, pub_key) = encodeVal("41235".to_string(), "224.0.0.3".to_string());
        let testnum = 45;
        let not_applicable = "N/A";
        let sequm = "3";
        let mut vec = Vec::new();
        vec.push(not_applicable.clone());
        vec.push(&pub_key);
        vec.push(&pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        vec.push(sequm);
        vec.push(not_applicable);//This is a hack to take the place of hash
        return Neighbor::new(vec, testnum);
    }

    fn neighbor_two() -> Option<Neighbor> {
        let (ip_addr, udp_port, pub_key) = encodeVal("51235".to_string(), "224.0.0.7".to_string());
        let testnum = 45;
        let not_applicable = "N/A";
        let sequm = "40";
        let mut vec = Vec::new();
        vec.push(not_applicable.clone());
        vec.push(&pub_key);
        vec.push(&pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        vec.push(sequm);
        vec.push(not_applicable);//This is a hack to take the place of hash
        return Neighbor::new(vec, testnum);
    }


    fn neighbor_three() -> Option<Neighbor> {
        let (ip_addr, udp_port, pub_key) = encodeVal("44235".to_string(), "224.0.0.2".to_string());
        let testnum = 42;
        let not_applicable = "N/A";
        let sequm = "3";
        let mut vec = Vec::new();
        vec.push(not_applicable.clone());
        vec.push(&pub_key);
        vec.push(&pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        vec.push(sequm);
        vec.push(not_applicable);//This is a hack to take the place of hash
        return Neighbor::new(vec, testnum);
    }

    fn neighbor_four() -> Option<Neighbor> {
        let (ip_addr, udp_port, pub_key) = encodeVal("41295".to_string(), "224.0.0.1".to_string());
        let testnum = 42;
        let not_applicable = "N/A";
        let sequm = "3";
        let mut vec = Vec::new();
        vec.push(not_applicable.clone());
        vec.push(&pub_key);
        vec.push(&pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        vec.push(sequm);
        vec.push(not_applicable);//This is a hack to take the place of hash
        Neighbor::new(vec, testnum)
    }

    fn given_neighbors() -> Neighbors {
        let mut ngbs = Neighbors::new();
        match neighbor_one() {
            Some(v) => ngbs.insert_neighbor(v),
            _ => {}
        };
        match neighbor_two() {
            Some(v) => ngbs.insert_neighbor(v),
            _ => {}
        };
        match neighbor_three() {
            Some(v) => ngbs.insert_neighbor(v),
            _ => {}
        };
        match neighbor_four() {
            Some(v) => ngbs.insert_neighbor(v),
            _ => {}
        };
        ngbs
    }


    #[test]
    fn neighbors_test_number_neighbors() {
        let mut ngbrs = given_neighbors();

        let  vec_neighbors = ngbrs.get_neighbors();

        assert_eq!(vec_neighbors.len(), 4);
    }

    #[test]
    fn neighbors_test_remove_inactive_neighbors() {
        let mut ngbrs = given_neighbors();

        ngbrs.set_host_status_num(45);

        ngbrs.remove_inactive_neighbors();

        let vec_neighbors = ngbrs.get_neighbors();

        assert_eq!(vec_neighbors.len(), 2);
    }

}