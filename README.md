# neighbor
Network Neighbor Discovery



Ping Pong Neighbour Discovery 

The Ping host would initiate neighbor discovery, by 
multcasting a "hello" message.
We will keep daemon(pong) running and listening to udp port. 
These daemons are already joined to the multicasting ip address as members.
They would only response to "hello" world message. When such messages come along
they will send their profile back.

1. This is the format that the payload would look at the Ping (initiator of multicast)
	- base64 ecode and decode are used
	- ed25519 is used for hash signature and verification
	- Hello_message ::= "ipv4_hello" Or "ipv4_hello_tunnel"
	- Hello_message is not encoded , just plane ascii.
	- It is the playload header.
	- Each individual item in the payload is separated by empty space
  
	- Following the header are 
		- public_key ::= encoded public_key
		- ip_address ::= encoded ip_address
		- udp_port ::= encoded udp_port
		- created_time_utc ::= encoded timestamp
		- seqnum ::= integer
The above payload is hash signed and the hash result appended to the above.

2.	At the Pong (daemon).
	- It reads the above , if header is correct, it then splits the received message
	- It would verify the hash sign using public key. It passes, it would build and send return payload
	- base64 ecode and decode are used
	- Hello_message ::= "ipv4_hello_confirm" Or "ipv4_hello_tunnel_confirm"
	- Hello_message is not encoded , just plane ascii.
	- It is the playload header.
    
    - Following the header are 
		- public_key ::= encoded public_key
		- payment_address ::= encoded public_key_t
		- ip_address ::= encoded ip_address
		- udp_port ::= encoded udp_port
		- tunnel_ip_address ::= encoded tunnel_ip_address ("ipv4_hello_tunnel_confirm")
		- tunnel_udp_port ::= encoded tunnel_udp_port ("ipv4_hello_tunnel_confirm")
		- created_time_utc ::= encoded timestamp,
		- tunnel_public_key ::= encoded tunnel_public_key
		- seqnum ::= integer

The above payload is hash signed and the hash result appended to the above.
The Ping will receive this message , and accepts it if it has either
"ipv4_hello_confirm" Or "ipv4_hello_tunnel_confirm" as its header
It will separate the items, and build a neighbor object. This object is 
inserted in to a table which is keyed by public_key.

The seqnum will be used to avoid cheating from pongs. And the table would be 
checked for nodes that are not atcive, and such nodes would be removed.

```
To use ::
use pingnetwork::Multicast_Net;
use neighbor::Neighbor;

let mut network = Multicast_Net::new("224.0.0.8".to_string(),"41239".to_string(), vec, secret );
network.start_net();
vec is vector:
item number 0 :: encoded public key
item number 1 :: encoded payment address
item number 2 :: encoded IP address (Multicast)
item number 3 :: encoded UDP port number

The IP address in the argument is the one used for receiving with its corresponding port
```