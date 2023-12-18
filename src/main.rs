mod structs {
    pub mod dns_flags;
    pub mod dns_header;
    pub mod dns_packet;
    pub mod dns_packet_buffer;
    pub mod dns_question;
    pub mod dns_record_types;
    pub mod dns_resource_record;
    pub mod error;
    pub mod record_types {
        pub mod a_record;
        pub mod aaaa_record;
        pub mod cname_record;
        pub mod mx_record;
        pub mod ns_record;
        pub mod ptr_record;
        pub mod soa_record;
        pub mod srv_record;
        pub mod txt_record;
    }
}

mod utils;

use std::io::Read;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::thread;

use crate::structs::dns_packet::DNSPacket;
use crate::structs::dns_packet_buffer::DNSPacketBuffer;
use crate::utils::{print_bytes_to_hex, temp_dns_packet, ToDNSLabels};

fn main() {
    // enable tracing
    tracing_subscriber::fmt::init();
    const BIND_ADDR: &str = "127.0.0.1:5300";
    let udp_thread = thread::spawn(|| {
        handle_udp(BIND_ADDR);
    });

    let tcp_thread = thread::spawn(|| {
        handle_tcp(BIND_ADDR);
    });

    udp_thread.join().expect("UDP thread join error");
    tcp_thread.join().expect("TCP thread join error");

    println!("UDP running at {}", &BIND_ADDR);
    println!("TCP running at {}", &BIND_ADDR);
}

fn handle_udp(bind_addr: &str) {
    let udp_socket = UdpSocket::bind(bind_addr).expect("Failed to bind UDP socket");
    let mut udp_buffer = [0u8; 512];

    let external_dns_server = ("8.8.4.4", 53);
    let external_socket = UdpSocket::bind("0.0.0.0:5301").expect("Failed to create external socket");

    loop {
        let (amt, src) = udp_socket
            .recv_from(&mut udp_buffer)
            .expect("UDP receive error");

        println!("Received UDP packet of size {} from {:?}", amt, src);

        let parsed = DNSPacket::parse(udp_buffer);
        let buffer = DNSPacketBuffer::new(udp_buffer);

        print_bytes_to_hex(buffer.base_packet());

        match parsed {
            Ok(packet) => {
                if packet.contains_question("google.com".to_dns_labels()) {
                    let response = temp_dns_packet(packet.header, packet.questions);
                    let mut response_buffer = DNSPacketBuffer {
                        buffer: [0u8; 512],
                        offset: 0,
                        domains: vec![],
                    };

                    let res = response.write_to_buffer(&mut response_buffer);
                    match res {
                        Ok(_) => {
                            println!("response packet: ");
                            print_bytes_to_hex(&response_buffer.response_bytes());
                        }
                        Err(e) => {
                            println!("Error writing packet: {:?}", e);
                        }
                    }
                    let sent = udp_socket.send_to(&response_buffer.response_bytes(), src);
                    match sent {
                        Ok(_) => {}
                        Err(err) => {
                            println!("Error sending packet: {:?}", err);
                        }
                    }
                } else {
                    println!("tring to send via google");
                    // Forward the query to 8.8.8.8.
                    external_socket
                        .send_to(&buffer.buffer[0..amt], &external_dns_server)
                        .expect("Failed to send to external DNS");

                    println!("sent to socket");

                    // Receive the response from 8.8.8.8.
                    let mut new_buffer = [0u8; 512];
                    let (_ext, _) = external_socket
                        .recv_from(&mut new_buffer)
                        .expect("Failed to receive from external DNS");


                    // Send the response back to the client.
                    udp_socket
                        .send_to(&new_buffer, src)
                        .expect("Failed to send to client");
                    println!("sent to client");
                }
            }
            Err(e) => {
                println!("Error parsing packet: {:?}", e);
            }
        }
        // Process the UDP packet as needed
    }
}

fn handle_tcp(bind_addr: &str) {
    let tcp_listener = TcpListener::bind(bind_addr).expect("Failed to bind TCP listener");

    for stream in tcp_listener.incoming() {
        let mut stream = stream.expect("TCP connection error");
        println!("Accepted TCP connection from {:?}", stream.peer_addr());

        let mut tcp_buffer = [0u8; 512];
        let amt = stream.read(&mut tcp_buffer).expect("TCP read error");
        print_bytes_to_hex(&tcp_buffer);

        let parsed = DNSPacket::parse(tcp_buffer);
        println!("Received TCP packet of size {}", amt);
        println!("parsed data: \n{:#?}", parsed);

        // Process the TCP packet as needed
    }
}
