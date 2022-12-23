use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();

    let mut buf = [0u8; 1504];
    let mut dev = tun::create(&config).unwrap();

    loop {
        dev.read(&mut buf).unwrap();
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..]) {
            Ok(ip) => {
                let src = ip.source_addr();
                let dst = ip.destination_addr();
                let proto = ip.protocol();
                let id = ip.identification();
                let len = ip.payload_len();
                println!("{} -> {} {}b proto: {} id: {}", src, dst, len, proto, id);
            }
            Err(e) => {
                println!("Received non-IP packet: {:?}", e);
            }
        };
    }
}
