mod tcp;

use std::{io::{self, Read}, net::Ipv4Addr, collections::HashMap};
use tcp::Connection;


#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut config = tun::Configuration::default();
    let mut conns: HashMap<Quad, Connection> = HashMap::new();

    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();

    let mut buf = [0u8; 1504];
    let mut dev = tun::create(&config).unwrap();

    loop {
        let nbytes = dev.read(&mut buf).unwrap();
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(iph) => {
                let proto = iph.protocol();
                if proto != 0x06 {
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        let datastart = 4 + iph.slice().len() + tcph.slice().len();
                        conns.entry(Quad {
                            src: (iph.source_addr(), tcph.source_port()),
                            dst: (iph.destination_addr(), tcph.destination_port()),
                        }).or_insert(Connection::new()).on_packet(&mut dev, iph, tcph, &buf[datastart..nbytes])?;
                    }
                    Err(e) => {
                        println!("Received weird packet: {:?}", e);

                    }
                }
            }
            Err(e) => {
                println!("Received non-IP packet: {:?}", e);
            }
        };
    }
}
