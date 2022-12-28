mod tcp;
mod validation;
mod sequence;
mod header;

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
                        match conns.entry(Quad {
                            src: (iph.source_addr(), tcph.source_port()),
                            dst: (iph.destination_addr(), tcph.destination_port()),
                        }) {
                            std::collections::hash_map::Entry::Occupied(mut conn) => {
                                conn.get_mut().on_packet(&mut dev, iph, tcph, &buf[datastart..nbytes])?;
                            },
                            std::collections::hash_map::Entry::Vacant(conn) => {
                                conn.insert(Connection::create(&mut dev, iph.to_header(), tcph.to_header())?);
                            }

                        };
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
