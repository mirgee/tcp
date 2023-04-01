use etherparse::Ipv4Header;

type Ipv4Address = [u8; 4];

#[derive(Debug)]
pub struct Ipv4HeaderBuilder {
    ttl: u8,
    protocol: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
}

impl Ipv4HeaderBuilder {
    pub fn new(source: Ipv4Address, destination: Ipv4Address, protocol: u8, ttl: u8) -> Self {
        Self {
            ttl,
            protocol,
            source,
            destination,
        }
    }

    pub fn build(&self, payload_len: u16) -> Ipv4Header {
        Ipv4Header::new(
            payload_len,
            self.ttl,
            self.protocol,
            self.source,
            self.destination,
        )
    }
}
