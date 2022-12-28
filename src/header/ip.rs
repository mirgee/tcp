type Ipv4Address = [u8; 4];

pub struct Ipv4HeaderBuilder {
    header_len: u16,
    ttl: u8,
    protocol: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
}
