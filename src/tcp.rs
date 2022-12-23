use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

pub struct State {
    // ...
}

impl State {
    /// Create a new TCP state machine.
    pub fn new() -> Self {
        State {}
    }

    pub fn on_packet(&mut self, iph: Ipv4HeaderSlice, tcph: TcpHeaderSlice, packet: &[u8]) {
        let src = iph.source_addr();
        let dst = iph.destination_addr();
        let sport = tcph.source_port();
        let dport = tcph.destination_port();
        let seq = tcph.sequence_number();
        let ack = tcph.acknowledgment_number();
        let win = tcph.window_size();
        // let data = 4 + ip.slice().len() + tcph.slice().len()..4 + ip.slice().len() + len;
        println!("{}:{} -> {}:{} seq={} ack={} win={} data_len={:?}", src, sport, dst, dport, seq, ack, win, packet.len());
    }
}
