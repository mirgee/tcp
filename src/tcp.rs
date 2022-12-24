use std::io::Write;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, Ipv4Header};
use tun::platform::macos::Device;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Established
}

/// Send Sequence Space (RFC 793, p. 20)
/// 
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
/// 
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
struct SendSequence {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: u32,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32
}

/// Receive Sequence Space (RFC 793, p. 20)
/// 
///     1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
struct ReceiveSequence {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: u32,
    /// initial receive sequence number
    irs: u32
}

pub struct Connection {
    state: State,
    // snd_seq: SendSequence,
    // rcv_seq: ReceiveSequence
}

impl Connection {
    pub fn new() -> Self {
        Self {
            state: State::Closed
        }
    }

    /// RFC 793, p. 23
    pub fn on_packet(&mut self, dev: &mut Device, iph: Ipv4HeaderSlice, tcph: TcpHeaderSlice, packet: &[u8]) -> std::io::Result<()> {
        match self.state {
            State::Closed => {
                println!("Received packet in closed state");
                return Ok(());
            },
            State::Listen => {
                // React only to SYN packets
                if !tcph.syn() {
                    println!("Received non-SYN packet in listen state");
                    return Ok(());
                }

                let mut syn_ack = etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), 0, 0);
                syn_ack.syn = true;
                syn_ack.ack = true;
                let iph = Ipv4Header::new(syn_ack.header_len(), iph.ttl(), iph.protocol(), iph.destination(), iph.source());

                // Construct pattern and send
                let mut buf = [0u8; 1500];
                let written = {
                    let mut bufs = &mut buf[..];
                    iph.write(&mut bufs).unwrap();
                    syn_ack.write(&mut bufs).unwrap();
                    bufs.len()
                };
                dev.write(&buf[..written]).unwrap();
            },
            State::SynRcvd => { println!("Received packet in synrcvd state"); },
            State::Established => { println!("Received packet in established state"); }

        };
        
        let src = iph.source_addr();
        let dst = iph.destination_addr();
        let sport = tcph.source_port();
        let dport = tcph.destination_port();
        let seq = tcph.sequence_number();
        let ack = tcph.acknowledgment_number();
        let win = tcph.window_size();
        // let data = 4 + ip.slice().len() + tcph.slice().len()..4 + ip.slice().len() + len;
        println!("{}:{} -> {}:{} seq={} ack={} win={} data_len={:?}", src, sport, dst, dport, seq, ack, win, packet.len());
        Ok(())
    }
}
