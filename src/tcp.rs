use std::io::Write;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, Ipv4Header, ip_number::TCP};
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
    /// oldest unacknowledged sequence number
    una: u32,
    /// next sequence number to be sent
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
    /// next sequence number expected on an incoming segments, and
    /// is the left or lower edge of the receive window
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: u16,
    /// initial receive sequence number
    irs: u32
}

pub struct Connection {
    state: State,
    snd_seq: SendSequence,
    rcv_seq: ReceiveSequence
}

impl Connection {
    pub fn accept(dev: &mut Device, iph: Ipv4HeaderSlice, tcph: TcpHeaderSlice) -> std::io::Result<Self> {
        if !tcph.syn() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received non-SYN packet in listen state"));
        }

        let iss = 0;
        let wnd = 1024;
        // Keep track of sender info
        let rcv_seq = ReceiveSequence {
            nxt: tcph.sequence_number() + 1,
            wnd: tcph.window_size(),
            up: 0,
            irs: tcph.sequence_number()
        };
        // Just out of curiosity
        let rcv_ackn = tcph.acknowledgment_number(); // This is relevant only if ACK is set
        println!("Received ackn: {}", rcv_ackn);
        
        // Keep track of what we're sending
        let snd_seq = SendSequence {
            una: iss,
            nxt: iss + 1,
            wnd,
            up: 0,
            wl1: 0,
            wl2: 0,
            iss
        };

        let mut syn_ack = etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), 0, wnd);
        syn_ack.acknowledgment_number = rcv_seq.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        syn_ack.checksum = syn_ack.calc_checksum_ipv4(&iph.to_header(), &[]).unwrap();
        let iph = Ipv4Header::new(syn_ack.header_len(), 64, TCP, iph.destination(), iph.source());

        // Construct pattern and send
        let mut buf = [0u8; 1500];
        let unwritten = {
            let mut bufs = &mut buf[..];
            bufs.write(&[0, 0, 0, 2])?;
            iph.write(&mut bufs).unwrap();
            syn_ack.write(&mut bufs).unwrap();
            bufs.len()
        };
        dev.write(&buf[..buf.len() - unwritten]).unwrap();
        Ok(Self {
            state: State::SynRcvd,
            snd_seq,
            rcv_seq
        })
    }

    /// RFC 793, p. 23
    pub fn on_packet(&mut self, iph: Ipv4HeaderSlice, tcph: TcpHeaderSlice, packet: &[u8]) -> std::io::Result<()> {
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
