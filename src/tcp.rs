use std::io::Write;

use etherparse::{ip_number::TCP, Ipv4Header, Ipv4HeaderSlice, TcpHeaderSlice};
use tun::platform::macos::Device;

pub enum State {
    SynRcvd,
    Established,
}

/// Send Sequence Space (RFC 793, p. 20)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
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
    iss: u32,
}

/// Receive Sequence Space (RFC 793, p. 20)
///
/// ```
///     1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
/// ```
struct ReceiveSequence {
    /// next sequence number expected on an incoming segments, and
    /// is the left or lower edge of the receive window
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: u16,
    /// initial receive sequence number
    irs: u32,
}

pub struct Connection {
    state: State,
    snd_seq: SendSequence,
    rcv_seq: ReceiveSequence,
    iph: Ipv4Header, // Not great, we have to change the payload len every time
}

impl Connection {
    pub fn accept(
        dev: &mut Device,
        iph: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
    ) -> std::io::Result<Self> {
        if !tcph.syn() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Received non-SYN packet in listen state",
            ));
        }

        let iss = 0;
        let wnd = 1024;

        // Keep track of what we're sending
        let snd_seq = SendSequence {
            una: iss,
            nxt: iss + 1,
            wnd,
            up: 0,
            wl1: 0,
            wl2: 0,
            iss,
        };

        // Keep track of sender info
        let rcv_seq = ReceiveSequence {
            nxt: tcph.sequence_number() + 1,
            wnd: tcph.window_size(),
            up: 0,
            irs: tcph.sequence_number(),
        };

        // Construct TCP header
        let mut syn_ack =
            etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), 0, wnd);
        syn_ack.acknowledgment_number = rcv_seq.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        syn_ack.checksum = syn_ack.calc_checksum_ipv4(&iph.to_header(), &[]).unwrap();

        // Construct IP header
        let iph = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            TCP,
            iph.destination(),
            iph.source(),
        );

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
            rcv_seq,
            iph,
        })
    }

    pub fn is_included_in_wrapped_boundary(start: u32, x: u32, end: u32) -> bool {
        if start < end {
            start <= x && x < end
        } else {
            start <= x || x < end
        }
    }

    pub fn check_packet(&self, packet: &[i8], tcph: TcpHeaderSlice) -> bool {
        let snd_una = self.snd_seq.una;
        let snd_nxt = self.snd_seq.nxt;

        let rcv_nxt = self.rcv_seq.nxt;
        let rcv_wnd = self.rcv_seq.wnd as u32;

        let seg_ackn = tcph.acknowledgment_number();
        let seg_seq = tcph.sequence_number();
        let seg_len = {
            let mut plen = packet.len() as u32;
            if tcph.syn() {
                plen += 1;
            }
            if tcph.fin() {
                plen += 1;
            }
            plen
        };

        // SEG.SEQ = RCV.NXT
        let check_zero_len_packet_zero_wnd = || -> bool { seg_seq == rcv_nxt };

        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        let check_zero_len_packet_nonzero_wnd = || -> bool {
            Self::is_included_in_wrapped_boundary(rcv_nxt, seg_seq, rcv_nxt + rcv_wnd)
        };

        // SND.UNA < SEG.ACK =< SND.NXT
        let acceptable_ack =
            || -> bool { Self::is_included_in_wrapped_boundary(snd_una, seg_ackn, snd_nxt) };

        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let check_both_ends_inside_window = || -> bool {
            Self::is_included_in_wrapped_boundary(rcv_nxt, seg_seq, rcv_nxt + rcv_wnd)
                || Self::is_included_in_wrapped_boundary(
                    rcv_nxt,
                    seg_seq + seg_len - 1,
                    rcv_nxt + rcv_wnd,
                )
        };

        match (packet.len(), self.rcv_seq.wnd) {
            (0, 0) => check_zero_len_packet_zero_wnd(),
            (0, y) if y > 0 => check_zero_len_packet_nonzero_wnd(),
            (x, 0) if x > 0 => false,
            (x, y) if x > 0 && y > 0 => acceptable_ack() && check_both_ends_inside_window(),
        }
    }

    /// RFC 793, p. 23
    pub fn on_packet(
        &mut self,
        iph: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
        packet: &[u8],
    ) -> std::io::Result<()> {
        match self.state {
            State::SynRcvd => {
                if !tcph.ack() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received non-ACK packet in syn-rcvd state",
                    ));
                }
                if ackn != self.snd_seq.nxt {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received ACK packet with wrong ack number",
                    ));
                }
                self.state = State::Established;
            }
            _ => {}
        };
        Ok(())
    }
}
