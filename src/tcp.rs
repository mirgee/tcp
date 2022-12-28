use std::io::Write;

use etherparse::{ip_number::TCP, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun::platform::macos::Device;

use crate::{
    sequence::{ReceiveSequence, SendSequence},
    validation::{acceptable_ack, is_packet_valid}, header::{TcpHeaderBuilder, Ipv4HeaderBuilder},
};

pub enum State {
    SynRcvd,
    Established,
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcvd => false,
            State::Established => true,
        }
    }
}

pub struct Connection {
    state: State,
    snd_seq: SendSequence,
    rcv_seq: ReceiveSequence,
    tcph_builder: TcpHeaderBuilder,
    iph_builder: Ipv4HeaderBuilder,
}

impl Connection {
    pub fn create(
        dev: &mut Device,
        rcv_iph: Ipv4Header,
        rcv_tcph: TcpHeader,
    ) -> std::io::Result<Self> {
        if !rcv_tcph.syn {
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
            nxt: rcv_tcph.sequence_number + 1,
            wnd: rcv_tcph.window_size,
            up: 0,
            irs: rcv_tcph.sequence_number,
        };

        // Construct TCP header
        let tcph_builder = TcpHeaderBuilder::new(rcv_tcph.destination_port, rcv_tcph.source_port, wnd);
        let rsp_tcph = tcph_builder.create_syn_ack(iss, rcv_seq.nxt, &rcv_iph);

        // Construct IP header
        let iph_builder = Ipv4HeaderBuilder::new(rcv_iph.destination, rcv_iph.source, TCP, 64);
        let rsp_iph = iph_builder.build(rsp_tcph.header_len());

        // Send packet
        Self::send(dev, rsp_tcph, rsp_iph)?;
        Ok(Self {
            state: State::SynRcvd,
            snd_seq,
            rcv_seq,
            iph_builder,
            tcph_builder,
        })
    }

    fn send(
        dev: &mut Device,
        tcph: TcpHeader,
        iph: Ipv4Header,
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 1500];
        let unwritten = {
            let mut bufs = &mut buf[..];
            bufs.write(&[0, 0, 0, 2])?;
            iph.write(&mut bufs).unwrap();
            tcph.write(&mut bufs).unwrap();
            bufs.len()
        };
        dev.write(&buf[..buf.len() - unwritten]).unwrap();
        Ok(())
    }

    fn send_rst(&self, dev: &mut Device) -> std::io::Result<()> {
        // TODO: Reset sequence numbers
        let tcph = self.tcph_builder.create_rst();
        let iph = self.iph_builder.build(tcph.header_len());
        Self::send(dev, tcph, iph)
    }

    /// RFC 793, p. 23
    pub fn on_packet(
        &mut self,
        dev: &mut Device,
        tcph: TcpHeaderSlice,
        packet: &[u8],
    ) -> std::io::Result<()> {
        if !self.state.is_synchronized()
            && !acceptable_ack(
                self.snd_seq.una,
                tcph.acknowledgment_number(),
                self.snd_seq.nxt,
            )
        {
            self.send_rst(dev)?;
            return Ok(());
        }
        if !is_packet_valid(packet, &self.snd_seq, &self.rcv_seq, &tcph) {
            println!("Invalid packet");
            return Ok(());
        };
        match self.state {
            State::SynRcvd => {
                if !tcph.ack() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received non-ACK packet in syn-rcvd state",
                    ));
                }
                println!("Connection established");
                self.state = State::Established;
            }
            _ => {}
        };
        Ok(())
    }
}
