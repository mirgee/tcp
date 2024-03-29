use std::io::Write;

use etherparse::{ip_number::TCP, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun::platform::macos::Device;

use crate::{
    header::{Ipv4HeaderBuilder, TcpHeaderBuilder},
    sequence::{ReceiveSequence, SendSequence},
    validation::{acceptable_ack, is_packet_valid},
};

#[derive(Debug)]
pub enum State {
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
    Closed,
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcvd => false,
            _ => true,
        }
    }
}

#[derive(Debug)]
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
            nxt: iss,
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
        let tcph_builder =
            TcpHeaderBuilder::new(rcv_tcph.destination_port, rcv_tcph.source_port, wnd);
        let rsp_tcph = tcph_builder.create_syn_ack(iss, rcv_seq.nxt, &rcv_iph);

        // Construct IP header
        let iph_builder = Ipv4HeaderBuilder::new(rcv_iph.destination, rcv_iph.source, TCP, 64);
        let rsp_iph = iph_builder.build(rsp_tcph.header_len());

        // Send packet
        let mut conn = Self {
            state: State::SynRcvd,
            snd_seq,
            rcv_seq,
            iph_builder,
            tcph_builder,
        };
        conn.send(dev, rsp_tcph, rsp_iph)?;
        Ok(conn)
    }

    fn send(&mut self, dev: &mut Device, tcph: TcpHeader, iph: Ipv4Header) -> std::io::Result<()> {
        let mut buf = [0u8; 1500];
        let unwritten = {
            let mut bufs = &mut buf[..];
            bufs.write(&[0, 0, 0, 2])?;
            iph.write(&mut bufs).unwrap();
            tcph.write(&mut bufs).unwrap();
            bufs.len()
        };
        // TODO: TCP sequence numbers must be set before sending, should be done at the point of
        // tcph creation
        // self.snd_seq.nxt += payload_len;
        if tcph.syn {
            self.snd_seq.nxt = self.snd_seq.nxt.wrapping_add(1);
        }
        if tcph.fin {
            self.snd_seq.nxt = self.snd_seq.nxt.wrapping_add(1);
        }
        // payload_len += data.len();
        // iph.set_payload_len(payload_len).unwrap();
        dev.write(&buf[..buf.len() - unwritten]).unwrap();
        Ok(())
    }

    fn send_rst(&mut self, dev: &mut Device) -> std::io::Result<()> {
        // TODO: Reset sequence numbers
        let tcph = self.tcph_builder.create_rst();
        let iph = self.iph_builder.build(tcph.header_len());
        self.send(dev, tcph, iph)
    }

    fn send_ack(
        &mut self,
        dev: &mut Device,
        iph: &Ipv4Header,
        tcph: &TcpHeader,
    ) -> std::io::Result<()> {
        let tcph = self
            .tcph_builder
            .create_ack(self.snd_seq.nxt, tcph.sequence_number, iph);
        let iph = self.iph_builder.build(tcph.header_len());
        println!("Sending ACK: {:?}", tcph);
        self.send(dev, tcph, iph)
    }

    fn send_fin(&mut self, dev: &mut Device) -> std::io::Result<()> {
        let tcph = self
            .tcph_builder
            .create_fin(self.snd_seq.nxt, self.rcv_seq.nxt);
        let iph = self.iph_builder.build(tcph.header_len());
        self.send(dev, tcph, iph)
    }

    fn close_connection(&self, dev: &mut Device) -> std::io::Result<()> {
        // TODO: Send FIN, move to FIN_WAIT_1
        todo!()
    }

    /// RFC 793, p. 23
    pub fn on_packet(
        &mut self,
        dev: &mut Device,
        iph: Ipv4Header,
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
            println!("Sending RST");
            self.send_rst(dev)?;
            return Ok(());
        }
        if !is_packet_valid(packet, &self.snd_seq, &self.rcv_seq, &tcph) {
            println!("Invalid packet");
            // TODO: Should send an empty acknowledgment segment containing the current send-sequence number
            // and an acknowledgment indicating the next sequence number expected to be received
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
            State::Established => {
                if tcph.fin() {
                    println!("Received FIN");
                    self.send_ack(dev, &iph, &tcph.to_header())?;
                    // TODO: Before sending FIN, should move to CloseWait and wait for
                    // user to close
                    // self.send_fin(dev)?;
                    self.state = State::CloseWait;
                    return Ok(());
                }
            }
            State::FinWait1 => {
                if !tcph.fin() || !packet.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received non-FIN packet in fin-wait-1 state",
                    ));
                }
                // TODO: If received FIN, send ACK and move to CLOSING
                // TODO: If received ACK of our fin, move to FinWait2
            }
            State::FinWait2 => {
                // TODO: Wait for Fin, send ACK, move to TimeWait and eventually Closed
            }
            State::LastAck => {
                if !tcph.ack() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received non-ACK packet in last-ack state",
                    ));
                }
                println!("Connection closed");
                self.state = State::Closed;
            }
            State::Closing => {
                // TODO: Verify it's our FIN what's being acked
                if !tcph.ack() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Received non-ACK packet in closing state",
                    ));
                }
                println!("Connection closed");
                self.state = State::Closed;
            }
            _ => unimplemented!(),
        };
        Ok(())
    }
}
