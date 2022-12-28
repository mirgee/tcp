use std::io::Write;

use etherparse::{ip_number::TCP, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun::platform::macos::Device;

use crate::{
    sequence::{ReceiveSequence, SendSequence},
    validation::{acceptable_ack, is_packet_valid},
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
    iph: Ipv4Header, // Not great, we have to change the payload len every time
    tcph: TcpHeader,
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
        let mut rsp_tcph =
            etherparse::TcpHeader::new(rcv_tcph.destination_port, rcv_tcph.source_port, 0, wnd);
        rsp_tcph.acknowledgment_number = rcv_seq.nxt;
        rsp_tcph.syn = true;
        rsp_tcph.ack = true;
        rsp_tcph.checksum = rsp_tcph.calc_checksum_ipv4(&rcv_iph, &[]).unwrap(); // TODO: Is this
                                                                                 // necessary?

        // Construct IP header
        let rsp_iph = Ipv4Header::new(
            rsp_tcph.header_len(),
            64,
            TCP,
            rcv_iph.destination,
            rcv_iph.source,
        );

        // Send packet
        Self::send(dev, rsp_tcph.clone(), rsp_iph.clone(), &[])?;
        Ok(Self {
            state: State::SynRcvd,
            snd_seq,
            rcv_seq,
            iph: rsp_iph,
            tcph: rsp_tcph,
        })
    }

    fn send(
        dev: &mut Device,
        tcph: TcpHeader,
        iph: Ipv4Header,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 1500];
        // TODO: TCP sequence numbers must be set before sending, should be done at the point of
        // tcph creation
        // tcph.sequence_number = self.snd_seq.nxt;
        // tcph.acknowledgment_number = self.rcv_seq.nxt;
        let unwritten = {
            let mut bufs = &mut buf[..];
            bufs.write(&[0, 0, 0, 2])?;
            iph.write(&mut bufs).unwrap();
            tcph.write(&mut bufs).unwrap();
            bufs.write(data).unwrap();
            bufs.len()
        };
        dev.write(&buf[..buf.len() - unwritten]).unwrap();
        Ok(())
    }

    fn send_rst(&mut self, dev: &mut Device) -> std::io::Result<()> {
        self.tcph.rst = true;
        self.tcph.sequence_number = 0;
        self.tcph.acknowledgment_number = 0;
        self.iph
            .set_payload_len(self.tcph.header_len().into())
            .unwrap();
        Self::send(dev, self.tcph.clone(), self.iph.clone(), &[])
    }

    /// RFC 793, p. 23
    pub fn on_packet(
        &mut self,
        dev: &mut Device,
        iph: Ipv4HeaderSlice,
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
                self.state = {
                    println!("Connection established");
                    State::Established
                }
            }
            _ => {}
        };
        Ok(())
    }
}
