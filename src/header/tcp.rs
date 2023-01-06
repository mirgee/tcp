use etherparse::{Ipv4Header, TcpHeader};

pub struct TcpHeaderBuilder {
    source_port: u16,
    destination_port: u16,
    window_size: u16,
}

impl TcpHeaderBuilder {
    pub fn new(source_port: u16, destination_port: u16, window_size: u16) -> Self {
        Self {
            source_port,
            destination_port,
            window_size,
        }
    }

    pub fn create_syn_ack(
        &self,
        sequence_number: u32,
        acknowledgment_number: u32,
        iph: &Ipv4Header,
    ) -> TcpHeader {
        let mut rsp_tcph = TcpHeader::new(
            self.source_port,
            self.destination_port,
            sequence_number,
            self.window_size,
        );
        rsp_tcph.acknowledgment_number = acknowledgment_number;
        rsp_tcph.syn = true;
        rsp_tcph.ack = true;
        rsp_tcph.checksum = rsp_tcph.calc_checksum_ipv4(iph, &[]).unwrap();
        rsp_tcph
    }

    pub fn create_rst(&self) -> TcpHeader {
        let mut rsp_tcph =
            TcpHeader::new(self.destination_port, self.source_port, 0, self.window_size);
        rsp_tcph.rst = true;
        // rsp_tcph.checksum = rsp_tcph.calc_checksum(..);
        rsp_tcph
    }

    pub fn create_ack(&self, sequence_number: u32, acknowledgment_number: u32) -> TcpHeader {
        let mut rsp_tcph = TcpHeader::new(
            self.destination_port,
            self.source_port,
            sequence_number,
            self.window_size,
        );
        rsp_tcph.acknowledgment_number = acknowledgment_number;
        rsp_tcph.ack = true;
        // rsp_tcph.checksum = rsp_tcph.calc_checksum(..);
        rsp_tcph
    }

    pub fn create_fin(&self, sequence_number: u32, acknowledgment_number: u32) -> TcpHeader {
        let mut rsp_tcph = TcpHeader::new(
            self.destination_port,
            self.source_port,
            sequence_number,
            self.window_size,
        );
        rsp_tcph.acknowledgment_number = acknowledgment_number;
        rsp_tcph.fin = true;
        // rsp_tcph.checksum = rsp_tcph.calc_checksum(..);
        rsp_tcph
    }
}
