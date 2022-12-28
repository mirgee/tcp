use etherparse::TcpHeader;

pub struct TcpHeaderBuilder {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    window_size: u16,
}

impl TcpHeaderBuilder {
    pub fn new(
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        window_size: u16,
    ) -> Self {
        Self {
            source_port,
            destination_port,
            sequence_number,
            window_size,
        }
    }

    pub fn create_syn_ack(&self) -> TcpHeader {
        let mut rsp_tcph = TcpHeader::new(
            self.destination_port,
            self.source_port,
            self.sequence_number,
            self.window_size,
        );
        rsp_tcph.acknowledgment_number = self.sequence_number + 1;
        rsp_tcph.syn = true;
        rsp_tcph.ack = true;
        // rsp_tcph.checksum = rsp_tcph.calc_checksum(..);
        rsp_tcph
    }

    pub fn create_rst(&self) -> TcpHeader {
        let mut rsp_tcph = TcpHeader::new(
            self.destination_port,
            self.source_port,
            self.sequence_number,
            self.window_size,
        );
        rsp_tcph.rst = true;
        // rsp_tcph.checksum = rsp_tcph.calc_checksum(..);
        rsp_tcph
    }
}
