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
#[derive(Debug)]
pub struct SendSequence {
    /// oldest unacknowledged sequence number
    pub una: u32,
    /// next sequence number to be sent
    pub nxt: u32,
    /// send window
    pub wnd: u16,
    /// send urgent pointer
    pub up: u32,
    /// segment sequence number used for last window update
    pub wl1: u32,
    /// segment acknowledgment number used for last window update
    pub wl2: u32,
    /// initial send sequence number
    pub iss: u32,
}
