/// Receive Sequence Space (RFC 793, p. 20)
///
/// ```
///     1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
/// ```
pub struct ReceiveSequence {
    /// next sequence number expected on an incoming segments, and
    /// is the left or lower edge of the receive window
    pub nxt: u32,
    /// receive window
    pub wnd: u16,
    /// receive urgent pointer
    pub up: u16,
    /// initial receive sequence number
    pub irs: u32,
}
