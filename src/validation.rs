use etherparse::TcpHeaderSlice;

use crate::sequence::{ReceiveSequence, SendSequence};

pub fn is_included_in_wrapped_boundary_end_incl(start: u32, x: u32, end: u32) -> bool {
    if start < end {
        start < x && x <= end
    } else {
        start < x || x <= end
    }
}

pub fn is_included_in_wrapped_boundary_start_incl(start: u32, x: u32, end: u32) -> bool {
    let res = if start < end {
        start <= x && x < end
    } else {
        start <= x || x < end
    };
    println!("{} <= {} < {} = {}", start, x, end, res);
    res
}

// SEG.SEQ = RCV.NXT
pub fn check_zero_len_packet_zero_wnd(seg_seq: u32, rcv_nxt: u32) -> bool {
    seg_seq == rcv_nxt
}

// RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
pub fn check_zero_len_packet_nonzero_wnd(seg_seq: u32, rcv_nxt: u32, rcv_wnd: u32) -> bool {
    is_included_in_wrapped_boundary_start_incl(rcv_nxt, seg_seq, rcv_nxt.wrapping_add(rcv_wnd))
}

// RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
// or
// RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
pub fn check_both_ends_inside_window(
    seg_seq: u32,
    seg_len: u32,
    rcv_nxt: u32,
    rcv_wnd: u32,
) -> bool {
    let res =
        is_included_in_wrapped_boundary_start_incl(rcv_nxt, seg_seq, rcv_nxt.wrapping_add(rcv_wnd))
            || is_included_in_wrapped_boundary_start_incl(
                rcv_nxt,
                seg_seq.wrapping_add(seg_len).wrapping_sub(1),
                rcv_nxt + rcv_wnd,
            );
    // println!("check_both_ends_inside_window: {}", res);
    res
}

// SND.UNA < SEG.ACK =< SND.NXT
pub fn acceptable_ack(snd_una: u32, seg_ackn: u32, snd_nxt: u32) -> bool {
    let res = is_included_in_wrapped_boundary_end_incl(snd_una, seg_ackn, snd_nxt);
    //     println!(
    //         "acceptable_ack: {} < {} =< {} = {}",
    //         snd_una, seg_ackn, snd_nxt, res
    //     );
    res
}

pub fn is_packet_valid(
    packet: &[u8],
    snd_seq: &SendSequence,
    rcv_seq: &ReceiveSequence,
    tcph: &TcpHeaderSlice,
) -> bool {
    let snd_una = snd_seq.una;
    let snd_nxt = snd_seq.nxt;

    let rcv_nxt = rcv_seq.nxt;
    let rcv_wnd = rcv_seq.wnd as u32;

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

    match (seg_len, rcv_wnd) {
        (0, 0) => check_zero_len_packet_zero_wnd(seg_seq, rcv_nxt),
        (0, y) if y > 0 => check_zero_len_packet_nonzero_wnd(seg_seq, rcv_nxt, rcv_wnd),
        (x, 0) if x > 0 => false,
        (x, y) if x > 0 && y > 0 => {
            acceptable_ack(snd_una, seg_ackn, snd_nxt)
                && check_both_ends_inside_window(seg_seq, seg_len, rcv_nxt, rcv_wnd)
        }
        _ => unreachable!(),
    }
}
