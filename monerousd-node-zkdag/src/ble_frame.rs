// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! BLE MTU cell framing — fragment a constant-size [`crate::net::CELL_SIZE`] onion cell into
//! BLE-notification-sized fragments and reassemble them, so a 4096-byte cell can cross a BLE GATT link
//! whose per-notification payload is only tens-to-hundreds of bytes. This is the glue between
//! [`crate::transport::BridgeCellTransport`] (which moves WHOLE cells) and the platform CoreBluetooth
//! characteristic (which moves one MTU-sized write/notify at a time).
//!
//! Both endpoints of a 2-device link — the desktop node and the iPhone in-process node — MUST frame
//! IDENTICALLY or neither can reassemble the other's cells, so the framing lives HERE (in the node),
//! shared verbatim by both platforms (the iOS side reaches it through the same Rust core). It carries the
//! SAME metadata-privacy invariant as the cell it wraps: every fragment of every cell (real or cover) is
//! the same shape, so a BLE sniffer sees only uniform fragments at a constant rate — never a size/timing
//! tell.
//!
//! Wire shape of one fragment: `seq(u16 BE) ‖ idx(u8) ‖ total(u8) ‖ payload`. `seq` groups the fragments
//! of ONE cell (so interleaved cells never corrupt each other), `idx`/`total` order + complete it. Nothing
//! here is secret — a fragment reveals only "a fragment went by" — so `seq` is a rolling counter, not an
//! identity. Reassembly is BOUNDED (a small in-flight window, drop-oldest), so a lossy or reordering link
//! can NEVER grow node RAM (no-growth pillar): a cell that never completes is simply re-sent by the
//! constant-rate re-gossip that already backs the cell channel.

use crate::net::CELL_SIZE;
use std::collections::VecDeque;

/// Fixed per-fragment header: `seq(u16 BE) ‖ idx(u8) ‖ total(u8)`.
pub const BLE_FRAG_HEADER: usize = 4;

/// A cell is split across at most 255 fragments (`total` is a `u8`). The smallest MTU that keeps a
/// 4096-byte cell within 255 fragments is `ceil(4096/255) + header = 21` payload bytes — below the
/// default ATT MTU (23 → 20 usable), so callers must negotiate at least a minimal MTU (enforced below).
const MAX_FRAGS: usize = 255;

/// How many partially-received cells the reassembler holds concurrently before evicting the OLDEST.
/// Small + constant ⇒ O(1) RAM regardless of link loss/reordering. 8 in-flight cells covers a full
/// [`crate::net`] slot burst (CELLS_PER_SLOT) with headroom.
pub const DEFAULT_REASM_WINDOW: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum BleFrameError {
    /// The input to [`fragment_cell`] was not exactly [`CELL_SIZE`] bytes.
    NotACell,
    /// The MTU is too small to carry the cell in ≤255 fragments (or ≤ the 4-byte header).
    MtuTooSmall,
    /// A received fragment is malformed (short header, `idx >= total`, inconsistent `total`, or its
    /// reassembled cell would not be [`CELL_SIZE`]).
    BadFragment,
}

/// Split one [`CELL_SIZE`] cell into ordered `mtu`-bounded fragments tagged with `seq`, ready for the
/// platform to write/notify one per GATT operation. `mtu` is the usable ATT payload (negotiated MTU − 3).
pub fn fragment_cell(cell: &[u8], seq: u16, mtu: usize) -> Result<Vec<Vec<u8>>, BleFrameError> {
    if cell.len() != CELL_SIZE {
        return Err(BleFrameError::NotACell);
    }
    let body = match mtu.checked_sub(BLE_FRAG_HEADER) {
        Some(b) if b > 0 => b,
        _ => return Err(BleFrameError::MtuTooSmall),
    };
    let total_usize = cell.len().div_ceil(body);
    if total_usize == 0 || total_usize > MAX_FRAGS {
        return Err(BleFrameError::MtuTooSmall);
    }
    let total = total_usize as u8;
    let mut out = Vec::with_capacity(total_usize);
    for (idx, chunk) in cell.chunks(body).enumerate() {
        let mut frag = Vec::with_capacity(BLE_FRAG_HEADER + chunk.len());
        frag.extend_from_slice(&seq.to_be_bytes());
        frag.push(idx as u8);
        frag.push(total);
        frag.extend_from_slice(chunk);
        out.push(frag);
    }
    Ok(out)
}

/// One cell being reassembled: its `total`, the fragments received so far (by index), and how many.
struct Partial {
    seq: u16,
    total: u8,
    frags: Vec<Option<Vec<u8>>>,
    have: usize,
}

/// Reassembles BLE fragments back into whole [`CELL_SIZE`] cells. Tolerates out-of-order + interleaved
/// fragments (index-placed, seq-separated). BOUNDED to `window` in-flight cells (drop-oldest) so a lossy
/// link is O(1) RAM. A cell is delivered ONLY once every one of its `total` fragments has arrived and its
/// reassembled length is exactly [`CELL_SIZE`] — a fail-closed check, never a truncated/padded cell.
pub struct BleReassembler {
    partial: VecDeque<Partial>,
    window: usize,
}

impl BleReassembler {
    pub fn new(window: usize) -> Self {
        BleReassembler {
            partial: VecDeque::new(),
            window: window.max(1),
        }
    }

    /// Feed one received BLE fragment. Returns `Ok(Some(cell))` when THIS fragment completed a cell,
    /// `Ok(None)` if the cell is still incomplete, or `Err` on a malformed fragment (fail-closed — the
    /// caller drops the peer; a dropped cell is re-gossiped).
    pub fn push(&mut self, frag: &[u8]) -> Result<Option<Vec<u8>>, BleFrameError> {
        if frag.len() <= BLE_FRAG_HEADER {
            return Err(BleFrameError::BadFragment);
        }
        let seq = u16::from_be_bytes([frag[0], frag[1]]);
        let idx = frag[2];
        let total = frag[3];
        if total == 0 || idx >= total {
            return Err(BleFrameError::BadFragment);
        }
        let payload = &frag[BLE_FRAG_HEADER..];

        // Find (or start) the partial for this seq.
        let pos = self.partial.iter().position(|p| p.seq == seq);
        let slot = match pos {
            Some(i) => {
                if self.partial[i].total != total {
                    return Err(BleFrameError::BadFragment); // inconsistent total across a cell's fragments
                }
                i
            }
            None => {
                if self.partial.len() >= self.window {
                    self.partial.pop_front(); // drop-oldest: bounded RAM, the evicted cell re-gossips
                }
                self.partial.push_back(Partial {
                    seq,
                    total,
                    frags: vec![None; total as usize],
                    have: 0,
                });
                self.partial.len() - 1
            }
        };

        {
            let p = &mut self.partial[slot];
            if p.frags[idx as usize].is_none() {
                p.frags[idx as usize] = Some(payload.to_vec());
                p.have += 1;
            }
            if p.have < p.total as usize {
                return Ok(None); // still waiting on fragments
            }
        }

        // Complete — assemble in index order, verify exact CELL_SIZE, and remove the partial.
        let Some(p) = self.partial.remove(slot) else { return Err(BleFrameError::BadFragment) };
        let mut cell = Vec::with_capacity(CELL_SIZE);
        for f in &p.frags {
            cell.extend_from_slice(f.as_ref().ok_or(BleFrameError::BadFragment)?);
        }
        if cell.len() != CELL_SIZE {
            return Err(BleFrameError::BadFragment); // a link that mis-sized fragments never yields a cell
        }
        Ok(Some(cell))
    }

    /// In-flight partial cells (for platform diagnostics / flow control).
    pub fn in_flight(&self) -> usize {
        self.partial.len()
    }
}

/// Ties [`crate::transport::BridgeCellTransport`] (whole cells) to a BLE GATT link (MTU fragments): the
/// ONE loop both the desktop (macOS CoreBluetooth / btleplug) and the iPhone (Swift CoreBluetooth via this
/// same Rust core) run. The node keeps running its generic beacon-adopt [`crate::node_runtime::NodeRuntime`]
/// over the bridge; this pump is the only BLE-aware glue, so the two platforms frame + reassemble
/// IDENTICALLY. Holds a CLONE of the node's bridge handle (shares the Arc queues) plus one reassembler and a
/// rolling fragment `seq`. No BLE library is pulled into the node — the platform supplies the actual
/// send/receive of a fragment; this owns only the framing, ordering, and bounded reassembly.
pub struct BleCellPump {
    link: crate::transport::BridgeCellTransport,
    reasm: BleReassembler,
    seq: u16,
    mtu: usize,
}

impl BleCellPump {
    /// `link` is a clone of the [`crate::transport::BridgeCellTransport`] the node runs on; `mtu` is the
    /// negotiated ATT payload (MTU − 3). The reassembly window defaults to [`DEFAULT_REASM_WINDOW`].
    pub fn new(link: crate::transport::BridgeCellTransport, mtu: usize) -> Self {
        BleCellPump {
            link,
            reasm: BleReassembler::new(DEFAULT_REASM_WINDOW),
            seq: 0,
            mtu,
        }
    }

    /// Drain up to `max_cells` of the node's outbound cells, fragment each to the MTU, and hand every
    /// fragment to `send` (the platform's GATT write/notify). Returns the number of FRAGMENTS emitted. A
    /// cell that cannot be framed at this MTU is dropped (fail-closed) — never sent malformed; it re-gossips.
    pub fn drive_outbound<F: FnMut(Vec<u8>)>(&mut self, max_cells: usize, mut send: F) -> usize {
        let mut emitted = 0;
        for cell in self.link.drain_outbound(max_cells) {
            if let Ok(frags) = fragment_cell(&cell, self.seq, self.mtu) {
                self.seq = self.seq.wrapping_add(1);
                for f in frags {
                    send(f);
                    emitted += 1;
                }
            }
        }
        emitted
    }

    /// Feed one fragment the platform RECEIVED over BLE. On the fragment that completes a cell, the whole
    /// cell is injected into the node's inbound queue. Returns `true` iff a cell completed on this fragment.
    /// A malformed fragment is dropped (fail-closed) and reported so the caller can drop the peer.
    pub fn on_fragment(&mut self, frag: &[u8]) -> Result<bool, BleFrameError> {
        match self.reasm.push(frag)? {
            Some(cell) => {
                // The reassembler already guaranteed `cell.len() == CELL_SIZE`, so inject can only fail on a
                // poisoned link lock — fail-closed (drop the peer), never a silently-lost cell.
                self.link
                    .inject_inbound(cell)
                    .map_err(|_| BleFrameError::BadFragment)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn cell(fill: u8) -> Vec<u8> {
        let mut c = vec![fill; CELL_SIZE];
        // vary a few bytes so a mis-ordered reassembly is detectable, not accidentally equal
        for (i, b) in c.iter_mut().enumerate().take(64) {
            *b = (i as u8) ^ fill;
        }
        c
    }

    #[test]
    fn cell_fragments_and_reassembles_at_every_realistic_mtu_in_and_out_of_order() {
        for mtu in [23usize, 185, 244, 512] {
            let c = cell(0xA5);
            let frags = fragment_cell(&c, 7, mtu).expect("fragmented");
            assert!(
                frags.iter().all(|f| f.len() <= mtu),
                "no fragment exceeds the MTU"
            );
            // in order
            let mut r = BleReassembler::new(DEFAULT_REASM_WINDOW);
            let mut got = None;
            for f in &frags {
                if let Some(cell) = r.push(f).unwrap() {
                    got = Some(cell);
                }
            }
            assert_eq!(
                got.as_deref(),
                Some(c.as_slice()),
                "in-order reassembly is byte-exact @mtu {mtu}"
            );
            // reversed (BLE can reorder notifications) reassembles identically
            let mut r2 = BleReassembler::new(DEFAULT_REASM_WINDOW);
            let mut got2 = None;
            for f in frags.iter().rev() {
                if let Some(cell) = r2.push(f).unwrap() {
                    got2 = Some(cell);
                }
            }
            assert_eq!(
                got2.as_deref(),
                Some(c.as_slice()),
                "out-of-order reassembly is byte-exact @mtu {mtu}"
            );
        }
    }

    #[test]
    fn interleaved_cells_do_not_corrupt_each_other() {
        // Two different cells fragmented under different seqs, their fragments interleaved on the link.
        let (c0, c1) = (cell(0x11), cell(0x22));
        let f0 = fragment_cell(&c0, 100, 185).unwrap();
        let f1 = fragment_cell(&c1, 101, 185).unwrap();
        let mut r = BleReassembler::new(DEFAULT_REASM_WINDOW);
        let (mut g0, mut g1) = (None, None);
        let n = f0.len().max(f1.len());
        for i in 0..n {
            if let Some(f) = f0.get(i) {
                if let Some(cell) = r.push(f).unwrap() {
                    g0 = Some(cell);
                }
            }
            if let Some(f) = f1.get(i) {
                if let Some(cell) = r.push(f).unwrap() {
                    g1 = Some(cell);
                }
            }
        }
        assert_eq!(
            g0.as_deref(),
            Some(c0.as_slice()),
            "seq 100 reassembles to cell 0"
        );
        assert_eq!(
            g1.as_deref(),
            Some(c1.as_slice()),
            "seq 101 reassembles to cell 1 — no cross-corruption"
        );
    }

    #[test]
    fn reassembly_window_is_bounded_no_growth_under_loss() {
        // Feed the FIRST fragment of many distinct cells (each never completes). The in-flight buffer must
        // stay ≤ window (drop-oldest), never growing with the number of lossy cells seen.
        let mut r = BleReassembler::new(4);
        let c = cell(0x33);
        for seq in 0..1000u16 {
            let frags = fragment_cell(&c, seq, 185).unwrap();
            let _ = r.push(&frags[0]).unwrap(); // only fragment 0 — cell can never complete
            assert!(
                r.in_flight() <= 4,
                "in-flight partials bounded by window, got {}",
                r.in_flight()
            );
        }
    }

    #[test]
    fn malformed_fragments_and_bad_inputs_fail_closed() {
        // non-cell input to fragment_cell
        assert_eq!(
            fragment_cell(&[0u8; 10], 0, 185),
            Err(BleFrameError::NotACell)
        );
        // MTU ≤ header
        assert_eq!(
            fragment_cell(&vec![0u8; CELL_SIZE], 0, BLE_FRAG_HEADER),
            Err(BleFrameError::MtuTooSmall)
        );
        let mut r = BleReassembler::new(DEFAULT_REASM_WINDOW);
        // header-only fragment (no payload)
        assert_eq!(r.push(&[0, 0, 0, 1]), Err(BleFrameError::BadFragment));
        // idx >= total
        assert_eq!(r.push(&[0, 0, 5, 2, 0xFF]), Err(BleFrameError::BadFragment));
        // total == 0
        assert_eq!(r.push(&[0, 0, 0, 0, 0xFF]), Err(BleFrameError::BadFragment));
    }

    #[test]
    fn ble_pump_ferries_whole_cells_between_two_node_transports_over_a_simulated_fragment_link() {
        // SCOPE: this proves the node-side SOFTWARE path only — bridge transport ↔ fragmentation ↔
        // reassembly — over a MOCK in-memory fragment link. It is NOT a proof over a physical BLE radio;
        // the real 2-device (desktop ↔ iPhone) converge still requires running it on the hardware.
        use crate::transport::{BridgeCellTransport, CellTransport};
        let ta = BridgeCellTransport::new(1024);
        let tb = BridgeCellTransport::new(1024);
        let mut pa = BleCellPump::new(ta.clone(), 185); // device A's pump @ a negotiated MTU
        let mut pb = BleCellPump::new(tb.clone(), 185); // device B's pump

        // Device A's node queues two outbound cells (as its CellChannel would).
        let (c0, c1) = (cell(0xC0), cell(0xC1));
        ta.send_cell(c0.clone()).unwrap();
        ta.send_cell(c1.clone()).unwrap();

        // A's pump fragments them; a MOCK link hands each fragment to B's pump, which reassembles + injects
        // whole cells into B's node inbound. Distinct seqs keep the two cells' fragments from cross-corrupting.
        let mut wire: Vec<Vec<u8>> = Vec::new();
        let sent = pa.drive_outbound(64, |frag| wire.push(frag));
        assert!(
            sent >= 2 * (CELL_SIZE / 182),
            "both cells fragmented onto the link"
        );
        let mut completed = 0;
        for frag in &wire {
            if pb.on_fragment(frag).unwrap() {
                completed += 1;
            }
        }
        assert_eq!(
            completed, 2,
            "both cells reassembled + injected into B over the simulated fragments"
        );

        // B's node inbound now holds BOTH whole cells, byte-exact (over the SIMULATED link).
        let got0 = tb.recv_cell().expect("first cell delivered");
        let got1 = tb.recv_cell().expect("second cell delivered");
        assert!(tb.recv_cell().is_none(), "exactly two cells delivered");
        let mut got = [got0, got1];
        got.sort();
        let mut want = [c0, c1];
        want.sort();
        assert_eq!(
            got, want,
            "B received exactly A's two cells intact across the simulated fragment link"
        );
    }
}
