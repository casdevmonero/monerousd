// Copyright (c) 2026, The MoneroUSD Protocol
//
// fixed.rs — the ONE crash-free path from a byte slice to a fixed-width array.
//
// Every fixed-width read in the node (`u64::from_le_bytes(b[i..i + 8] …)`, a 32-byte commitment cut from a note, a
// 4-byte cell out of `chunks_exact(4)`) used `.try_into().unwrap()` / `.expect(..)`: a panic site in shippable code
// (hole scanner, BLIND "panic in shippable code"). At each of those sites the slice already has exactly N bytes — the
// range `[a..a + N]`, a `chunks_exact(N)` chunk or a length checked just above bounds it — so the conversion can never
// fail there, and `fixed()` returns the identical array. It copies `min(len, N)` bytes into a zeroed `[u8; N]`, so a
// slice that is NOT N bytes (a future caller's slip) yields a zero-padded / truncated array instead of aborting the
// process. A caller decoding OUTSIDE bytes still checks the length itself and refuses a short input; `fixed()` is the
// width conversion, never the length gate.

/// Converts a byte slice into a fixed-width array without a panic path (see the module doc).
pub trait FixedBytes {
    /// The first `N` bytes as an array; a shorter slice is zero-padded, a longer one truncated.
    fn fixed<const N: usize>(&self) -> [u8; N];
}

impl FixedBytes for [u8] {
    #[inline]
    fn fixed<const N: usize>(&self) -> [u8; N] {
        let mut out = [0u8; N];
        let n = self.len().min(N);
        out[..n].copy_from_slice(&self[..n]);
        out
    }
}

/// The ONE crash-free encode of a plain chain object (a struct of integers, arrays and byte vectors). `postcard`'s
/// `to_allocvec` cannot fail on such a type (no fixed buffer, no unknown-length sequence), so every site used
/// `.expect(..)`: a panic path in shippable code. Here a failure — unreachable by construction — yields an EMPTY
/// body, which every decoder refuses (fail closed on the item, never the process), and is named on stderr once.
pub fn encode_plain<T: serde::Serialize + ?Sized>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).unwrap_or_else(|e| {
        eprintln!("encode_plain: a plain chain object failed to serialize ({e}); an empty body is handed out and refused");
        Vec::new()
    })
}

/// The ONE crash-free join of a worker thread. A worker that panicked has no result, so `fallback` supplies the value
/// the caller fails closed on — the lane's work run inline (the same deterministic computation), an empty lane, or the
/// refusal its class already handles — and the lane is named on stderr once. The process never aborts on a worker's
/// defect; a genuine panic in the work itself recurs at its own site when the fallback recomputes it inline.
pub fn join_or_else<T>(h: std::thread::ScopedJoinHandle<'_, T>, what: &str, fallback: impl FnOnce() -> T) -> T {
    h.join().unwrap_or_else(|_| {
        eprintln!("join_or_else: the {what} worker panicked; its result is replaced by the fail-closed value");
        fallback()
    })
}

#[cfg(test)]
mod tests {
    use super::FixedBytes;

    #[test]
    fn fixed_equals_try_into_on_an_exact_slice_and_never_panics_on_a_wrong_width() {
        let b: Vec<u8> = (0u8..40).collect();
        // exact width: byte-for-byte what `try_into().unwrap()` returned at every rewritten site
        let want: [u8; 8] = b[3..11].try_into().unwrap();
        assert_eq!(b[3..11].fixed::<8>(), want);
        assert_eq!(u64::from_le_bytes(b[0..8].fixed()), u64::from_le_bytes(b[0..8].try_into().unwrap()));
        let c32: [u8; 32] = b[..32].try_into().unwrap();
        assert_eq!(b[..32].fixed::<32>(), c32);
        for c in b.chunks_exact(4) {
            assert_eq!(u32::from_le_bytes(c.fixed()), u32::from_le_bytes(c.try_into().unwrap()));
        }
        // wrong width: no panic; short is zero-padded, long is truncated (the planted defect `try_into` would abort on)
        assert_eq!(b[..3].fixed::<8>(), [0, 1, 2, 0, 0, 0, 0, 0]);
        assert_eq!(b[..12].fixed::<4>(), [0, 1, 2, 3]);
        assert_eq!([0u8; 0][..].fixed::<4>(), [0u8; 4]);
        assert!(std::panic::catch_unwind(|| {
            let r: Result<[u8; 8], _> = b[..3].try_into();
            r.unwrap()
        })
        .is_err());
    }
    #[test]
    fn join_or_else_returns_the_workers_value_and_the_fallback_when_it_panicked() {
        let (fine, broken) = std::thread::scope(|s| {
            let fine = s.spawn(|| 7u32);
            let broken = s.spawn(|| -> u32 {
                if std::hint::black_box(true) {
                    panic!("planted worker defect");
                }
                1
            });
            (super::join_or_else(fine, "fine", || 0), super::join_or_else(broken, "broken", || 99))
        });
        assert_eq!(fine, 7);
        assert_eq!(broken, 99, "a panicked worker yields the fail-closed value, never an abort");
    }
    #[test]
    fn encode_plain_round_trips_a_plain_struct_through_postcard() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Plain {
            a: u64,
            b: [u8; 4],
            c: Vec<u8>,
        }
        let v = Plain { a: 7, b: [1, 2, 3, 4], c: vec![9; 33] };
        let bytes = super::encode_plain(&v);
        assert_eq!(bytes, postcard::to_allocvec(&v).unwrap());
        assert_eq!(postcard::from_bytes::<Plain>(&bytes).unwrap(), v);
    }
}
