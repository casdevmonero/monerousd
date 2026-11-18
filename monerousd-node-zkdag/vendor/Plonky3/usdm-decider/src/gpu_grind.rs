//! ⭐ SPEED G1 (lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8) — THE PROOF-OF-WORK GRIND ON THE GPU.
//!
//! MEASURED why: a 40 s stack sample of a real node proving blocks (main ffd3e074, `prof-base`) spent 14.5 % of the
//! prover's working CPU grinding, every grind a serial point of its proof. The same Poseidon2-16 permutation over
//! KoalaBear runs at 122 M/s on the M1 Pro's 16 GPU cores (session bench `p2bench.swift`, bit-for-bit equal to a CPU
//! copy) against 5.68 M/s on one NEON core (`light_commit::tests::prove_cost_poseidon2_against_blake3_on_this_machine`).
//!
//! What it is: [`install`] registers the production challenger permutations (the two seeds the provers use,
//! `REC_DECIDER_SEED` and `COMMITTED_AIR_SEED`, with constants from the ONE derivation the circuits use,
//! [`crate::sponge_chain_air::raw_constants_for_seed`]) and installs [`accel`] as the duplex challenger's grind
//! accelerator (`p3_challenger::set_grind_accel`). A grind then scans candidates on the GPU in increasing chunks and
//! returns the SMALLEST hit, which is the witness the CPU search returns, so proofs are byte-for-byte what they were.
//! The challenger accepts the answer only after its own `check_witness`.
//!
//! SAFE-FALLBACK: when the GPU declines (an unknown permutation, a grind under [`GPU_MIN_BITS`], no GPU, a failed
//! dispatch) the challenger runs its own CPU search — the very search this accelerator mirrors, followed by the same
//! `check_witness` — so the alternate path checks exactly as much as the primary and costs only time.
//!
//! Protects it (AGENTS §2 AI RESISTANT): (b) ordinary code — the GPU only proposes a witness; the proof's soundness is
//! the unchanged native check every prover and verifier makes. A lying GPU can at worst cost the CPU search's time.
//! Privacy: a grind's inputs are the public Fiat–Shamir transcript (it is in the proof); no witness or secret reaches
//! the GPU.
//! Scale: constant — nothing grows with nodes, items or height; one fingerprint permutation per grind on the CPU.
//! No tier of node: a node without a GPU (or with `MONEROUSD_GPU=0`) makes the same proofs on the CPU.
//! cons: a node binary links Metal on Apple targets; about one permutation of CPU per grind for the fingerprint.

use std::sync::OnceLock;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

use crate::hiding_decider::{Fa4, Perm16};

/// The KoalaBear prime.
const P: u32 = 0x7f00_0001;
/// Below this many bits a grind is a few thousand candidates: the CPU's NEON search finishes before a GPU dispatch
/// returns. Read against the per-depth timings `the_gpu_grind_returns_the_cpu_witness` prints.
pub const GPU_MIN_BITS: usize = 12;

const fn mu() -> u32 {
    // P^-1 mod 2^32 by Newton iteration.
    let mut inv: u32 = 1;
    let mut i = 0;
    while i < 5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(P.wrapping_mul(inv)));
        i += 1;
    }
    inv
}
const MU: u32 = mu();
/// R^2 mod P with R = 2^32: the Montgomery form of R, so `mm(x, R2) = x · R`.
const R2: u32 = ((1u128 << 64) % (P as u128)) as u32;

fn to_mont(x: u32) -> u32 {
    (((x as u64) << 32) % P as u64) as u32
}
fn from_mont(y: u32) -> u32 {
    let x = y as u64;
    let t = (x as u32).wrapping_mul(MU);
    let u = t as u64 * P as u64;
    let (hi, uh) = ((x >> 32) as u32, (u >> 32) as u32);
    if hi >= uh { hi - uh } else { hi.wrapping_sub(uh).wrapping_add(P) }
}

/// The kernels. Montgomery arithmetic in 32-bit words; the permutation is Plonky3's `Poseidon2KoalaBear<16>` step for
/// step: the light external layer (M4 blocks then the column sums), 4 initial full rounds, 20 partial rounds with the
/// internal layer `(1 + Diag(V))`, 4 terminal full rounds, S-box x^3. Constants come in a buffer (164 words).
fn kernel_source() -> String {
    format!(
        r#"
#include <metal_stdlib>
using namespace metal;
constant uint P = {P}u;
constant uint MU = {MU}u;
constant uint R2 = {R2}u;
inline uint mm(uint a, uint b) {{ ulong x = (ulong)a * b; uint t = (uint)x * MU; ulong u = (ulong)t * P;
  uint hi = (uint)(x >> 32), uh = (uint)(u >> 32); return hi >= uh ? hi - uh : hi - uh + P; }}
inline uint ad(uint a, uint b) {{ uint s = a + b; return s >= P ? s - P : s; }}
inline uint sb(uint a, uint b) {{ return a >= b ? a - b : a + P - b; }}
inline uint cube(uint x) {{ return mm(mm(x, x), x); }}
inline void m4(thread uint* x) {{
  uint t01 = ad(x[0], x[1]), t23 = ad(x[2], x[3]), t0123 = ad(t01, t23), t01123 = ad(t0123, x[1]), t01233 = ad(t0123, x[3]);
  uint d0 = ad(x[0], x[0]), d2 = ad(x[2], x[2]);
  x[3] = ad(t01233, d0); x[1] = ad(t01123, d2); x[0] = ad(t01123, t01); x[2] = ad(t01233, t23); }}
inline void mds_light(thread uint* s) {{
  for (int i = 0; i < 16; i += 4) m4(s + i);
  uint sums[4]; for (int k = 0; k < 4; k++) sums[k] = ad(ad(s[k], s[4 + k]), ad(s[8 + k], s[12 + k]));
  for (int i = 0; i < 16; i++) s[i] = ad(s[i], sums[i & 3]); }}
inline void perm(thread uint* s, constant uint* c) {{
  constant uint* ei = c; constant uint* et = c + 64; constant uint* rin = c + 128; constant uint* dg = c + 148;
  mds_light(s);
  for (int r = 0; r < 4; r++) {{ for (int i = 0; i < 16; i++) s[i] = cube(ad(s[i], ei[r * 16 + i])); mds_light(s); }}
  for (int r = 0; r < 20; r++) {{
    s[0] = cube(ad(s[0], rin[r]));
    uint part = 0; for (int i = 1; i < 16; i++) part = ad(part, s[i]);
    uint full = ad(part, s[0]);
    s[0] = sb(part, s[0]);
    for (int i = 1; i < 16; i++) s[i] = ad(mm(s[i], dg[i]), full);
  }}
  for (int r = 0; r < 4; r++) {{ for (int i = 0; i < 16; i++) s[i] = cube(ad(s[i], et[r * 16 + i])); mds_light(s); }}
}}
kernel void grind16(constant uint* c [[buffer(0)]], constant uint* base [[buffer(1)]], constant uint* prm [[buffer(2)]],
                    device atomic_uint* out_min [[buffer(3)]], uint gid [[thread_position_in_grid]]) {{
  uint cand = prm[3] + gid;
  if (cand >= P) return;
  uint s[16]; for (int i = 0; i < 16; i++) s[i] = base[i];
  s[prm[0]] = mm(cand, R2);
  perm(s, c);
  uint v = mm(s[prm[1]], 1u);
  if ((v & prm[2]) == 0u) atomic_fetch_min_explicit(out_min, cand, memory_order_relaxed);
}}
// SPEED G2: PaddingFreeSponge<Perm16, 16, 8, 8> over one row of `w` Montgomery words: each block of up to 8 words
// overwrites the rate (a short last block overwrites only its own words) and is followed by one permutation.
kernel void leaves16(constant uint* c [[buffer(0)]], device const uint* rows [[buffer(1)]], constant uint& w [[buffer(2)]],
                     device uint* out [[buffer(3)]], uint gid [[thread_position_in_grid]]) {{
  uint s[16]; for (int i = 0; i < 16; i++) s[i] = 0u;
  device const uint* row = rows + (ulong)gid * w;
  for (uint b = 0; b < w; b += 8) {{
    uint n = min(8u, w - b);
    for (uint i = 0; i < n; i++) s[i] = row[b + i];
    perm(s, c);
  }}
  for (int i = 0; i < 8; i++) out[(ulong)gid * 8 + i] = s[i];
}}
// SPEED G2: TruncatedPermutation<Perm16, 2, 8, 16>: the two children fill the state (a missing second child is the
// default digest, all zero), one permutation, the first 8 words are the parent.
kernel void compress16(constant uint* c [[buffer(0)]], device const uint* prev [[buffer(1)]], constant uint& step [[buffer(2)]],
                       device uint* out [[buffer(3)]], uint gid [[thread_position_in_grid]]) {{
  uint s[16];
  for (int i = 0; i < 8; i++) s[i] = prev[(ulong)gid * step * 8 + i];
  for (int i = 0; i < 8; i++) s[8 + i] = step == 2u ? prev[(ulong)gid * 16 + 8 + i] : 0u;
  perm(s, c);
  for (int i = 0; i < 8; i++) out[(ulong)gid * 8 + i] = s[i];
}}
// SPEED G3: the radix-2 transform of every column of a row-major h × w matrix of Montgomery words.
// rows reversed into place: dst[rev(r)] = src[r]
kernel void bitrev16(device const uint* src [[buffer(0)]], device uint* dst [[buffer(1)]], constant uint* p [[buffer(2)]],
                     uint gid [[thread_position_in_grid]]) {{
  uint w = p[1], logh = p[2];
  uint r = gid / w, c = gid % w;
  uint rr = reverse_bits(r) >> (32u - logh);
  dst[(ulong)rr * w + c] = src[(ulong)r * w + c];
}}
// every word of row r times s[r]
kernel void rowscale16(device uint* a [[buffer(0)]], device const uint* s [[buffer(1)]], constant uint* p [[buffer(2)]],
                       uint gid [[thread_position_in_grid]]) {{
  uint w = p[1];
  a[gid] = mm(a[gid], s[gid / w]);
}}
// one decimation-in-time stage of half-span m: pairs (i, i + m) with twiddle tw[k · h / 2m]
kernel void dit16(device uint* a [[buffer(0)]], device const uint* tw [[buffer(1)]], constant uint* p [[buffer(2)]],
                  uint gid [[thread_position_in_grid]]) {{
  uint h = p[0], w = p[1], m = p[3];
  uint pr = gid / w, c = gid % w;
  uint k = pr % m;
  uint i = (pr / m) * 2u * m + k;
  uint j = i + m;
  uint t = tw[k * (h / (2u * m))];
  ulong ii = (ulong)i * w + c, jj = (ulong)j * w + c;
  uint u = a[ii];
  uint v = mm(a[jj], t);
  a[ii] = ad(u, v);
  a[jj] = sb(u, v);
}}
kernel void perm16(constant uint* c [[buffer(0)]], device uint* st [[buffer(1)]], uint gid [[thread_position_in_grid]]) {{
  uint s[16]; for (int i = 0; i < 16; i++) s[i] = st[gid * 16 + i];
  perm(s, c);
  for (int i = 0; i < 16; i++) st[gid * 16 + i] = s[i];
}}
"#
    )
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod ffi {
    unsafe extern "C" {
        pub fn musd_gpu_init(source: *const core::ffi::c_char) -> i32;
        pub fn musd_gpu_grind16(consts: *const u32, base: *const u32, params: *const u32, count: u32, out_min: *mut u32) -> i32;
        pub fn musd_gpu_perm16(consts: *const u32, states: *mut u32, n: u32) -> i32;
        pub fn musd_gpu_leaves16(consts: *const u32, rows: *const u32, nrows: u32, width: u32, out: *mut u32) -> i32;
        pub fn musd_gpu_compress16(consts: *const u32, prev: *const u32, prev_len: u32, out_len: u32, step: u32, out: *mut u32) -> i32;
        pub fn musd_gpu_ntt16(data: *mut u32, h: u32, w: u32, tw: *const u32, prescale: *const u32) -> i32;
    }
}

/// One registered permutation: its 164 Montgomery constants and its fingerprint (the CPU permutation of a fixed probe).
#[derive(Clone)]
pub struct GpuPerm {
    consts: [u32; 164],
    fingerprint: [u32; 16],
}

fn probe() -> [Fa4; 16] {
    core::array::from_fn(|i| Fa4::from_u32(i as u32 + 1))
}

fn fingerprint(perm: &Perm16) -> [u32; 16] {
    let mut s = probe();
    perm.permute_mut(&mut s);
    core::array::from_fn(|i| s[i].as_canonical_u32())
}

/// The internal layer's diagonal V of `Poseidon2KoalaBear<16>` (koala-bear/src/poseidon2.rs, `internal_layer_mat_mul`):
/// [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24].
fn internal_diag() -> [u32; 16] {
    let f = |n: i64, log2_den: u32| -> Fa4 {
        let mag = Fa4::from_u32(n.unsigned_abs() as u32) * Fa4::from_u32(1u32 << log2_den).inverse();
        if n < 0 { -mag } else { mag }
    };
    let v = [
        f(-2, 0), f(1, 0), f(2, 0), f(1, 1), f(3, 0), f(4, 0), f(-1, 1), f(-3, 0), f(-4, 0),
        f(1, 8), f(1, 3), f(1, 24), f(-1, 8), f(-1, 3), f(-1, 4), f(-1, 24),
    ];
    core::array::from_fn(|i| v[i].as_canonical_u32())
}

/// The constants of the permutation the provers build at `seed`, laid for the kernels.
pub fn gpu_perm_for_seed(seed: u64) -> GpuPerm {
    let (initial, terminal, internal) = crate::sponge_chain_air::raw_constants_for_seed(seed);
    let mut consts = [0u32; 164];
    for r in 0..4 {
        for i in 0..16 {
            consts[r * 16 + i] = to_mont(initial[r][i].as_canonical_u32());
            consts[64 + r * 16 + i] = to_mont(terminal[r][i].as_canonical_u32());
        }
    }
    for (k, c) in internal.iter().enumerate() {
        consts[128 + k] = to_mont(c.as_canonical_u32());
    }
    for (i, d) in internal_diag().iter().enumerate() {
        consts[148 + i] = to_mont(*d);
    }
    GpuPerm { consts, fingerprint: fingerprint(crate::sponge_chain_air::perm_for_seed(seed)) }
}

static REGISTRY: OnceLock<Vec<GpuPerm>> = OnceLock::new();
static STATUS: OnceLock<&'static str> = OnceLock::new();

/// Run `n` permutations on the GPU (canonical in, canonical out). `None` when the GPU is not ready.
pub fn gpu_permute(gp: &GpuPerm, states: &[[u32; 16]]) -> Option<Vec<[u32; 16]>> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !gpu_ready() {
            return None;
        }
        let mut flat: Vec<u32> = states.iter().flat_map(|s| s.iter().map(|&x| to_mont(x))).collect();
        // SAFETY: `consts` is 164 words and `flat` is 16·n words, the lengths the shim reads and writes.
        let ok = unsafe { ffi::musd_gpu_perm16(gp.consts.as_ptr(), flat.as_mut_ptr(), states.len() as u32) };
        if ok != 1 {
            return None;
        }
        Some(flat.chunks_exact(16).map(|c| core::array::from_fn(|i| from_mont(c[i]))).collect())
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (gp, states);
        None
    }
}

/// The smallest `w` below the field order whose permutation (written at `witness_idx` over `base`) samples an element
/// at `out_idx` with its low `bits` bits zero — searched on the GPU in increasing chunks. `None` when the GPU is not
/// ready or a dispatch fails (the caller then runs its own CPU search).
pub fn gpu_grind(gp: &GpuPerm, base: &[u64; 16], witness_idx: usize, out_idx: usize, bits: usize) -> Option<u64> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !gpu_ready() || witness_idx >= 16 || out_idx >= 16 || bits == 0 || bits >= 31 {
            return None;
        }
        let base_m: [u32; 16] = core::array::from_fn(|i| to_mont(base[i] as u32));
        let mask = (1u32 << bits) - 1;
        let mut start: u64 = 0;
        // The first chunk holds ONE expected hit's worth of candidates and every next chunk doubles, so the expected scan
        // is about 2–3 × 2^bits. A chunk is scanned whole before its minimum is read (that is what keeps the answer the
        // CPU's smallest witness), so a chunk sized for 16 hits paid 16 × 2^bits every time. MEASURED (the pin's own
        // timings, load 51–61): 20 bits took 169–186 ms with the 16-hit chunk against 77–235 ms on the CPU.
        let mut count: u64 = (1u64 << bits).clamp(1 << 16, 1 << 24);
        while start < P as u64 {
            let n = count.min(P as u64 - start) as u32;
            let params = [witness_idx as u32, out_idx as u32, mask, start as u32];
            let mut hit = u32::MAX;
            // SAFETY: the buffers have the lengths the shim reads (164, 16, 4 words) and `hit` is one word.
            let ok = unsafe { ffi::musd_gpu_grind16(gp.consts.as_ptr(), base_m.as_ptr(), params.as_ptr(), n, &mut hit) };
            if ok != 1 {
                return None;
            }
            if hit != u32::MAX {
                return Some(hit as u64);
            }
            start += n as u64;
            count = (count * 2).min(1 << 26);
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (gp, base, witness_idx, out_idx, bits);
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn gpu_ready() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        let src = std::ffi::CString::new(kernel_source()).expect("the kernel source has no NUL");
        // SAFETY: a NUL-terminated string the shim copies before returning.
        unsafe { ffi::musd_gpu_init(src.as_ptr()) == 1 }
    })
}

/// The challenger's grind accelerator: recognise a registered permutation and search on the GPU.
fn accel(job: &p3_challenger::GrindJob<'_>) -> Option<u64> {
    if job.bits < GPU_MIN_BITS || job.base.len() != 16 || job.order != P as u64 {
        return None;
    }
    let perm = job.permutation.downcast_ref::<Perm16>()?;
    let fp = fingerprint(perm);
    let gp = REGISTRY.get()?.iter().find(|g| g.fingerprint == fp)?;
    let base: [u64; 16] = core::array::from_fn(|i| job.base[i]);
    gpu_grind(gp, &base, job.witness_idx, job.out_idx, job.bits)
}

// ───────────────────────── SPEED G2: the streamed Merkle tree's hashing on the GPU ─────────────────────────
//
// MEASURED why: the leaf sponge (17.6 %) and the compressions (about 12 %) of the prover's working CPU on a real node
// (`prof-base`). The tree (`p3_merkle_tree::accel`) offers each leaf pass and each layer pass; these answer for the
// decider's own `SpongeHash` / `CompressHash` over a registered permutation, and only for passes large enough that the
// GPU beats the CPU ([`GPU_MIN_ROWS`]).
// SAFE-FALLBACK: every GPU pass is SPOT-CHECKED on the CPU before it is returned (four rows or parents recomputed with
// the very hasher the tree holds); a mismatch returns `None` — the tree's own CPU pass then runs and produces the same
// digests — and turns the GPU Merkle path off for the rest of the process. The proof built on either is still checked
// in full by its prover's own verify and by every peer.
// Privacy: the rows are the committed codeword plus the hiding salts, already in this process's memory; the GPU is part
// of this machine (unified memory) and nothing leaves it.

use std::sync::atomic::{AtomicBool, Ordering};

/// Below this many rows (or parents) a pass is cheaper on the CPU than a dispatch.
pub const GPU_MIN_ROWS: usize = 4096;
static MERKLE_DISTRUST: AtomicBool = AtomicBool::new(false);
/// Merkle passes the GPU answered in this process (read by the pins to know the GPU path was taken).
static GPU_MERKLE_PASSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect()
}
fn word_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
/// A raw Montgomery word as the field element it is (`MontyField31` is `repr(transparent)` over its Montgomery `u32`).
fn fe(raw: u32) -> Fa4 {
    // SAFETY: KoalaBear is `#[repr(transparent)]` over a `u32` holding its Montgomery form (monty-31/src/monty_31.rs:35).
    unsafe { core::mem::transmute::<u32, Fa4>(raw) }
}
fn raw(x: Fa4) -> u32 {
    // SAFETY: as in [`fe`].
    unsafe { core::mem::transmute::<Fa4, u32>(x) }
}

fn registered(perm: &Perm16) -> Option<&'static GpuPerm> {
    let fp = fingerprint(perm);
    REGISTRY.get()?.iter().find(|g| g.fingerprint == fp)
}

fn distrust(what: &str) {
    if !MERKLE_DISTRUST.swap(true, Ordering::SeqCst) {
        eprintln!("[gpu] ⛔ a GPU {what} disagreed with the CPU on a spot check: the Merkle passes run on the CPU from now on");
    }
}

/// The leaf digests of `rows` (row-major, `width` Montgomery words per row) under `gp`, spot-checked against `h`.
/// `Err` = the spot check failed; `Ok(None)` = the GPU could not run.
pub fn gpu_leaves_checked(gp: &GpuPerm, h: &crate::hiding_decider::SpongeHash, rows: &[u32], width: usize) -> Result<Option<Vec<u32>>, ()> {
    use p3_symmetric::CryptographicHasher;
    let nrows = rows.len() / width;
    if width == 0 || nrows * width != rows.len() || nrows == 0 {
        return Ok(None);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !gpu_ready() {
            return Ok(None);
        }
        let mut out = vec![0u32; nrows * 8];
        // SAFETY: `rows` holds nrows·width words and `out` nrows·8, the lengths the shim reads and writes.
        let ok = unsafe { ffi::musd_gpu_leaves16(gp.consts.as_ptr(), rows.as_ptr(), nrows as u32, width as u32, out.as_mut_ptr()) };
        if ok != 1 {
            return Ok(None);
        }
        for r in [0, nrows / 2, (nrows * 7) / 11, nrows - 1] {
            let cpu = h.hash_iter(rows[r * width..(r + 1) * width].iter().map(|&x| fe(x)));
            if (0..8).any(|i| raw(cpu[i]) != out[r * 8 + i]) {
                return Err(());
            }
        }
        Ok(Some(out))
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (gp, h);
        Ok(None)
    }
}

/// One layer of `out_len` parents over `prev` (8-word digests) under `gp`, spot-checked against `c`.
pub fn gpu_compress_checked(
    gp: &GpuPerm,
    c: &crate::hiding_decider::CompressHash,
    prev: &[u32],
    step: usize,
    out_len: usize,
) -> Result<Option<Vec<u32>>, ()> {
    use p3_symmetric::PseudoCompressionFunction;
    if out_len == 0 || !(step == 1 || step == 2) || prev.len() < out_len * step * 8 {
        return Ok(None);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !gpu_ready() {
            return Ok(None);
        }
        let mut out = vec![0u32; out_len * 8];
        // SAFETY: `prev` holds at least out_len·step·8 words and `out` out_len·8, what the shim reads and writes.
        let ok = unsafe {
            ffi::musd_gpu_compress16(gp.consts.as_ptr(), prev.as_ptr(), (prev.len() / 8) as u32, out_len as u32, step as u32, out.as_mut_ptr())
        };
        if ok != 1 {
            return Ok(None);
        }
        for p in [0, out_len / 2, (out_len * 7) / 11, out_len - 1] {
            let child = |k: usize| -> [Fa4; 8] {
                if k < step { core::array::from_fn(|i| fe(prev[(p * step + k) * 8 + i])) } else { [Fa4::ZERO; 8] }
            };
            let cpu = c.compress([child(0), child(1)]);
            if (0..8).any(|i| raw(cpu[i]) != out[p * 8 + i]) {
                return Err(());
            }
        }
        Ok(Some(out))
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (gp, c);
        Ok(None)
    }
}

fn merkle_leaves(job: &p3_merkle_tree::accel::LeafJob<'_>) -> Option<Vec<u8>> {
    if MERKLE_DISTRUST.load(Ordering::Relaxed)
        || job.hasher_type != core::any::type_name::<crate::hiding_decider::SpongeHash>()
        || job.value_type != core::any::type_name::<Fa4>()
        || job.digest_type != core::any::type_name::<Fa4>()
        || job.digest_elems != 8
        || job.width == 0
        || job.rows.len() / 4 / job.width < GPU_MIN_ROWS
    {
        return None;
    }
    // SAFETY: the tree names its hasher type `SpongeHash`, so `job.hasher` points at one for the length of this call.
    let h: &crate::hiding_decider::SpongeHash = unsafe { &*(job.hasher as *const crate::hiding_decider::SpongeHash) };
    let gp = registered(h.permutation())?;
    match gpu_leaves_checked(gp, h, &words(job.rows), job.width) {
        Ok(Some(out)) => {
            GPU_MERKLE_PASSES.fetch_add(1, Ordering::Relaxed);
            Some(word_bytes(&out))
        }
        Ok(None) => None,
        Err(()) => {
            distrust("leaf pass");
            None
        }
    }
}

fn merkle_compress(job: &p3_merkle_tree::accel::CompressJob<'_>) -> Option<Vec<u8>> {
    if MERKLE_DISTRUST.load(Ordering::Relaxed)
        || job.compress_type != core::any::type_name::<crate::hiding_decider::CompressHash>()
        || job.digest_type != core::any::type_name::<Fa4>()
        || job.digest_elems != 8
        || job.arity != 2
        || job.out_len < GPU_MIN_ROWS
    {
        return None;
    }
    // SAFETY: the tree names its compression type `CompressHash`, so `job.compress` points at one for this call.
    let c: &crate::hiding_decider::CompressHash = unsafe { &*(job.compress as *const crate::hiding_decider::CompressHash) };
    let gp = registered(c.inner_permutation())?;
    match gpu_compress_checked(gp, c, &words(job.prev), job.step, job.out_len) {
        Ok(Some(out)) => {
            GPU_MERKLE_PASSES.fetch_add(1, Ordering::Relaxed);
            Some(word_bytes(&out))
        }
        Ok(None) => None,
        Err(()) => {
            distrust("layer pass");
            None
        }
    }
}

static MERKLE_ACCEL: p3_merkle_tree::accel::MerkleAccel =
    p3_merkle_tree::accel::MerkleAccel { leaves: merkle_leaves, compress: merkle_compress };

// ───────────────────────── SPEED G3: the small-batch DFT on the GPU ─────────────────────────
//
// What it is: `p3_dft::accel` offers `dft_batch` and `coset_lde_batch` of `Radix2DFTSmallBatch` over raw words; these
// answer for KoalaBear. The forward transform is one GPU pass (row reversal, then log2(h) butterfly stages with
// `tw[x] = root^x`); the LDE is the inverse pass (root⁻¹), then a forward pass over the zero-padded coefficients of order
// `h << added_bits` with the row pre-scale `(1/h)·shift^r` — `coset_lde_batch`'s own definition (interpolate, extend,
// evaluate on the coset).
// SAFE-FALLBACK: every GPU transform is SPOT-CHECKED on the CPU — four output entries recomputed directly as
// `Σ_j x[j]·ω^(r·j)` (and for the LDE the coefficient pass the same way) with the field's own arithmetic; a mismatch
// returns `None` — the CPU transform then runs and produces the same matrix — and turns the GPU DFT off for the process.
// Scale: one transform's memory on the GPU (the matrix twice); passes above [`GPU_MAX_DFT_WORDS`] stay on the CPU.

/// Below this many words a transform is cheaper on the CPU than a dispatch, whatever the CPU has.
pub const GPU_MIN_DFT_WORDS: usize = 1 << 16;
/// With more proving threads than [`GPU_DFT_FEW_THREADS`], a transform goes to the GPU only from this many words.
/// MEASURED (`member_ledger::tests::measure_the_member_ledger_proof_with_the_gpu_on_and_off`, 2026-11-12, load 64):
/// all 10 threads — off 2,364 ms, GPU DFT 2,906 ms (96 small transforms per proof, each a GPU round trip); 2 threads —
/// off 6,499 ms, GPU DFT 5,647 ms, all parts 4,607 ms. A wide CPU does a small transform faster than a round trip; a
/// narrow one (a phone, a sliced node) does not.
pub const GPU_MIN_DFT_WORDS_WIDE: usize = 1 << 20;
/// At or below this many proving threads every transform of [`GPU_MIN_DFT_WORDS`] or more goes to the GPU.
pub const GPU_DFT_FEW_THREADS: usize = 4;

fn dft_min_words() -> usize {
    if rayon::current_num_threads() <= GPU_DFT_FEW_THREADS { GPU_MIN_DFT_WORDS } else { GPU_MIN_DFT_WORDS_WIDE }
}
/// Above this many output words a transform stays on the CPU (the GPU holds the matrix twice: 2 × 256 MB at most).
pub const GPU_MAX_DFT_WORDS: usize = 1 << 26;
static DFT_DISTRUST: AtomicBool = AtomicBool::new(false);
static GPU_DFT_PASSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn pow_table(root: Fa4, n: usize) -> Vec<u32> {
    let mut v = Vec::with_capacity(n);
    let mut x = Fa4::ONE;
    for _ in 0..n {
        v.push(raw(x));
        x *= root;
    }
    v
}

/// The GPU transform of the h × w matrix `data` (raw Montgomery words), in place: optional row pre-scale, natural order.
fn gpu_ntt(data: &mut [u32], h: usize, w: usize, root: Fa4, prescale: Option<&[u32]>) -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if !gpu_ready() || data.len() != h * w || prescale.is_some_and(|p| p.len() != h) {
            return false;
        }
        let tw = pow_table(root, h / 2);
        let pre = prescale.map_or(core::ptr::null(), <[u32]>::as_ptr);
        // SAFETY: `data` holds h·w words, `tw` h/2, `pre` h (or null): the lengths the shim reads and writes.
        unsafe { ffi::musd_gpu_ntt16(data.as_mut_ptr(), h as u32, w as u32, tw.as_ptr(), pre) == 1 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (data, h, w, root, prescale);
        false
    }
}

/// `Σ_j x[j][c]·scale[j]·ω^(r·j)` straight from the definition, for the spot checks.
fn eval_entry(x: &[u32], h: usize, w: usize, c: usize, r: usize, omega: Fa4, scale: Option<&[u32]>) -> u32 {
    let step = omega.exp_u64(r as u64);
    let (mut acc, mut pw) = (Fa4::ZERO, Fa4::ONE);
    for j in 0..h {
        let mut v = fe(x[j * w + c]) * pw;
        if let Some(s) = scale {
            v *= fe(s[j]);
        }
        acc += v;
        pw *= step;
    }
    raw(acc)
}

fn spot_rows(h: usize) -> [usize; 4] {
    [0, 1 % h, (h / 2 + 1) % h, h - 1]
}

/// The forward transform of `x` (h × w raw words) on the GPU, spot-checked. `Err` = a spot check failed.
pub fn gpu_dft_checked(x: &[u32], h: usize, w: usize, root: Fa4) -> Result<Option<Vec<u32>>, ()> {
    let mut out = x.to_vec();
    if !gpu_ntt(&mut out, h, w, root, None) {
        return Ok(None);
    }
    for (k, r) in spot_rows(h).into_iter().enumerate() {
        let c = (k * 7919) % w;
        if eval_entry(x, h, w, c, r, root, None) != out[r * w + c] {
            return Err(());
        }
    }
    Ok(Some(out))
}

/// The LDE of `x` (evaluations on the subgroup of order h) onto `shift` times the subgroup of order `h << added`, on
/// the GPU, both passes spot-checked. `Err` = a spot check failed.
pub fn gpu_lde_checked(x: &[u32], h: usize, w: usize, added: usize, shift: Fa4) -> Result<Option<Vec<u32>>, ()> {
    let log_h = h.trailing_zeros() as usize;
    let root = <Fa4 as p3_field::TwoAdicField>::two_adic_generator(log_h);
    let out_root = <Fa4 as p3_field::TwoAdicField>::two_adic_generator(log_h + added);
    let inv_root = root.inverse();
    let inv_h = Fa4::from_u32(h as u32).inverse();
    // pass 1: h · coefficients (the inverse transform without its 1/h)
    let mut coeffs = x.to_vec();
    if !gpu_ntt(&mut coeffs, h, w, inv_root, None) {
        return Ok(None);
    }
    for (k, r) in spot_rows(h).into_iter().enumerate() {
        let c = (k * 104_729) % w;
        if eval_entry(x, h, w, c, r, inv_root, None) != coeffs[r * w + c] {
            return Err(());
        }
    }
    // pass 2: the zero-padded coefficients, row r scaled by (1/h)·shift^r, evaluated on the subgroup of order h << added
    let big = h << added;
    let mut prescale = vec![0u32; big];
    let mut s = inv_h;
    for p in prescale.iter_mut().take(h) {
        *p = raw(s);
        s *= shift;
    }
    let mut out = vec![0u32; big * w];
    out[..h * w].copy_from_slice(&coeffs);
    if !gpu_ntt(&mut out, big, w, out_root, Some(&prescale)) {
        return Ok(None);
    }
    for (k, r) in spot_rows(big).into_iter().enumerate() {
        let c = (k * 15_485_863) % w;
        if eval_entry(&coeffs, h, w, c, r, out_root, Some(&prescale[..h])) != out[r * w + c] {
            return Err(());
        }
    }
    Ok(Some(out))
}

fn dft_job_fe(bytes: &[u8]) -> Option<Fa4> {
    (bytes.len() == 4).then(|| fe(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])))
}

fn dft_distrust() {
    if !DFT_DISTRUST.swap(true, Ordering::SeqCst) {
        eprintln!("[gpu] ⛔ a GPU transform disagreed with the CPU on a spot check: the DFT runs on the CPU from now on");
    }
}

fn accel_dft(job: &p3_dft::accel::DftJob<'_>) -> Option<Vec<u8>> {
    let words_n = job.height * job.width;
    if DFT_DISTRUST.load(Ordering::Relaxed)
        || job.value_type != core::any::type_name::<Fa4>()
        || !(dft_min_words()..=GPU_MAX_DFT_WORDS).contains(&words_n)
    {
        return None;
    }
    let root = dft_job_fe(job.root)?;
    match gpu_dft_checked(&words(job.values), job.height, job.width, root) {
        Ok(Some(out)) => {
            GPU_DFT_PASSES.fetch_add(1, Ordering::Relaxed);
            Some(word_bytes(&out))
        }
        Ok(None) => None,
        Err(()) => {
            dft_distrust();
            None
        }
    }
}

fn accel_lde(job: &p3_dft::accel::DftJob<'_>) -> Option<Vec<u8>> {
    let out_n = (job.height << job.added_bits) * job.width;
    if DFT_DISTRUST.load(Ordering::Relaxed)
        || job.value_type != core::any::type_name::<Fa4>()
        || !(dft_min_words()..=GPU_MAX_DFT_WORDS).contains(&out_n)
    {
        return None;
    }
    let shift = dft_job_fe(job.shift)?;
    match gpu_lde_checked(&words(job.values), job.height, job.width, job.added_bits, shift) {
        Ok(Some(out)) => {
            GPU_DFT_PASSES.fetch_add(1, Ordering::Relaxed);
            Some(word_bytes(&out))
        }
        Ok(None) => None,
        Err(()) => {
            dft_distrust();
            None
        }
    }
}

static DFT_ACCEL: p3_dft::accel::DftAccel = p3_dft::accel::DftAccel { dft: accel_dft, lde: accel_lde };

/// The transforms the GPU has answered in this process.
#[must_use]
pub fn gpu_dft_passes() -> usize {
    GPU_DFT_PASSES.load(Ordering::SeqCst)
}

/// The Merkle passes the GPU has answered in this process (for measurements to know the GPU path was taken).
#[must_use]
pub fn gpu_merkle_passes() -> usize {
    GPU_MERKLE_PASSES.load(Ordering::SeqCst)
}

/// Switch each installed accelerator on or off on its own (grind, Merkle, DFT) — for the in-process measurement of which
/// part pays; the node never calls it. Only parts whose [`install`] succeeded can be switched on.
pub fn set_parts(grind: bool, merkle: bool, dft: bool) {
    let ok = REGISTRY.get().is_some();
    p3_challenger::set_grind_accel((ok && grind).then_some(accel as p3_challenger::GrindAccel));
    p3_merkle_tree::accel::set_merkle_accel((ok && merkle).then_some(&MERKLE_ACCEL));
    p3_dft::accel::set_dft_accel((ok && dft).then_some(&DFT_ACCEL));
}

/// Switch the installed accelerators off (`false`) or back on (`true`, only when [`install`] succeeded) — for the
/// in-process A/B measurement; the node never calls it.
pub fn set_enabled(on: bool) {
    if on && REGISTRY.get().is_some() {
        p3_challenger::set_grind_accel(Some(accel));
        p3_merkle_tree::accel::set_merkle_accel(Some(&MERKLE_ACCEL));
        p3_dft::accel::set_dft_accel(Some(&DFT_ACCEL));
    } else {
        p3_challenger::set_grind_accel(None);
        p3_merkle_tree::accel::set_merkle_accel(None);
        p3_dft::accel::set_dft_accel(None);
    }
}

/// Install the GPU grind for every duplex challenger in this process, once. Each registered permutation is first held
/// to the CPU permutation on 256 random states; any difference and NOTHING is installed (the CPU keeps every grind).
/// `MONEROUSD_GPU=0` keeps the CPU path (measurement A/B). Returns a one-line status for the node's log.
pub fn install() -> &'static str {
    // ⛔ A PROVE NEVER WAITS FOR THE GPU (lane af58, 2026-11-16). This ran the whole GPU setup (the Metal kernels' compile in
    // `musd_gpu_init`, then a CPU cross-check) inside `STATUS.get_or_init` on the CALLER's thread, and every prove calls it, so
    // when that compile blocked every prover of the process queued behind the OnceLock for good. MEASURED (macOS `sample` of a
    // wallet-harness stuck 22 min in a send, af58 rig, main 55a00793): the send's main thread, the note-spend prover and the
    // spend-or-decoy prover all in `OnceLock::initialize` → `Once::wait` → `_dispatch_semaphore_wait_slow`, the double-spend
    // check hung with it. Now the setup runs ONCE on its own thread; until it finishes this answers at once and the prover
    // grinds on the CPU — the same witnesses (every GPU result is checked on the CPU, and the accelerators are registered only
    // at the end of a setup that passed), so a proof is byte-for-byte what it would be either way.
    if let Some(s) = STATUS.get() {
        return s;
    }
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let _ = std::thread::Builder::new().name("musd-gpu-setup".into()).spawn(|| {
            let _ = install_blocking();
        });
    });
    STATUS.get().copied().unwrap_or("setting up: proofs grind on the CPU until the GPU is ready")
}

/// The GPU setup itself, on the calling thread (the background thread `install` starts, and a test that needs the result).
pub fn install_blocking() -> &'static str {
    STATUS.get_or_init(|| {
        if std::env::var("MONEROUSD_GPU").is_ok_and(|v| v == "0") {
            return "off (MONEROUSD_GPU=0): grinding on the CPU";
        }
        let seeds = [crate::whir_rec_block::REC_DECIDER_SEED, crate::committed_air::COMMITTED_AIR_SEED];
        let mut reg = Vec::new();
        for seed in seeds {
            let gp = gpu_perm_for_seed(seed);
            let cpu = crate::sponge_chain_air::perm_for_seed(seed);
            let mut x: u32 = 0x9e37_79b9 ^ seed as u32;
            let states: Vec<[u32; 16]> = (0..256)
                .map(|_| {
                    core::array::from_fn(|_| {
                        x ^= x << 13;
                        x ^= x >> 17;
                        x ^= x << 5;
                        x % P
                    })
                })
                .collect();
            let Some(gpu_out) = gpu_permute(&gp, &states) else {
                return "unavailable (no GPU or the kernels did not compile): grinding on the CPU";
            };
            for (s, g) in states.iter().zip(&gpu_out) {
                let mut c: [Fa4; 16] = core::array::from_fn(|i| Fa4::from_u32(s[i]));
                cpu.permute_mut(&mut c);
                if (0..16).any(|i| c[i].as_canonical_u32() != g[i]) {
                    return "REFUSED: the GPU permutation differs from the CPU permutation: grinding on the CPU";
                }
            }
            reg.push(gp);
        }
        if REGISTRY.set(reg).is_err() {
            return "already registered";
        }
        p3_challenger::set_grind_accel(Some(accel));
        p3_merkle_tree::accel::set_merkle_accel(Some(&MERKLE_ACCEL));
        p3_dft::accel::set_dft_accel(Some(&DFT_ACCEL));
        "on: proof-of-work grinds (12 bits or more), Merkle passes (4,096 rows or more) and DFTs (2^16 words or more) run on the GPU; every grind witness and a spot check of every Merkle pass and transform verified on the CPU"
    })
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, DuplexChallenger};
    use p3_field::PrimeField64;

    type Chl = DuplexChallenger<Fa4, Perm16, 16, 8>;

    fn xs(seed: u32, n: usize) -> Vec<u32> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x % P
            })
            .collect()
    }

    /// The GPU permutation IS `Poseidon2KoalaBear<16>` at both production seeds, on 4,096 random states each.
    #[test]
    fn the_gpu_permutation_is_the_cpu_permutation_at_both_production_seeds() {
        for seed in [crate::whir_rec_block::REC_DECIDER_SEED, crate::committed_air::COMMITTED_AIR_SEED] {
            let gp = gpu_perm_for_seed(seed);
            let v = xs(seed as u32 ^ 0x5eed, 4096 * 16);
            let states: Vec<[u32; 16]> = v.chunks_exact(16).map(|c| core::array::from_fn(|i| c[i])).collect();
            let out = gpu_permute(&gp, &states).expect("this test runs on an Apple machine with a GPU: the GPU must be ready");
            let cpu = crate::sponge_chain_air::perm_for_seed(seed);
            for (s, g) in states.iter().zip(&out) {
                let mut c: [Fa4; 16] = core::array::from_fn(|i| Fa4::from_u32(s[i]));
                cpu.permute_mut(&mut c);
                let c: [u32; 16] = core::array::from_fn(|i| c[i].as_canonical_u32());
                assert_eq!(&c, g, "seed {seed:#x}: GPU and CPU permutations differ on {s:?}");
            }
        }
    }

    /// CALIBRATION: the comparison above CAN fail — one internal round constant changed by one, and the GPU output
    /// differs from the CPU's on every state.
    #[test]
    fn calibration_a_gpu_permutation_with_one_wrong_constant_is_caught() {
        let seed = crate::whir_rec_block::REC_DECIDER_SEED;
        let mut gp = gpu_perm_for_seed(seed);
        gp.consts[128 + 7] = to_mont((from_mont(gp.consts[128 + 7]) + 1) % P);
        let states: Vec<[u32; 16]> = (0..64u32).map(|k| core::array::from_fn(|i| k * 16 + i as u32)).collect();
        let out = gpu_permute(&gp, &states).expect("GPU ready");
        let cpu = crate::sponge_chain_air::perm_for_seed(seed);
        let differing = states
            .iter()
            .zip(&out)
            .filter(|(s, g)| {
                let mut c: [Fa4; 16] = core::array::from_fn(|i| Fa4::from_u32(s[i]));
                cpu.permute_mut(&mut c);
                (0..16).any(|i| c[i].as_canonical_u32() != g[i])
            })
            .count();
        assert_eq!(differing, 64, "a wrong constant must change every output");
    }

    /// The GPU grind returns EXACTLY the CPU search's witness — the smallest — for both production challengers, every
    /// input-buffer fill (0 to 7 buffered elements) and depths 12 to 20; prints each depth's two timings.
    #[test]
    fn the_gpu_grind_returns_the_cpu_witness() {
        for seed in [crate::whir_rec_block::REC_DECIDER_SEED, crate::committed_air::COMMITTED_AIR_SEED] {
            let gp = gpu_perm_for_seed(seed);
            for (k, bits) in [12usize, 14, 16, 18, 20].into_iter().enumerate() {
                for fill in 0..8usize {
                    let mut ch = Chl::new(crate::sponge_chain_air::perm_for_seed(seed).clone());
                    for v in xs((seed as u32) ^ (k as u32 * 131 + fill as u32 * 7 + 1), 9 + fill) {
                        ch.observe(Fa4::from_u32(v));
                    }
                    let base: [u64; 16] = core::array::from_fn(|i| {
                        if i < ch.input_buffer.len() { ch.input_buffer[i].as_canonical_u64() } else { ch.sponge_state[i].as_canonical_u64() }
                    });
                    let t = std::time::Instant::now();
                    let cpu = ch.try_grind_cpu(bits).map(|w| w.as_canonical_u64());
                    let cpu_ms = t.elapsed().as_secs_f64() * 1e3;
                    let t = std::time::Instant::now();
                    let gpu = gpu_grind(&gp, &base, ch.input_buffer.len(), 7, bits);
                    let gpu_ms = t.elapsed().as_secs_f64() * 1e3;
                    assert_eq!(gpu, cpu, "seed {seed:#x} bits {bits} fill {fill}: the GPU must return the CPU's (smallest) witness");
                    if fill == 0 {
                        eprintln!("[gpu-grind] seed {seed:#x} {bits:>2} bits: witness {cpu:?}, CPU {cpu_ms:.2} ms, GPU {gpu_ms:.2} ms");
                    }
                }
            }
        }
    }

    fn sponge(seed: u64) -> crate::hiding_decider::SpongeHash {
        crate::hiding_decider::SpongeHash::new(crate::sponge_chain_air::perm_for_seed(seed).clone())
    }
    fn compressor(seed: u64) -> crate::hiding_decider::CompressHash {
        crate::hiding_decider::CompressHash::new(crate::sponge_chain_air::perm_for_seed(seed).clone())
    }

    /// G2: the GPU leaf pass is the CPU sponge on EVERY row, for row widths that are short, exact, one over and long
    /// (1, 7, 8, 9, 17, 437 words), at both production seeds.
    #[test]
    fn g2_the_gpu_leaf_digests_are_the_cpu_digests() {
        use p3_symmetric::CryptographicHasher;
        for seed in [crate::whir_rec_block::REC_DECIDER_SEED, crate::committed_air::COMMITTED_AIR_SEED] {
            let gp = gpu_perm_for_seed(seed);
            let h = sponge(seed);
            for width in [1usize, 7, 8, 9, 17, 437] {
                let nrows = 4100;
                let rows: Vec<u32> = xs(seed as u32 ^ width as u32 * 31 + 3, nrows * width).into_iter().map(|v| raw(Fa4::from_u32(v))).collect();
                let out = gpu_leaves_checked(&gp, &h, &rows, width).expect("spot check passes").expect("GPU ready");
                for r in 0..nrows {
                    let cpu = h.hash_iter(rows[r * width..(r + 1) * width].iter().map(|&x| fe(x)));
                    assert!((0..8).all(|i| raw(cpu[i]) == out[r * 8 + i]), "seed {seed:#x} width {width} row {r}");
                }
            }
        }
    }

    /// G2: the GPU layer pass is the CPU compression on every parent, binary (step 2) and the odd tail (step 1).
    #[test]
    fn g2_the_gpu_compress_is_the_cpu_compress() {
        use p3_symmetric::PseudoCompressionFunction;
        for seed in [crate::whir_rec_block::REC_DECIDER_SEED, crate::committed_air::COMMITTED_AIR_SEED] {
            let gp = gpu_perm_for_seed(seed);
            let c = compressor(seed);
            for step in [1usize, 2] {
                let out_len = 4099;
                let prev: Vec<u32> = xs(seed as u32 ^ step as u32 * 77 + 9, out_len * step * 8).into_iter().map(|v| raw(Fa4::from_u32(v))).collect();
                let out = gpu_compress_checked(&gp, &c, &prev, step, out_len).expect("spot check passes").expect("GPU ready");
                for p in 0..out_len {
                    let child = |k: usize| -> [Fa4; 8] {
                        if k < step { core::array::from_fn(|i| fe(prev[(p * step + k) * 8 + i])) } else { [Fa4::ZERO; 8] }
                    };
                    let cpu = c.compress([child(0), child(1)]);
                    assert!((0..8).all(|i| raw(cpu[i]) == out[p * 8 + i]), "seed {seed:#x} step {step} parent {p}");
                }
            }
        }
    }

    /// G2 CALIBRATION: a GPU permutation with one wrong constant fails the spot check of both passes (`Err`), so a
    /// faulty GPU never reaches a tree.
    #[test]
    fn g2_calibration_a_wrong_gpu_permutation_fails_the_spot_checks() {
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        let mut gp = gpu_perm_for_seed(seed);
        gp.consts[3] = to_mont((from_mont(gp.consts[3]) + 1) % P);
        let rows: Vec<u32> = xs(5, 4096 * 9).into_iter().map(|v| raw(Fa4::from_u32(v))).collect();
        assert!(gpu_leaves_checked(&gp, &sponge(seed), &rows, 9).is_err(), "a wrong leaf pass must fail its spot check");
        let prev: Vec<u32> = xs(6, 4096 * 16).into_iter().map(|v| raw(Fa4::from_u32(v))).collect();
        assert!(gpu_compress_checked(&gp, &compressor(seed), &prev, 2, 4096).is_err(), "a wrong layer pass must fail its spot check");
    }

    /// G2 end to end: with the accelerator installed, a STREAMED tree over the decider's own hash types (taking the GPU
    /// leaf and layer passes) has the root of the CLASSIC tree (no accelerator path), at 1, 2 and 4 cosets.
    #[test]
    fn g2_a_streamed_tree_on_the_gpu_has_the_classic_root() {
        use p3_matrix::Matrix;
        use p3_matrix::dense::RowMajorMatrix;
        type Pk = <Fa4 as Field>::Packing;
        assert!(install_blocking().starts_with("on"), "install must succeed on this machine");
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        let (h, c) = (sponge(seed), compressor(seed));
        let rows = 1usize << 15;
        let width = 21;
        let m = RowMajorMatrix::new(xs(15, rows * width).into_iter().map(Fa4::from_u32).collect::<Vec<_>>(), width);
        let coset_of = |m: &RowMajorMatrix<Fa4>, cosets: usize, k: usize| -> RowMajorMatrix<Fa4> {
            let mut vals = Vec::with_capacity(m.width() * rows / cosets);
            for j in 0..rows / cosets {
                vals.extend(m.row_slice(k + cosets * j).expect("row").iter().copied());
            }
            RowMajorMatrix::new(vals, m.width())
        };
        let classic = p3_merkle_tree::MerkleTree::<Fa4, Fa4, RowMajorMatrix<Fa4>, 2, 8>::new::<Pk, Pk, _, _>(&h, &c, vec![m.clone()]);
        let passes_before = GPU_MERKLE_PASSES.load(Ordering::SeqCst);
        for cosets in [1usize, 2, 4] {
            let streamed = p3_merkle_tree::MerkleTree::<Fa4, Fa4, RowMajorMatrix<Fa4>, 2, 8>::new_streamed::<Pk, Pk, _, _, _>(
                &h,
                &c,
                m.clone(),
                cosets,
                |leaf, k| coset_of(leaf, cosets, k),
            );
            assert_eq!(classic.root(), streamed.root(), "{cosets} coset(s): the GPU-built tree must have the classic root");
        }
        assert!(!MERKLE_DISTRUST.load(Ordering::SeqCst), "no spot check may have failed");
        let passes = GPU_MERKLE_PASSES.load(Ordering::SeqCst) - passes_before;
        assert!(passes >= 6, "the streamed trees must have taken the GPU path (leaf + layer passes): {passes} GPU passes");
    }

    fn mat(seed: u32, h: usize, w: usize) -> p3_matrix::dense::RowMajorMatrix<Fa4> {
        p3_matrix::dense::RowMajorMatrix::new(xs(seed, h * w).into_iter().map(Fa4::from_u32).collect(), w)
    }
    fn raws(m: &p3_matrix::dense::RowMajorMatrix<Fa4>) -> Vec<u32> {
        m.values.iter().map(|&x| raw(x)).collect()
    }

    /// G3: the GPU forward transform is the CPU transform (`Radix2Dit`, which has no accelerator hook) on EVERY entry,
    /// for heights 2^1 to 2^14 and widths 1 to 64.
    #[test]
    fn g3_the_gpu_dft_is_the_cpu_dft() {
        use p3_dft::TwoAdicSubgroupDft;
        let cpu = p3_dft::Radix2Dit::<Fa4>::default();
        for (log_h, w) in [(1usize, 1usize), (3, 5), (10, 1), (12, 17), (14, 3), (14, 64)] {
            let h = 1 << log_h;
            let m = mat(log_h as u32 * 101 + w as u32, h, w);
            let root = <Fa4 as p3_field::TwoAdicField>::two_adic_generator(log_h);
            let gpu = gpu_dft_checked(&raws(&m), h, w, root).expect("spot check passes").expect("GPU ready");
            let want = raws(&cpu.dft_batch(m.clone()));
            assert_eq!(gpu, want, "h = 2^{log_h}, w = {w}: the GPU transform must be the CPU transform entry for entry");
        }
    }

    /// G3: the GPU low-degree extension is the CPU `coset_lde_batch` (`Radix2Dit`) on every entry, for 1 to 3 added
    /// bits and the shifts the provers use (the field's generator) and a random one.
    #[test]
    fn g3_the_gpu_lde_is_the_cpu_lde() {
        use p3_dft::TwoAdicSubgroupDft;
        use p3_field::PrimeCharacteristicRing;
        let cpu = p3_dft::Radix2Dit::<Fa4>::default();
        for (log_h, w, added, shift) in [
            (4usize, 3usize, 1usize, Fa4::GENERATOR),
            (10, 7, 2, Fa4::GENERATOR),
            (12, 16, 1, Fa4::from_u32(123_456_789)),
            (13, 5, 3, Fa4::GENERATOR),
        ] {
            let h = 1 << log_h;
            let m = mat(log_h as u32 * 31 + w as u32 + added as u32, h, w);
            let gpu = gpu_lde_checked(&raws(&m), h, w, added, shift).expect("spot checks pass").expect("GPU ready");
            let want = raws(&cpu.coset_lde_batch(m.clone(), added, shift));
            assert_eq!(gpu, want, "h = 2^{log_h}, w = {w}, +{added} bits: the GPU extension must be the CPU extension");
        }
    }

    /// G3 CALIBRATION: the comparison above can fail — the GPU transform under the WRONG root (one of twice the order)
    /// differs from the CPU transform, and a corrupted output entry fails the spot check's own equality.
    #[test]
    fn g3_calibration_a_wrong_transform_is_caught() {
        use p3_dft::TwoAdicSubgroupDft;
        let (log_h, w) = (10usize, 4usize);
        let h = 1 << log_h;
        let m = mat(77, h, w);
        // A root of twice the order breaks the butterflies' ω^(h/2) = −1: the GPU output is not the transform of the
        // definition, and the spot check (computed from the definition) must refuse it.
        let wrong_root = <Fa4 as p3_field::TwoAdicField>::two_adic_generator(log_h + 1);
        assert!(gpu_dft_checked(&raws(&m), h, w, wrong_root).is_err(), "a transform that is not the DFT must fail its spot check");
        let _ = p3_dft::Radix2Dit::<Fa4>::default().dft_batch(m.clone());
        let root = <Fa4 as p3_field::TwoAdicField>::two_adic_generator(log_h);
        let x = raws(&m);
        let mut out = gpu_dft_checked(&x, h, w, root).expect("ok").expect("GPU ready");
        out[w] ^= 1; // row 1, column 0: a spot-checked entry
        assert_ne!(eval_entry(&x, h, w, 0, 1, root, None), out[w], "the spot check's equality must see a corrupted entry");
    }

    /// G3 end to end: with the accelerators installed, the decider's own `Radix2DFTSmallBatch` (hooked) gives the CPU
    /// reference's transform and extension, and the GPU path was taken.
    #[test]
    fn g3_the_hooked_small_batch_dft_is_the_cpu_dft() {
        use p3_dft::TwoAdicSubgroupDft;
        assert!(install_blocking().starts_with("on"), "install must succeed on this machine");
        let before = GPU_DFT_PASSES.load(Ordering::SeqCst);
        let hooked = crate::hiding_decider::Dft16::default();
        let cpu = p3_dft::Radix2Dit::<Fa4>::default();
        let m = mat(4242, 1 << 13, 16);
        assert_eq!(raws(&hooked.dft_batch(m.clone())), raws(&cpu.dft_batch(m.clone())), "dft_batch");
        assert_eq!(
            raws(&hooked.coset_lde_batch(m.clone(), 1, Fa4::GENERATOR)),
            raws(&cpu.coset_lde_batch(m, 1, Fa4::GENERATOR)),
            "coset_lde_batch"
        );
        assert!(!DFT_DISTRUST.load(Ordering::SeqCst), "no spot check may have failed");
        assert!(GPU_DFT_PASSES.load(Ordering::SeqCst) - before >= 2, "both transforms must have taken the GPU path");
    }

    /// ⛔ A prove never waits for the GPU (lane af58, 2026-11-16): `install()`, which every prove calls, answers at once — it
    /// starts the setup on its own thread and reports it, whatever the setup does. Before, it ran the Metal compile on the
    /// caller and a wallet's send deadlocked behind it for 22 min (macOS `sample`: three provers in `OnceLock::initialize`).
    /// TWO-PARTY-REVIEWED: a process-local resource setup (this process's GPU); there is no second endpoint — the boundary
    /// that matters, a send crossing two nodes, is the real-node double-spend check.
    #[test]
    fn a_prove_never_waits_for_the_gpu_setup() {
        let t = std::time::Instant::now();
        let status = install();
        let took = t.elapsed();
        assert!(took < std::time::Duration::from_millis(250), "install() blocked the caller for {took:?}: {status}");
        // the setup still completes on its own thread; the blocking form is what a caller that needs it waits on
        assert!(!install_blocking().is_empty());
    }

    /// Installed, a challenger's own `try_grind` returns the CPU search's witness and the witness checks.
    #[test]
    fn an_installed_grind_is_the_cpu_grind() {
        let status = install_blocking();
        assert!(status.starts_with("on"), "install must succeed on this machine: {status}");
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        for bits in [8usize, 13, 17] {
            let mut ch = Chl::new(crate::sponge_chain_air::perm_for_seed(seed).clone());
            for v in xs(bits as u32 * 977, 11) {
                ch.observe(Fa4::from_u32(v));
            }
            let cpu = ch.try_grind_cpu(bits);
            let got = p3_challenger::GrindingChallenger::try_grind(&mut ch.clone(), bits);
            assert_eq!(got, cpu, "bits {bits}");
            assert!(p3_challenger::GrindingChallenger::check_witness(&mut ch.clone(), bits, got.unwrap()));
        }
    }
}
