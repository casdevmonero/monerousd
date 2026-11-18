// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! Protocol: MonerousD — test harness (no consensus or wire effect).
//!
//! **THE DECODE-DOOR REPLAY (B1 (ii), 2026-10-22).** Every production decoder of outside bytes
//! (`crate::decode_doors`) driven in-process with the kept cargo-fuzz corpus, every recorded crash input, the real
//! pre-fork snapshot fixtures and seeded hostile bytes (random, mutations of a valid encoding — bit flips, inserts,
//! deletes, truncations, splices, a 2^32−1 varint length, zero runs, duplicated chunks — and the structural attacks:
//! 100k nested brackets, a 1 MiB number, a lone surrogate, an overflowing integer, a BOM, a NUL), each judged
//! FAIL-CLOSED: no panic (caught and named) and no input outliving its bound (a HANG — the worker is abandoned and
//! named, a fresh one takes the rest). A green door writes one `decode-fuzz` coverage row the hole scanner reads
//! (`holes::fuzz_driven_decode_doors`) to close every decode site that door stands behind, on the current source.
//!
//! REFUTATION BEFORE GREEN: `the_decode_door_replay_catches_a_planted_panic_and_a_planted_hang` plants a door that
//! trusts a length and panics, and a door that never answers, and requires both named.
//!
//! Stated limits: allocation is not measured here (the libFuzzer run carries `-rss_limit_mb` / `-malloc_limit_mb`);
//! a current-schema checkpoint that DECODES is the restart suite's pin (`persist::real_v27_fixture_tests`, the
//! journeys' restart census), this replay drives the refusal doors and the fixtures the repo holds.

use crate::decode_doors::{self, DOORS};
use crate::harness::fuzz::rng::Rng;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// A door under test: bytes in, nothing out — the judge watches for a panic or a hang, never a verdict.
pub(crate) type Door = Arc<dyn Fn(&[u8]) + Send + Sync + 'static>;

/// One input a door failed OPEN on.
pub(crate) struct Red {
    pub door: String,
    pub what: String,
    pub input: Vec<u8>,
}

/// Drive every input through `door` on a worker thread. A panic is caught and named; an input that outlives `bound` is a
/// HANG (the worker is abandoned, a fresh one takes the rest); a worker that dies is named. Returns the reds.
pub(crate) fn drive_inputs(name: &str, door: Door, inputs: &[Vec<u8>], bound: Duration) -> Vec<Red> {
    struct Worker {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Result<(), String>>,
    }
    fn spawn(door: Door) -> Worker {
        let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>();
        let (tx_out, rx_out) = mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            while let Ok(input) = rx_in.recv() {
                let r = catch_unwind(AssertUnwindSafe(|| door(&input))).map_err(|e| {
                    e.downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| e.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic (no message)".to_string())
                });
                if tx_out.send(r).is_err() {
                    return;
                }
            }
        });
        Worker { tx: tx_in, rx: rx_out }
    }
    let red = |what: String, input: &Vec<u8>| Red { door: name.to_string(), what, input: input.clone() };
    let mut w = spawn(door.clone());
    let mut reds = Vec::new();
    for input in inputs {
        if w.tx.send(input.clone()).is_err() {
            w = spawn(door.clone());
            let _ = w.tx.send(input.clone());
        }
        match w.rx.recv_timeout(bound) {
            Ok(Ok(())) => {}
            Ok(Err(p)) => reds.push(red(format!("PANIC: {p}"), input)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                reds.push(red(format!("HANG: no answer within {bound:?}"), input));
                w = spawn(door.clone());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                reds.push(red("WORKER DIED: the decode took the thread down (abort)".to_string(), input));
                w = spawn(door.clone());
            }
        }
    }
    reds
}

/// `n` random byte strings (mostly short, one in sixteen up to 64 KiB) and, when `valid` has an encoding to start from,
/// `n` mutants of one (one to four mutations each), plus the structural attacks. Deterministic in `seed`.
pub(crate) fn hostile_inputs(seed: u64, valid: &[Vec<u8>], n: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::with_capacity(2 * n + 16);
    for _ in 0..n {
        let len = match rng.below(16) {
            0 => 0,
            1 => 1 + rng.below(65_536),
            _ => rng.below(512),
        };
        out.push((0..len).map(|_| rng.next_u64() as u8).collect());
    }
    if !valid.is_empty() {
        for _ in 0..n {
            let mut b = valid[rng.below(valid.len())].clone();
            for _ in 0..1 + rng.below(4) {
                mutate(&mut rng, &mut b, valid);
            }
            out.push(b);
        }
    }
    out.extend(structural());
    out
}

fn mutate(rng: &mut Rng, b: &mut Vec<u8>, valid: &[Vec<u8>]) {
    match rng.below(9) {
        0 if !b.is_empty() => {
            let i = rng.below(b.len());
            b[i] ^= 1 << rng.below(8);
        }
        1 if !b.is_empty() => {
            let i = rng.below(b.len());
            b[i] = rng.next_u64() as u8;
        }
        2 => {
            let i = rng.below(b.len() + 1);
            b.insert(i, rng.next_u64() as u8);
        }
        3 if !b.is_empty() => {
            let i = rng.below(b.len());
            b.remove(i);
        }
        4 if !b.is_empty() => {
            let i = rng.below(b.len());
            b.truncate(i);
        }
        5 => {
            let o = &valid[rng.below(valid.len())];
            let i = rng.below(b.len() + 1);
            let j = rng.below(o.len() + 1);
            b.truncate(i);
            b.extend_from_slice(&o[j..]);
        }
        6 => {
            // a postcard varint length of 2^32 − 1 where a length was (or was not)
            let i = rng.below(b.len() + 1);
            for (k, v) in [0xffu8, 0xff, 0xff, 0xff, 0x0f].iter().enumerate() {
                b.insert(i + k, *v);
            }
        }
        7 if !b.is_empty() => {
            let i = rng.below(b.len());
            let j = i + rng.below(b.len() - i);
            let chunk = b[i..j].to_vec();
            let at = rng.below(b.len() + 1);
            let tail = b.split_off(at);
            b.extend_from_slice(&chunk);
            b.extend_from_slice(&tail);
        }
        _ if !b.is_empty() => {
            let i = rng.below(b.len());
            let j = i + rng.below(b.len() - i);
            for x in &mut b[i..j] {
                *x = 0;
            }
        }
        _ => {}
    }
}

fn structural() -> Vec<Vec<u8>> {
    vec![
        "[".repeat(100_000).into_bytes(),
        "{\"a\":".repeat(50_000).into_bytes(),
        b"1e400".to_vec(),
        "9".repeat(1 << 20).into_bytes(),
        b"\"\\ud800\"".to_vec(),
        b"{\"positions\":[{\"id\":18446744073709551616}]}".to_vec(),
        b"{\"from_height\":-1,\"by_ordinal\":true,\"positions\":[[]]}".to_vec(),
        b"\xef\xbb\xbf{}".to_vec(),
        b"{\"s\":\"\0\"}".to_vec(),
        vec![0xff; 4096],
        vec![0x80; 4096],
        vec![0; 1 << 16],
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
        vec![0x01, 0xff, 0xff, 0xff, 0xff, 0x0f],
    ]
}

fn dir_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir).ok().into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
    names.sort();
    names.iter().filter_map(|p| std::fs::read(p).ok()).collect()
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/persist_fixtures")
}

/// A valid encoding per door — the mutation base, and the seed corpus `write_the_seed_corpus_for_every_door` keeps.
pub(crate) fn valid_seeds(door: &str) -> Vec<Vec<u8>> {
    match door {
        decode_doors::JSON_VALUE => [
            "{}",
            "{\"positions\":[{\"id\":1,\"slot\":2},{\"id\":3}],\"by_ordinal\":true,\"from_height\":3}",
            "{\"positions\":[[1,2]],\"by_record_id\":true}",
            "{\"name\":\"alice\",\"address\":\"USDm1\",\"pow_stamp\":7}",
            "[1,2,3,\"x\",null,true,{\"k\":1.5e3}]",
            "\"\\u001f\\n\\t\\\\\\\"\\ud83d\\ude00\"",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect(),
        // the real pre-fork checkpoints: their first 8 KiB (the schema varint, the header, the first vectors) as bases
        decode_doors::SNAPSHOT_FILE => dir_files(&fixture_dir()).into_iter().map(|f| f[..f.len().min(8192)].to_vec()).collect(),
        decode_doors::NAME_REGISTRY_FILE => vec![format!(
            "{{\"alice\":{{\"address\":\"USDm1\",\"owner\":{},\"pubkey\":[1,2,3],\"sig\":[4,5]}},\"Bob\":{{\"address\":\"USDm2\",\"owner\":{}}}}}",
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]"
        )
        .into_bytes()],
        decode_doors::TOR_GUARDS_DOC => vec![
            b"{\"default\":{\"guards\":[{\"disabled\":null},{\"disabled\":{\"since\":1}},{}]},\"restricted\":{\"guards\":[]}}".to_vec(),
            b"{\"default\":{\"guards\":[{\"disabled\":1},{\"disabled\":2}]}}".to_vec(),
        ],
        decode_doors::COMPRESSED_COPATH_VEC => {
            use crate::nf_sparse::CompressedCopath;
            use crate::spend_frontier::Digest4;
            let full = CompressedCopath { present: [0xff; 32], siblings: vec![Digest4::default(); 32], terminal: Some(Digest4::default()) };
            let empty = CompressedCopath { present: [0; 32], siblings: vec![], terminal: None };
            vec![
                postcard::to_allocvec(&vec![full.clone(), empty.clone()]).expect("encode"),
                postcard::to_allocvec(&vec![empty]).expect("encode"),
                postcard::to_allocvec(&vec![full; 4]).expect("encode"),
            ]
        }
        // a Bisq body and a Haveno body, each one a price both conventions' readers walk (the mutator grows the rest)
        decode_doors::PRICE_RELAY_ANSWER => [
            "{\"data\":[{\"currencyCode\":\"USD\",\"price\":65000.5,\"timestampSec\":1730419200},{\"currencyCode\":\"XMR\",\"price\":0.0025,\"timestampSec\":1730419190}]}",
            "{\"data\":[{\"baseCurrencyCode\":\"XMR\",\"counterCurrencyCode\":\"USD\",\"price\":162.4,\"timestampMs\":1730419200000},{\"baseCurrencyCode\":\"BTC\",\"counterCurrencyCode\":\"XMR\",\"price\":400.0,\"timestampMs\":1730419199000.0}]}",
            "{\"data\":[]}",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect(),
        _ => vec![],
    }
}

fn door_salt(door: &str) -> u64 {
    door.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

fn corpus_dir(door: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus").join(door.replace('-', "_"))
}

fn artifacts_dir(door: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/artifacts").join(door.replace('-', "_"))
}

/// ⭐ THE REPLAY (farm-listed, `SIM_SEED`): every door, the kept corpus + every crash artifact + the real fixtures + 1,500
/// random and 1,500 mutant inputs per door, fail-closed; one `decode-fuzz` coverage row per green door.
#[test]
fn every_decode_door_of_outside_bytes_fails_closed_on_the_corpus_and_seeded_hostile_bytes() {
    let seed = crate::harness::netsim::journey::seed(0xDEC0DE);
    let eco = crate::harness::surface_census::ecosystem();
    let sites = crate::harness::surface_census::decode_sites(&eco);
    let mut undriven = 0usize;
    for s in &sites {
        match s.door {
            Some(d) if DOORS.contains(&d) => eprintln!("[decode-fuzz] site {} (type `{}`) → door `{d}`", s.at, s.ty),
            _ => {
                undriven += 1;
                eprintln!("[decode-fuzz] UNDRIVEN site {} (type `{}`) — no door of decode_doors maps it; its hole stays open", s.at, s.ty);
            }
        }
    }
    crate::harness::sim_coverage::start();
    let mut reds = Vec::new();
    let t0 = Instant::now();
    for door in DOORS {
        assert!(decode_doors::drive(door, b"{}").is_some(), "door `{door}` is listed but `drive` does not serve it");
        let mut inputs = dir_files(&corpus_dir(door));
        let n_corpus = inputs.len();
        inputs.extend(dir_files(&artifacts_dir(door)));
        let n_art = inputs.len() - n_corpus;
        if *door == decode_doors::SNAPSHOT_FILE {
            inputs.extend(dir_files(&fixture_dir()));
        }
        let n_fix = inputs.len() - n_corpus - n_art;
        let valid = valid_seeds(door);
        inputs.extend(hostile_inputs(seed ^ door_salt(door), &valid, 1500));
        let d: &'static str = door;
        let f: Door = Arc::new(move |b: &[u8]| {
            std::hint::black_box(decode_doors::drive(d, b));
        });
        let t = Instant::now();
        let r = drive_inputs(door, f, &inputs, Duration::from_secs(5));
        eprintln!(
            "[decode-fuzz] door `{door}`: {} input(s) ({n_corpus} corpus · {n_art} crash artifact(s) · {n_fix} fixture(s) · {} seeded) · {} red · {:.1} s",
            inputs.len(),
            inputs.len() - n_corpus - n_art - n_fix,
            r.len(),
            t.elapsed().as_secs_f64()
        );
        if r.is_empty() {
            crate::harness::sim_coverage::note("decode-door", door);
        }
        reds.extend(r);
    }
    let rows = crate::harness::sim_coverage::finish("decode-fuzz");
    for (i, r) in reds.iter().enumerate() {
        let p = crate::harness::scratchpad_dir().join(format!("verify/decode-fuzz-red-{}-{i}.bin", r.door));
        let _ = std::fs::write(&p, &r.input);
        eprintln!("[decode-fuzz] RED door `{}` — {} ({} B, written {})", r.door, r.what, r.input.len(), p.display());
    }
    eprintln!(
        "[decode-fuzz] {} door(s) · {} site(s) ({undriven} undriven) · {rows} coverage row(s) · {} red · seed {seed:#x} · {:.1} s",
        DOORS.len(),
        sites.len(),
        reds.len(),
        t0.elapsed().as_secs_f64()
    );
    assert!(
        reds.is_empty(),
        "{} decode door(s) failed OPEN under hostile bytes (SIM_SEED={seed:#x}): {:?}",
        reds.len(),
        reds.iter().map(|r| format!("{} {}", r.door, r.what)).collect::<Vec<_>>()
    );
}

/// REFUTATION BEFORE GREEN: a door that trusts a length and panics, and a door that never answers, are both NAMED; a
/// sound door drives the same inputs with zero reds.
#[test]
fn the_decode_door_replay_catches_a_planted_panic_and_a_planted_hang() {
    let inputs = hostile_inputs(7, &[b"{}".to_vec(), b"[1,2]".to_vec()], 60);
    let planted_panic: Door = Arc::new(|b: &[u8]| {
        if b.len() % 5 == 1 {
            let claimed = usize::from(b[0]) * 1024;
            panic!("planted: trusted a length prefix of {claimed} over {} bytes", b.len());
        }
    });
    let reds = drive_inputs("planted-panic", planted_panic, &inputs, Duration::from_secs(1));
    assert!(
        reds.iter().any(|r| r.what.contains("PANIC") && r.what.contains("planted: trusted a length prefix")),
        "the replay did not name the planted panic: {:?}",
        reds.iter().map(|r| r.what.clone()).collect::<Vec<_>>()
    );
    let n_hit = inputs.iter().filter(|b| b.len() % 5 == 1).count();
    assert_eq!(reds.len(), n_hit, "every planted-panic input is one red, nothing else is");

    static STOP: AtomicBool = AtomicBool::new(false);
    let mut one = false;
    let hang_inputs: Vec<Vec<u8>> = inputs
        .iter()
        .filter(|b| {
            if b.len() % 5 == 2 {
                if one {
                    return false;
                }
                one = true;
            }
            true
        })
        .cloned()
        .collect();
    assert!(one, "the inputs hold one hanging shape");
    let planted_hang: Door = Arc::new(|b: &[u8]| {
        if b.len() % 5 == 2 {
            while !STOP.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    });
    let reds = drive_inputs("planted-hang", planted_hang, &hang_inputs, Duration::from_secs(1));
    STOP.store(true, Ordering::Relaxed);
    assert_eq!(reds.len(), 1, "exactly the hanging input is named: {:?}", reds.iter().map(|r| r.what.clone()).collect::<Vec<_>>());
    assert!(reds[0].what.contains("HANG"), "{}", reds[0].what);
    assert_eq!(reds[0].input.len() % 5, 2, "the red carries the input that hung");

    let sound: Door = Arc::new(|b: &[u8]| {
        std::hint::black_box(decode_doors::drive(decode_doors::JSON_VALUE, b));
    });
    let reds = drive_inputs("sound", sound, &inputs, Duration::from_secs(5));
    assert!(reds.is_empty(), "a sound door has no red: {:?}", reds.iter().map(|r| r.what.clone()).collect::<Vec<_>>());
}

/// Writes the kept seed corpus (`fuzz/corpus/<door>/seed-NN`) from `valid_seeds` — run once, commit the files.
#[test]
#[ignore = "writes the kept seed corpus under fuzz/corpus/<door>/ — run once, commit the files"]
fn write_the_seed_corpus_for_every_door() {
    for door in DOORS {
        let dir = corpus_dir(door);
        std::fs::create_dir_all(&dir).expect("corpus dir");
        for (i, s) in valid_seeds(door).iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i:02}")), s).expect("seed");
        }
        eprintln!("[decode-fuzz] seed corpus `{door}` → {}", dir.display());
    }
}
