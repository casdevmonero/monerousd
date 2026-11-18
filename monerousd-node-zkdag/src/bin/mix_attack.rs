// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Attacks a running node's mix layer as a real neighbour would: its own identity, its own real link, real packets built for the
//! node's real key. Run by `scratchpad/net/mix_attacks.py`, which reads the running node's own counters before and after, and passes
//! only on the refusal the node itself recorded.
//!
//! Usage: mix_attack <victim socket path> <replay|tag|forged-header|forged-record|ip-record>

use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use usdmd_node::pqmix::carrier::CarrierAddr;
use usdmd_node::pqmix::link::{self, LinkKeys};
use usdmd_node::pqmix::packet::{self, Hop, HEADER};
use usdmd_node::pqmix::record::{self, epoch_now, Identity, Record};
use usdmd_node::pqmix::rng::Rng;
use usdmd_node::pqmix::runtime::now_ms;

const F_PACKET: u8 = 1;
const F_RECORD: u8 = 2;

async fn send(s: &mut tokio::net::UnixStream, keys: &mut LinkKeys, kind: u8, body: &[u8], rng: &mut Rng) {
    let frame = link::seal(keys, kind, body, rng).expect("a frame fits");
    s.write_all(&frame).await.expect("the victim closed the link");
    s.flush().await.expect("the victim closed the link");
}

/// Reads frames until the victim's own record arrives, which it sends first on every new link.
async fn victim_record(s: &mut tokio::net::UnixStream, keys: &mut LinkKeys, victim: [u8; 32]) -> Record {
    let mut wire = vec![0u8; link::FRAME_WIRE];
    loop {
        s.read_exact(&mut wire).await.expect("the victim closed the link before its record");
        let (kind, body) = link::open(keys, &wire).expect("a frame from the victim opens");
        if kind == F_RECORD {
            if let Ok(r) = record::verify_record(&body, Some(epoch_now(now_ms()))) {
                if record::id_of(&r.dsa_pk) == victim {
                    return r;
                }
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (path, what) = (&args[1], args[2].as_str());
    let dir: PathBuf = std::env::temp_dir().join(format!("mix-attacker-{}", std::process::id()));
    let id = Identity::load_or_mint(&dir);
    let mut rng = Rng::new();
    let mut s = tokio::net::UnixStream::connect(path).await.expect("the victim is not listening");
    let (victim, mut keys) = link::initiate(&mut s, None).await.expect("the handshake failed");
    let vr = victim_record(&mut s, &mut keys, victim).await;
    // Every hop is the victim, so the node's own counters see every step and no other node is involved.
    let route: Vec<Hop> = (0..packet::HOPS).map(|_| Hop { id: victim, kem_pk: vr.kem_pk.clone(), delay_ms: 1 }).collect();
    let pkt = packet::build(&route, &[0, 0, 0], &mut rng).expect("a route of the right length builds");
    match what {
        "replay" => {
            send(&mut s, &mut keys, F_PACKET, &pkt, &mut rng).await;
            send(&mut s, &mut keys, F_PACKET, &pkt, &mut rng).await;
        }
        "tag" => {
            let mut bad = pkt.clone();
            bad[HEADER + 100] ^= 1;
            send(&mut s, &mut keys, F_PACKET, &bad, &mut rng).await;
        }
        "forged-header" => {
            let mut bad = pkt.clone();
            bad[packet::KEM_CT + packet::MAC + 5] ^= 1;
            send(&mut s, &mut keys, F_PACKET, &bad, &mut rng).await;
        }
        "forged-record" => {
            let epoch = epoch_now(now_ms());
            let (kem_pk, _) = packet::kem_keypair();
            let r = Record {
                dsa_pk: id.dsa_pk.clone(),
                epoch,
                kem_pk,
                carriers: vec![CarrierAddr::Unix("/tmp/attacker.sock".into())],
                seq: now_ms() / 1000,
                pow_nonce: id.pow_nonce,
                epoch_nonce: record::mine_epoch_work(&id.dsa_pk, epoch),
            };
            let mut raw = record::encode_signed(&r, &id.dsa_sk).expect("signs");
            let last = raw.len() - 1;
            raw[last] ^= 1; // a signature that does not verify
            send(&mut s, &mut keys, F_RECORD, &raw, &mut rng).await;
        }
        "unknown-frame" => {
            // A frame kind this version does not know, as a newer node might send: ignored, and the link stays up.
            send(&mut s, &mut keys, 200, b"from the future", &mut rng).await;
        }
        "ip-record" => {
            // A correctly signed record, with real work, naming an IP where an address goes. Encoded by hand: the code has no
            // type that can hold one, which is the point.
            let epoch = epoch_now(now_ms());
            let (kem_pk, _) = packet::kem_keypair();
            let mut m = Vec::new();
            m.extend_from_slice(b"monerousd mix v1 record");
            m.extend_from_slice(&id.dsa_pk);
            m.extend_from_slice(&epoch.to_le_bytes());
            m.extend_from_slice(&kem_pk);
            m.push(1);
            let ip = b"203.0.113.7:29200";
            m.push(1);
            m.extend_from_slice(&(ip.len() as u16).to_le_bytes());
            m.extend_from_slice(ip);
            m.extend_from_slice(&(now_ms() / 1000).to_le_bytes());
            m.extend_from_slice(&id.pow_nonce.to_le_bytes());
            m.extend_from_slice(&record::mine_epoch_work(&id.dsa_pk, epoch).to_le_bytes());
            let sig = usdmd_node::pqauth::ml_dsa_sign(&m, &id.dsa_sk).expect("signs");
            m.extend_from_slice(&sig);
            send(&mut s, &mut keys, F_RECORD, &m, &mut rng).await;
        }
        _ => panic!("unknown attack"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    if std::fs::remove_dir_all(&dir).is_err() {
        eprintln!("[mix-attack] the attacker's temporary identity folder was already gone");
    }
    println!("[mix-attack] sent {what}");
}
