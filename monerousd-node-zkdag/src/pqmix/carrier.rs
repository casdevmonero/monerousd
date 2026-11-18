// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! What a link runs on. User 2026-11-07: *"it must be original not based on another provider who may go down"*, and *"why cant
//! we have our own hidden addresses that an ip cannot be found from"*. `docs/MONEROUSD-NATIVE-NETWORK-SPEC-20261107.md`.
//!
//! A link is a direct connection between two of our own nodes, with nothing else in between:
//! - [`CarrierAddr::Relay`]: the reachable address of a relay face. Only a node that chose to accept inbound links has one. It
//!   names that relay face and never a hidden address, and it is the one place on this layer an internet address exists.
//! - [`CarrierAddr::Unix`]: a filesystem path, for nodes on one machine. A public node refuses these (`view.rs`).
//!
//! A node that dials proves nothing about itself (`link.rs`), so the machine it dials learns an IP and a one-time key, and never
//! which hidden address that IP holds. A census pin below refuses an internet socket anywhere else in `src/pqmix/`.

use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

const KIND_RELAY: u8 = 1;
const KIND_UNIX: u8 = 2;
const KIND_VIA: u8 = 3;
const RELAY_MAX: usize = 64;
const UNIX_MAX: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CarrierAddr {
    Relay(String),
    Unix(String),
    /// ⭐ O5 (lane af57, 2026-11-16; user: "if we have 500 nodes on tor then we should have 500 relays automatically … make sure
    /// users ips arent exposed and able to be linked"): a node with no relay face is a hop THROUGH the relay it dials, named by that
    /// relay's id. A packet for it goes to the gateway, which forwards it down the node's own link. It names no address: only the
    /// gateway, which already sees the node's IP as its first hop, learns where the hop is. Never dialled.
    Via([u8; 32]),
}

fn is_relay_addr(s: &str) -> bool {
    s.len() <= RELAY_MAX && s.parse::<std::net::SocketAddr>().is_ok_and(|a| a.port() != 0)
}

fn is_unix_path(s: &str) -> bool {
    s.len() <= UNIX_MAX && s.starts_with('/') && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
}

impl CarrierAddr {
    /// `relay:<address>:<port>` or `unix:<path>`, the form seeds are written in. A bare address is refused: nothing on this layer
    /// is an address without saying it is a relay's.
    pub fn parse(text: &str) -> Option<CarrierAddr> {
        if let Some(a) = text.strip_prefix("relay:") {
            return is_relay_addr(a).then(|| CarrierAddr::Relay(a.to_string()));
        }
        if let Some(p) = text.strip_prefix("unix:") {
            return is_unix_path(p).then(|| CarrierAddr::Unix(p.to_string()));
        }
        None
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let (kind, body): (u8, &[u8]) = match self {
            CarrierAddr::Relay(a) => (KIND_RELAY, a.as_bytes()),
            CarrierAddr::Unix(p) => (KIND_UNIX, p.as_bytes()),
            CarrierAddr::Via(g) => (KIND_VIA, &g[..]),
        };
        out.push(kind);
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
    }

    pub fn decode(kind: u8, body: &[u8]) -> Option<CarrierAddr> {
        if kind == KIND_VIA {
            return <[u8; 32]>::try_from(body).ok().map(CarrierAddr::Via);
        }
        let s = std::str::from_utf8(body).ok()?;
        match kind {
            KIND_RELAY if is_relay_addr(s) => Some(CarrierAddr::Relay(s.to_string())),
            KIND_UNIX if is_unix_path(s) => Some(CarrierAddr::Unix(s.to_string())),
            _ => None,
        }
    }

    /// Whether this carrier can be dialled (a relay face or a local path). A `Via` hop is reached only through its gateway.
    pub fn dialable(&self) -> bool {
        !matches!(self, CarrierAddr::Via(_))
    }
}

pub trait CarrierStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> CarrierStream for T {}
pub type BoxStream = Box<dyn CarrierStream>;

/// Dials one carrier address. `None` means this node has no way to reach it, or the attempt failed.
pub async fn dial(addr: &CarrierAddr, own_unix: Option<&PathBuf>) -> Option<BoxStream> {
    match addr {
        CarrierAddr::Relay(a) => {
            let target = a.parse::<std::net::SocketAddr>().ok()?;
            let s = tokio::net::TcpStream::connect(target).await.ok()?;
            // A frame is sent whole, and waiting to fill a segment would only add delay.
            s.set_nodelay(true).ok()?;
            Some(Box::new(s))
        }
        CarrierAddr::Unix(p) => {
            own_unix?;
            let s = tokio::net::UnixStream::connect(p).await.ok()?;
            Some(Box::new(s))
        }
        CarrierAddr::Via(_) => None, // a hop through its gateway is never dialled
    }
}

/// Answers inbound links on a relay face. The peer's address goes no further than this function: a link has no field for it, it is
/// never logged or stored, and nothing above can read it.
pub async fn relay_accept_loop<F>(addr: &str, mut on_stream: F)
where
    F: FnMut(BoxStream),
{
    let Ok(target) = addr.parse::<std::net::SocketAddr>() else {
        eprintln!("[mix] the relay face's address did not parse");
        return;
    };
    let Ok(listener) = tokio::net::TcpListener::bind(target).await else {
        eprintln!("[mix] could not open the relay face");
        return;
    };
    loop {
        match listener.accept().await {
            Ok((stream, _dropped_on_purpose)) => {
                if stream.set_nodelay(true).is_ok() {
                    on_stream(Box::new(stream));
                }
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

/// A state folder path, kept here so the module's one filesystem shape stays with its one socket shape.
pub fn path_text(p: &Path) -> Option<&str> {
    p.to_str()
}

// TWO-PARTY-REVIEWED: parsing has no second side. The carriers themselves cross between real processes in `mix_cut.py`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_only_ever_a_relays_and_says_so() {
        for bad in [
            "1.2.3.4:5",
            "[::1]:5",
            "127.0.0.1:7656",
            "example.com:443",
            "relay:example.com:443",
            "relay:1.2.3.4",
            "relay:1.2.3.4:0",
            "unix:1.2.3.4:5",
            "tcp:1.2.3.4:5",
            "i2p:AAAA",
            "onion:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        ] {
            assert_eq!(CarrierAddr::parse(bad), None, "{bad} was accepted as a carrier address");
        }
        assert_eq!(CarrierAddr::decode(KIND_RELAY, b"not an address"), None);
        assert_eq!(CarrierAddr::decode(KIND_UNIX, b"1.2.3.4:5"), None);
        assert_eq!(CarrierAddr::decode(9, b"1.2.3.4:5"), None, "an unknown kind is refused, so a new one cannot slip in");
    }

    #[test]
    fn real_shaped_addresses_round_trip() {
        for a in [CarrierAddr::Relay("192.0.2.1:9443".into()), CarrierAddr::Unix("/tmp/node-0.sock".into())] {
            let mut b = Vec::new();
            a.encode_into(&mut b);
            assert_eq!(CarrierAddr::decode(b[0], &b[3..]).unwrap(), a);
        }
        assert_eq!(CarrierAddr::parse("relay:192.0.2.1:9443"), Some(CarrierAddr::Relay("192.0.2.1:9443".into())));
    }

    /// The census: an internet socket exists only in this file, and no file on the layer can hold a peer's address taken from a
    /// socket. A new one in `src/pqmix/` turns this red.
    #[test]
    fn only_this_file_touches_an_internet_socket_and_nothing_reads_a_peers_address() {
        const FORBIDDEN: [&str; 5] = ["IpAddr", "Ipv4Addr", "Ipv6Addr", "peer_addr", "to_socket_addrs"];
        const FORBIDDEN_EXCEPT_CARRIER: [&str; 4] = ["SocketAddr", "TcpStream", "TcpListener", "UdpSocket"];
        let files = [
            ("packet.rs", include_str!("packet.rs")),
            ("record.rs", include_str!("record.rs")),
            ("view.rs", include_str!("view.rs")),
            ("link.rs", include_str!("link.rs")),
            ("runtime.rs", include_str!("runtime.rs")),
            ("mod.rs", include_str!("mod.rs")),
            ("replay.rs", include_str!("replay.rs")),
            ("rng.rs", include_str!("rng.rs")),
            ("carrier.rs", include_str!("carrier.rs")),
        ];
        for (name, src) in files {
            let code = match src.find("#[cfg(test)]") {
                Some(at) => &src[..at],
                None => src,
            };
            for word in FORBIDDEN {
                assert!(!code.contains(word), "{name} names {word}");
            }
            if name != "carrier.rs" {
                for word in FORBIDDEN_EXCEPT_CARRIER {
                    assert!(!code.contains(word), "{name} names {word}, which only the carrier may");
                }
            }
        }
    }
}
