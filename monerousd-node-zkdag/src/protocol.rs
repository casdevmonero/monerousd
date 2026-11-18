// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The peer wire protocol: the messages that flow between nodes over the onion transport.
//!
//! This is the greenfield replacement for the levin command set — there is NO block-by-block
//! "SYNCHRONIZATION" request here. A joining / behind node's ONLY sync path is [`WireMsg::SyncRequest`]
//! → a synced peer replies [`WireMsg::SyncResponse`] carrying the ≤1.8MB #29 DSYNC bundle, which the
//! joiner verifies once and adopts (jump to tip). Block / tx gossip carry already-serialized payloads
//! (the [`crate::net`] layer frames each message into fixed-size onion cells; a >1-cell payload like a
//! decider bundle is chunked by the transport).
//!
//! Every message is postcard-encoded; a corrupt / truncated / unknown frame decodes to `None`
//! (fail-closed) so a peer can never drive a node with a malformed command.

use serde::{Deserialize, Serialize};

/// A message on the peer wire. Payload-carrying variants hold already-serialized bytes so this enum
/// stays self-contained (the block/tx types serialize themselves at the gossip layer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMsg {
    /// Gossip a produced block (postcard-serialized `Block`).
    Block(Vec<u8>),
    /// Gossip a PQ transaction (postcard-serialized `PqTx`).
    Tx(Vec<u8>),
    /// Gossip a sovereign SITE publish so EVERY node serves the same content and agrees on the site root
    /// (bidirectional hosting — a site is chain-anchored state, replicated like a block, never single-node).
    /// Payload = postcard-serialized [`crate::site::SiteGossip`] (the SitePublish + owner pubkey + PQ sig);
    /// a receiver verifies the signature before adopting, then re-gossips a freshly-adopted version.
    Site(Vec<u8>),
    /// Gossip a bonded-validator FINALITY VOTE so votes flow bidirectionally across the set and every
    /// validator can independently tally the ≥2/3 quorum (no vote sink, no single point). Payload =
    /// postcard-serialized [`crate::validator::VoteGossip`] (block id + height + voter pubkey + PQ sig).
    Vote(Vec<u8>),
    /// Gossip a `@username` REGISTRATION so the name directory CONVERGES across the mesh — a @name is public
    /// directory state, replicated like a site, never single-node (the bidirectional-replication law). Payload =
    /// postcard-serialized [`crate::names::NameGossip`] (name + address + owner pubkey + PQ sig over
    /// `name_register_msg`); a receiver VERIFIES the ML-DSA signature + the first-come/owner rule before adopting,
    /// then re-gossips a freshly-adopted registration so every node resolves the same @name → address.
    Name(Vec<u8>),
    /// ⭐ DA NOTE BACKFILL — request: `from(u64 LE) ‖ count(u32 LE)`. A node whose CONSENSUS state jumped via a
    /// certified DSYNC adopt has a perfect tip and NO note data for the blocks it leapt over, so its owner's
    /// wallet can never find a payment that settled in them. Consensus stays O(1); the note stream converges
    /// AFTER, in bounded pages, over this request. PRIVACY: the range is a chain-progress interval every node
    /// already publishes as its height — it names no note, address, amount or owner, and every peer answering
    /// it returns the SAME bytes to anyone, so it is selector-independent (no which-item query).
    NotesReq(Vec<u8>),
    /// DA NOTE BACKFILL — response: repeated `seq(u64 LE) ‖ len(u32 LE) ‖ note bytes`.
    NotesResp(Vec<u8>),
    /// ⭐ MISSING-TX REQUEST — payload: exactly [`TX_REQ_FIXED_COUNT`] × 32-byte tx ids.
    ///
    /// A block gossips as ids; its transactions gossip separately. So a node routinely holds a block whose
    /// txs it never received — it missed the gossip, restarted, or evicted them — and until now it had NO WAY
    /// TO ASK. That is not cosmetic: a block's nullifier decoy seed is derived from its nullifier-bearing
    /// txs' confidential blobs, so a node without them derives the wrong seed, its fold cannot reach the
    /// producer's proven post-root, and the block never folds. `nf_fold_seq` then falls permanently behind
    /// `served_seq`, and since wallets fold the served stream to its END, every spender ends up naming an
    /// endpoint the node never held and EVERY SEND IS REFUSED. Measured on a live pair: the gap grew 7 -> 103
    /// -> 213 and kept going.
    ///
    /// This is the message Bitcoin and Kaspa have as `getblocktxn`: a node that cannot complete a block asks
    /// for the bodies it is missing, so a block is never left unapplied merely because nobody offered it.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: tx ids ONLY, and the request is COVER-PADDED to a CONSTANT count, so it
    /// carries no real-count signal — a node missing one tx and a node missing thirty send byte-identical
    /// shapes. The ids themselves are already public: they are listed in the block every peer holds. It names
    /// no note, amount, key, address or owner, and asks no which-item question about ownership.
    TxReq(Vec<u8>),
    /// MISSING-FOLD-INPUT response: repeated `pre_root(32) ‖ n_real(u32 LE) ‖ n_real×32 ‖ conf_len(u32 LE) ‖
    /// conf bytes`. Self-verifying — the receiver regenerates the padded set and the block's carried fold must
    /// reach its own committed post-root, so a wrong answer advances nothing.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the same bytes every node stored for that block, identical for every
    /// requester (selector-independent). Nullifiers here are the block's already-settled public set.
    TxResp(Vec<u8>),
    /// ACCOUNT-BUCKET request: exactly [`TX_REQ_FIXED_COUNT`] x 32-byte bucket ids.
    ///
    /// A recipient's wallet finds its note through its account bucket; if its node holds no entries for that
    /// bucket it learns nothing, never names an ordinal, and the targeted record fetch never fires. This is
    /// how a node goes and gets the bucket instead of waiting for a stream walk that never arrives.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a bucket id identifies an ACCOUNT, so it is a which-item selector and
    /// never travels alone. The set is CONSTANT-width and padded with decoys seeded on the requester's own
    /// secret, so an observer cannot tell which id is real, how many are, or whether any are.
    BucketReq(Vec<u8>),
    /// ACCOUNT-BUCKET response: repeated `bucket(32) | n(u32 LE) | n x (len(u32 LE) | entry bytes)`.
    /// Self-verifying downstream: an entry is a note record the wallet must still decapsulate and prove it
    /// owns, so a forged entry fails there and nothing here is trusted.
    BucketResp(Vec<u8>),
    /// Gossip a CLUE-KEY registration so the OMR clue directory CONVERGES across the mesh — a sender on ANY node
    /// can resolve a recipient's PUBLIC clue key to attach an oblivious-detection clue (cold-restore works
    /// mesh-wide, not only on the node the recipient published to). Payload = postcard-serialized
    /// [`crate::clue_registry::ClueGossip`] (owner pubkey + clue key + PQ sig over `clue_register_msg`); a receiver
    /// VERIFIES the ML-DSA signature (owner-keyed) before adopting, then re-gossips ONLY a freshly-changed one.
    Clue(Vec<u8>),
    /// ⛔ RETIRED (DB-330): the per-note clue gossip lane. It let any peer file a clue for any cm, first-writer-wins —
    /// a free way to pre-empt a note owner's locator hint. Nothing sends it; a receiver DROPS it. A per-note clue now
    /// travels only inside the transaction that carries the note. The variant stays so every later discriminant
    /// keeps its wire value.
    NoteClue(Vec<u8>),
    /// Gossip a PEER record so the peer directory CONVERGES across the mesh — a node's own dialable identity
    /// (`peer_id | /dns/<onion>/tcp/<port> | Noise x_pk | ML-KEM ek`) is public directory state that must
    /// replicate like a @name, so EVERY node learns EVERY peer and re-dials whoever is alive. This is what makes
    /// "any node on any device auto-joins the mesh" true WITHOUT a single bootstrap node: after one successful
    /// join, a node's persisted + gossiped peer set lets it re-peer to survivors on restart (the pinned seed is
    /// pure first-contact redundancy, never a dependency — no single point of failure). Payload = postcard-
    /// serialized [`crate::peer_directory::PeerGossip`] (record + announcer ML-DSA pubkey + sig over
    /// `peer_record_msg`). A receiver VERIFIES the self-signature + onion-only multiaddr + newer-`seq`-wins rule
    /// before adopting, then re-gossips ONLY a freshly-adopted record (dedup, loop-free). A forged record cannot
    /// eclipse-redirect: the Noise handshake proves `peer_id` at dial (see the module docs). Never gates block
    /// flow (peer records are optional directory state, like a site/name).
    Peer(Vec<u8>),
    /// Gossip a GOVERNANCE record (an open proposal or a bicameral vote) so the governance directory CONVERGES
    /// across the mesh — open proposals and their ≥2/3-of-both-chambers vote tallies are chain-anchored consensus
    /// state a validator on ANY node must see + independently tally, never a single-node island. Payload =
    /// postcard-serialized [`crate::governance::GovernGossip`]. A `Vote` re-runs the SAME authenticated adopt
    /// (verify the voter's ML-DSA sig over `governance_vote_msg(id,2)` → voter id = H(pubkey) → credit the LIVE
    /// bonded weight) before recording, so no peer can cast another's vote or inflate weight; a `ProposalOpen`
    /// is idempotent by id. A receiver re-gossips ONLY a freshly-opened proposal / a tally-changing vote (dedup,
    /// loop-free). Never gates block flow (governance is optional overlay state, like a site/name).
    Govern(Vec<u8>),
    /// #29 DSYNC request: "I am joining / behind — serve me your decider sync bundle." Parameterless
    /// (a node serves its current tip); it never asks for a height range or a block-by-block stream.
    SyncRequest,
    /// #29 DSYNC response: the wire-serialized [`crate::sync::SyncBundle`] (`SyncBundle::to_wire`).
    SyncResponse(Vec<u8>),
    /// BEACON-ADOPT convergence (the novel private-DAG fork choice — user 2026-07-14): a constant-rate,
    /// UNTRUSTED tip hint `(genesis_commit, tip, blue_work, blue_score)` (postcard [`TipBeaconBody`]) every
    /// node emits on the cover cadence. A receiver whose own selected tip has STRICTLY LESS `blue_work` AND
    /// an IDENTICAL `genesis_commit` fires ONE throttled #29 DSYNC request and adopts the peer's tip via the
    /// verify-once ≤1.8MB decider bundle — the decider proof attests the WHOLE chain to that tip is sound
    /// (no-inflation, every transition valid) = "correct", and `blue_work` decides "longest". The beacon is
    /// ONLY a hint: a forged/lying beacon can never cause an adopt (the decider verify is the gate), it can
    /// at worst trigger a throttled DSYNC that fails to verify → dropped. This REPLACES the classical
    /// block-by-block orphan-parent backfill (deleted): a behind node never crawls history, it jumps to the
    /// heaviest VERIFIED tip in one O(1) verify — deterministic total order over `(blue_work, id)` ⇒ no
    /// chain split can persist beyond one beacon interval.
    TipBeacon(Vec<u8>),
    /// HF44 L2 SETTLEMENT carrier (the VISA-class throughput lane): a gossiped [`crate::settlement::
    /// SettlementBundle`] (postcard bytes) that settles a whole BATCH of L2 txs under one ≤1.8MB O(1)-verify
    /// proof. A receiving node VERIFIES it against its CURRENT L2 root (state-root-chained, anti-replay) and,
    /// if it applies (advances the root), RE-GOSSIPS it so every node converges on the same L2 state — the
    /// bidirectional-replication law for settlement state. A stale/duplicate/invalid bundle does not apply,
    /// so it is not re-sent (natural dedup: once the root advances, the same bundle's `prev` no longer matches).
    /// Optional per block — its absence NEVER stops block flow (liveness).
    Settlement(Vec<u8>),
    /// ⭐ CHUNK RE-REQUEST — closes the measured loss class where ONE dropped cell killed a multi-cell
    /// message FOREVER (2026-08-18: payload block 6bfac5d4/505741b9 SENT on H, receiver I stuck at
    /// "chunk 4/6 arrived, still missing [5]" for good; 56/56 single-cell empties arrived while every
    /// payload block died — no retransmit existed anywhere). Payload = msg_id(u64 LE) ‖ missing seqs
    /// (u16 LE each). Appended LAST so every earlier variant keeps its postcard index (wire compat);
    /// an old node decodes this as None and drops it fail-closed.
    /// PRIVACY: rides the same constant-rate cell cover as every message; msg_id is a transport-layer
    /// content hash, never a tx/note identity; the request names cell indexes, not items.
    ChunkReq(Vec<u8>),
    /// ⭐ TRANSPORT DELIVERY ACK for a fully-assembled Block message — payload = the 32-byte block id.
    /// MEASURED 2026-08-19 on the live pair: the sender's only "delivered" signal was the peer's DAG
    /// carrying the block ID, which a DSYNC tip adopt satisfies WITHOUT the payload — so the re-offer
    /// engine cleared every pending payment block while the recipient held id-only state and the
    /// targets never arrived (three sends, three cleared, zero re-offers, recipient at 0.0). Sent by
    /// the receiver the moment a gossiped Block message DECODES (assembly complete = transport done —
    /// consensus validity stays a separate gate); the sender re-offers until THIS arrives, never until
    /// a tip hint. Appended LAST so every earlier variant keeps its postcard index (wire compat); an
    /// old node decodes this as None and drops it fail-closed.
    /// PRIVACY: a block id — public chain structure already gossiped in the clear on this same lane.
    BlockAck(Vec<u8>),
    /// Ask a peer for one sealed LADDER span record by span index (u64 LE). Appended variant —
    /// wire-compatible with older peers exactly like BlockAck (unknown variants are ignored).
    LadderReq(Vec<u8>),
    /// A ladder span record: span index (u64 LE) ‖ the span's roots blob. Adopted ONLY when it
    /// folds rung-acc to rung-acc on the receiver (`adopt_ladder_span`) — self-verifying.
    LadderResp(Vec<u8>),
    /// ⭐ LETTER — one OPAQUE end-to-end-sealed private message (Letter messenger). The relay is
    /// metadata-blind: this blob is `kem_ct ‖ nonce ‖ tag ‖ ciphertext` (ML-KEM-768 + blake3 AEAD),
    /// sealed WALLET-SIDE to the recipient; no node ever holds a Letter key. A node that receives a NEW
    /// blob adds it to its constant-cover relay ring and re-gossips it ONCE (dedup by content), so a letter
    /// reaches its recipient on ANY node while an observer counting the wire learns nothing (real letters are
    /// indistinguishable from cover and the recipient scans obliviously). Appended variant — wire-compatible
    /// with older peers (unknown variants are ignored).
    Letter(Vec<u8>),
    /// ⭐ LETTER PULL — request: empty payload, "send me the letter blobs still in their freshness
    /// countdown". The PUSH flood alone measurably fails on asymmetric-dial topologies (2026-08-24: the
    /// joiner could not dial the origin's onion — the same-host two-HS descriptor race — so its letter
    /// frames died with its writers while the chain still converged, because BLOCKS have a pull lane
    /// (DSYNC) and letters did not). This is the letters' pull lane: the same request/response idiom as
    /// NotesReq, answered identically to every requester (selector-independent, no which-item question).
    /// Appended variant — wire-compatible with older peers (unknown variants are ignored).
    LetterReq(Vec<u8>),
    /// LETTER PULL — response: repeated `len(u32 LE) ‖ blob`. Exactly the blobs the push flood would have
    /// sent this pass (the still-fresh ring slice) — the receiver admits each content-deduped, so repeats
    /// are no-ops. DIGITAL-CASH-PRIVACY-REVIEWED: node-to-node lane only; carries the SAME opaque sealed
    /// blobs the existing Letter push already moves peer-to-peer (no new count/volume signal vs that lane —
    /// a peer watching the push already sees one frame per fresh blob), every blob is end-to-end ciphertext
    /// naming no note/amount/key/owner, and the wallet-facing surface stays the constant-cover /letter/inbox.
    LetterResp(Vec<u8>),
    /// DIRECTORY REFILL — request: `from` = the asker's next apply-order log index. A jumped joiner whose
    /// adopted certified `dir_acc` differs from its local fold pulls the FULL registry sequence through
    /// this door (one-time on divergence, never steady-state). Appended variant — wire-compatible.
    DirReq(u64),
    /// DIRECTORY REFILL — response: `(from_index, postcard page of apply-order DirEntrys)`. The offset
    /// makes ordering ENFORCEABLE: the asker applies a page ONLY when it extends its log contiguously
    /// (from == its log length), and stops the page at the first refused entry — an out-of-order or
    /// tampered page can therefore never fold out of sequence (the fold is order-sensitive).
    /// PUBLIC replicated registry data (the same opt-in sign-ups every block already carries in
    /// `dir_set`); every entry is re-verified by the asker through the same apply gate (sig + address
    /// binding + owner-continuity) and the fold must land exactly on the certified accumulator.
    DirResp((u64, Vec<u8>)),
    /// ⭐⭐⭐ GOSSIP A RESTING ORDER — without this the DEX book is NODE-LOCAL and the exchange does not
    /// work between strangers.
    ///
    /// MEASURED 2026-08-31 by audit: `/post_order` put an order into the receiving node's book and
    /// NOTHING propagated it. A maker posting to node A was invisible to a taker on node B, so a trade
    /// could only happen if both parties happened to pick the SAME node — which is not an exchange, and
    /// it breaks the decentralization pillar outright (your ability to trade would depend on guessing
    /// your counterparty's node).
    ///
    /// The payload is `order_book::OrderWire` — a FROZEN wire shape owned by this protocol, never the
    /// decider's live types, so an upstream field addition cannot silently change what peers exchange.
    /// An order is a PUBLIC offer by construction (it is the book's whole product), so gossiping it
    /// discloses nothing that reading the book does not already.
    ///
    /// Flood control needs NO new state: the receiver runs the same `OrderBook::post` gate, which
    /// verifies the maker half and refuses a `Duplicate`, and a node re-broadcasts ONLY when the post
    /// was genuinely new. A loop therefore dies at its second hop, and a forged order never propagates
    /// at all because it never enters a book.
    OrderPost(Vec<u8>),
    /// ⭐ A PEG-IN ATTESTATION REQUEST — the executor's [`crate::peg_attest::PegInProposal`] (two opaque
    /// commitments, the recipient, one ML-KEM-sealed delta per bonded custodian). Relayed by every node;
    /// answered by every bonded custodian that can open its envelope and re-derive the commitments from its
    /// own opening. The finality-vote shape applied to the mint quorum: without it a second seated
    /// validator made every mint `INSUFFICIENT_THRESHOLD` (measured on real nodes, 2026-09-17).
    PegAttestReq(Vec<u8>),
    /// ⭐ ONE custodian's [`crate::peg_attest::PegInAttestation`] over that proposal's statement. Re-gossiped
    /// only when fresh and valid against a proposal this node holds (dedup per custodian per deposit).
    PegAttestResp(Vec<u8>),
    /// ⭐ A PEG-OUT ATTESTATION REQUEST — the executor's [`crate::peg_attest::PegOutProposal`] (two opaque
    /// commitments, the destination, one ML-KEM-sealed (release, burn) per bonded custodian, and the burn
    /// evidence every custodian re-verifies). Relayed by every node; answered by every bonded custodian
    /// that can open its envelope, verify the burn and re-derive the commitments from its own opening.
    /// Until this existed (2026-09-17) the redeem quorum was whatever the caller pasted: 1-of-1 on the real
    /// quorum, so a deposit could enter custody and never come back.
    PegOutAttestReq(Vec<u8>),
    /// ⭐ ONE custodian's [`crate::peg_attest::PegOutAttestation`] over that proposal's statement.
    PegOutAttestResp(Vec<u8>),
    /// DB-77 — a custodial REQUEST (mint / redeem / wrapped mint) any node publishes and every node relays
    /// once; the bonded custodians act on it (`peg_attest::PegRequest`). Amounts, addresses and owner keys
    /// inside are ML-KEM-sealed per custodian; the cleartext is proof material a block would carry anyway.
    PegRequest(Vec<u8>),
    /// ⭐ DB-121 (2026-09-20) — a Bitcoin PAYOUT PROPOSAL for the exit leg (`crate::btc_payout::PayoutProposal`):
    /// which burns it pays (nullifiers only — each destination stays in the custodian's own sealed book, DB-110),
    /// which reserve coins it spends, the fee and the change nonce. Relayed once by every node; SIGNED
    /// independently by every bonded custodian whose own book, own Bitcoin source and own chain agree with it.
    /// No signing session and no coordinator: the Bitcoin twin of the bond-weighted multisig tally.
    PayoutProposal(Vec<u8>),
    /// DB-121 — one custodian's independent BIP-340 signatures over a payout proposal's inputs
    /// (`crate::btc_payout::PayoutSig`); any node holding a quorum's worth assembles and broadcasts the payout.
    PayoutSig(Vec<u8>),
    /// DB-121x (2026-09-21) — one custodian's Monero multisig KEY-EXCHANGE round for the current bonded set
    /// (`crate::xmr_custody::KexMsg`, signed with its ML-DSA identity). Relayed once by every node; consumed by the
    /// set's members, whose own wallets form the k-of-n address from these. Public key material only.
    XmrCustodyKex(Vec<u8>),
    /// DB-121x — a custodian's signed announcement that the set's Monero custody wallet is final at an address
    /// (`crate::xmr_custody::ReadyMsg`). Any node that hears the same address from ≥k members serves deposit
    /// addresses derived from it — a user's node never needs a Monero wallet to peg in.
    XmrCustodyReady(Vec<u8>),
    /// DB-121x — a custodian's exported Monero multisig state (`crate::xmr_payout::SyncMsg`, signed), so the other
    /// members' wallets can account for the reserve's outputs before one of them builds a payout.
    XmrPayoutSync(Vec<u8>),
    /// DB-121x — a Monero payout in progress (`crate::xmr_payout::PayoutMsg`): which burns it pays (nullifiers
    /// only, DB-110), the partially signed multisig set and the ordered signers so far; each next signer adds its
    /// signature from its own wallet after checking the set pays exactly what its own book owes.
    XmrPayoutRound(Vec<u8>),
    /// DB-240 — ONE bonded validator's signed price observation for (epoch, asset)
    /// (`crate::price_quote::SignedQuote::wire`). Gathered against the receiver's own bonded set and
    /// re-gossiped only when fresh; at >=2/3 of bonded weight any node publishes the `Class::PriceMark`.
    PriceQuote(Vec<u8>),
    /// ⭐⭐ DB-454 — THE BAND STEP INVENTORY (Bitcoin `inv` / BIP152, Kaspa block relay; docs/DB-454-BAND-STEP-INV-GETDATA.md):
    /// `n (u8) ‖ n × 32-byte block ids` of fold steps this node can SERVE by id over the bulk lane (kind 22) — its own
    /// proof the moment it exists (verified, or held ahead of its predecessor), a relayed copy its door VERIFIED, or the
    /// subset of a `BandReq`'s ids it holds. One cell, control class. The body never rides the cell stream: the peer that
    /// WANTS a step pulls it by id, so every copy that lands is solicited. Replaces the cell-flooded `BandStep` (deleted at
    /// link 85): MEASURED on the real lane, every node proved every step because an owner's step proven ahead was neither
    /// flooded nor served until the owner's own band reached it, and the 4 s ask round outran the 6.2 s lease.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: fold-step block ids every node holds — public chain structure, no user data.
    BandInv(Vec<u8>),
    /// ⭐ DB-353 §11.10 / DB-454 — a node whose band pointer waits on steps nobody announced to it asks who holds them:
    /// `n (u8) ‖ n × 32-byte block ids`, n ≤ the door's solicited window. A holder answers with a `BandInv` of the ids it
    /// can serve (never the bytes); the asker then pulls by id.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: fold-step block ids every node holds — public chain structure, no user data.
    BandReq(Vec<u8>),
    /// ⭐ PRIVATE SHARDING: a node's ask about tags already public or about to be ([`crate::nf_evidence::NfAsk`]), postcard.
    NfAsk(Vec<u8>),
    /// A holder's answer ([`crate::nf_evidence::NfAnswer`]), postcard.
    NfAnswer(Vec<u8>),
    /// ⭐ LIQUIDATION §10.2 (4) — ONE bonded custodian's signature over a due liquidation's v2 message
    /// (`crate::liquidation_tx::LiquidationSig::wire`): gathered against the receiver's OWN state and bonded set,
    /// re-gossiped only when new; the first custodian holding ≥2/3 proves the five legs and frames the object.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: commitments, a public asset id, the mark epoch and a validator's signature — the
    /// same opaque digests the framed object carries on chain; no amount, owner or note.
    LiquidationSig(Vec<u8>),
    /// ⭐⭐ DB-444 — A TRANSACTION INVENTORY: `n (u8) ‖ n × 32-byte tx ids`, 1 ≤ n ≤ [`TX_INV_MAX`] — the ids this node
    /// pooled since its last inventory. A receiver lacking one fetches its body ONCE over the bulk lane (kind 21) instead
    /// of every peer flooding the whole body to every link (Bitcoin `inv`, Kaspa `InvTransactions`; docs/DB-444).
    /// DIGITAL-CASH-PRIVACY-REVIEWED: content ids of public gossip — the bodies every peer received before this message
    /// existed; no note, amount, key, address or owner.
    TxInv(Vec<u8>),
    /// ⭐ G2c (lane a 2026-10-23) — CLUE-DIRECTORY ANTI-ENTROPY: [`crate::clue_registry::CLUE_DIGEST_WIRE_BYTES`] (2,048 B,
    /// one cell, fixed width) = one 8-byte digest per owner bucket of the sender's clue directory. Sent on every link rise
    /// and every 60 s; a receiver whose bucket differs re-pushes that bucket's verified `Clue` registrations (re-verified
    /// and deduped by the order-free adopt), at most once per period. The one-shot `Clue` gossip lost at 0 writers was
    /// otherwise never repaired (fast-eco replica census `clues` 1 vs 2). Names' 60 s full push was not copied: the clue
    /// directory is one registration per wallet, so a full push would grow with every wallet; the digest is constant.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: digests of the PUBLIC clue directory every node already gossips whole — no note,
    /// amount, scan key or linkage; constant width whatever the directory holds.
    ClueDigest(Vec<u8>),
    /// ⭐ §BR-9a step (c) — ONE custodian's RELEASE of an epoch at its batch (`crate::btc_payout::EpochReleaseMsg`): its
    /// captured seed shares of that epoch, sealed to every other custodian on the roster (ML-KEM, one bundle each). Relayed
    /// once by every node; a custodian opens its own bundle and, at two thirds, the epoch's key and every ticket sealed to it.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the public epoch number, the sender's custodian id and sealed bundles — no ticket,
    /// nullifier, destination, amount or share readable by any relaying node.
    EpochRelease(Vec<u8>),
    /// ⭐ §BR-6 — THE ENTRY MIX ROUND'S PUBLIC VIEW (`crate::entry_mix::RoundView`): terms, the coordinator's onion address,
    /// the phase, the signed credential record and the unsigned transaction, under the epoch's designated custodian's ML-DSA
    /// signature. Relayed once per new view; registrations never ride this message (they go point to point over Tor).
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the record is credential commitments (hiding: each opening hides its owner), the
    /// transaction is what Bitcoin will publish anyway — no mapping from an input to an output is in any field.
    MixRound(Vec<u8>),
    /// ⭐ §BR-3 17.5 — ONE bonded custodian's signature over a due theft repayment (`theft_repayment_tx::TheftRepaySig`),
    /// gathered against the receiver's own state and bonded set (the liquidation lane's shape), re-gossiped only when new.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: public amounts of a public theft and commitments; no holder's value.
    TheftRepaySig(Vec<u8>),
    /// ⭐ §BR-3 17.5 layer 1 — a buyer's request for SAT from the repayment pot at the floor (`pot_fill_tx::PotFillTx` with no
    /// custody half), relayed once per new request so custody can sign its retire.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a public buy (amounts public, the buyer's notes confidential under their own clues).
    PotBuy(Vec<u8>),
    /// ⭐ §BR-3 17.5 layer 1 — ONE bonded custodian's signature over a buy request's retire (`pot_fill_tx::PotFillSig`).
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a request digest, a commitment and a signature.
    PotFillSig(Vec<u8>),
    /// ⭐ §BR-8 B8-a — one bonded custodian's signature on the decoy lanes (`decoy_tx::DecoySig`: a batch booking, a return, an
    /// overdue decoy's theft certificate), gathered against the receiver's own state, re-gossiped only when new.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: custody's own public decoy outputs and signatures; no user's value or identity.
    DecoySig(Vec<u8>),
    /// ⭐ §BR-4 B4-3 — an owner's request to close one debt unit (`unit_close_tx::UnitCloseTx` with no custody half), relayed once
    /// per new request so custody can sign its two legs.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the band, size and day §10.3 makes public; the owner's notes confidential, the Bitcoin
    /// destination sealed in the ticket.
    UnitClose(Vec<u8>),
    /// ⭐ §BR-4 B4-3 — ONE bonded custodian's signature over a close request's legs (`unit_close_tx::UnitCloseSig`).
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a request digest, two commitments and a signature.
    UnitCloseSig(Vec<u8>),
    /// ⭐ §BR-15 — ONE custodian's DeFi lane message (`crate::defi_lane::DefiMpcMsg`: a handshake, a key confirmation, an
    /// engine message or a settlement part), relayed once by every node; only its addressee can open or check it.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the batch number, the sender's and addressee's roster indices, a sequence number and
    /// ciphertexts under pair keys — no amount, order, share or owner readable by a relaying node.
    DefiMpc(Vec<u8>),
    /// ⭐ PAYMENT LOCK (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11, stage 1) — one bonded validator's signature that it
    /// holds a pool payment and has locked that payment's tags to its statement. Payload = postcard-serialized
    /// [`crate::spend_lock::SpendLock`]. A receiver verifies it at `Node::ingest_spend_lock` and relays only a fresh,
    /// verified one. Last in the enum: every earlier variant keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a statement digest, a validator's key, a fold step and a signature — the digest is
    /// of a payment every relaying node already holds from the payment's own gossip; no amount, note, owner or address.
    SpendLock(Vec<u8>),
    /// ⭐ SPEED — THE INVENTORY OF ONE LARGE LANE MESSAGE (`crate::sealed_body`): exactly 37 bytes, `[lane][id 32][len u32
    /// LE]`, the same shape for every message. A node that has not seen the id pulls the body from its announcer over a
    /// bulk lane (`[28][id]`), checks it against the id and the length, and hands it to the lane's own intake — the one
    /// the lane's cells enter by. Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a lane number, the hash of bytes already sealed to their addressee, and their
    /// length — less than the cell flood it replaces showed every relay; every node pulls every announced body, so a
    /// pull says nothing about who a message is for.
    SealedInv(Vec<u8>),
    /// ⭐ A-F19 (lane dcash, 2026-11-10) — A CUSTODIAN'S OPENING SHARE (`crate::node::opening_share::OpeningShare`): an ask from
    /// a bonded custodian whose hidden opening (a pool, a PSM's reserve pair, the stakers' paid-out total) no longer opens the chain's
    /// commitments, or an opening sealed to one such custodian's registered ML-KEM key, which it takes only if it reproduces them.
    /// Relayed once by every node.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a public custodian id, a public asset id, a digest of words every node holds, and an
    /// envelope only its addressee opens — no user, note, amount, address or owner.
    OpeningShare(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three — one custodian's signature over a custody key statement of its own vault
    /// (`crate::vault_key_tx::VaultKeySig::wire`): the take of its members' key, or the retire of a key it replaced.
    /// Gathered against the receiver's OWN seats and key record (the message is formed there, never read from the wire),
    /// relayed once when new; whoever holds two thirds of that vault frames the `Class::VaultKey` object.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: public custodian ids, a vault index and the reserve's own custody address — chain
    /// structure every node already holds; no user, note, amount or deposit.
    VaultKeySig(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three — one custodian's signature over a reserve cost of its own vault
    /// (`crate::reserve_cost_tx::ReserveCostSig::wire`): the public fee of one foreign transaction that moved the vault's
    /// own coins to the vault's own key, with the move itself as evidence every custodian re-checks on its OWN source
    /// before it adds its signature. Relayed once when new; a custodian holding two thirds of that vault proves the
    /// reserve's fall from its own opening and frames the `Class::ReserveCost` object.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: custody's own foreign transaction (public on its own chain), its public fee and a
    /// commitment every node will hold — no user, note, deposit or destination.
    ReserveCostSig(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three — the coin list of a custody vault, asked for by a custodian of that vault whose own
    /// source shows fewer coins than its opening counts, and answered by any other custodian of the vault sealed to the
    /// asker's registered custody ML-KEM key (`crate::btc_payout::CoinShare`). The asker books an entry only if the
    /// address derives from a key its own chain records and its own source shows a coin there.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: an ask names a public custodian id and a vault index; an answer is an envelope
    /// only its addressee opens — no user, note, amount or address on the wire.
    CoinShare(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three — one message of the Monero sweep lane (`crate::xmr_sweep::SweepMsg`): a member of
    /// a REPLACED custody key shares the old wallet's multisig state, passes on the sweep it signed, or states that
    /// its own old wallet shows the sweep confirmed. Verified against the receiver's own key record (the signer is a
    /// member of a replaced key the chain still records), relayed once.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: custody's own wallets and its own transaction between them (public on Monero);
    /// the one address a sweep pays is the vault's own, read from the chain — no user, note, deposit or destination.
    XmrSweep(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three — one custodian's signature over a statement of the vault merge its chain says is
    /// due (`crate::vault_merge_tx::VaultMergeSig::wire`): the retiring vault's release, or the receiving vault's
    /// acceptance with the pairs after. Gathered over the message the receiver's OWN chain forms, relayed once when
    /// new; a custodian of the receiving vault holding both lists proves the sums and frames `Class::VaultMerge`.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: two vault indexes, commitments every node will hold and public custodian keys —
    /// chain structure; no user, note, amount or deposit.
    VaultMergeSig(Vec<u8>),
    /// ⭐ OWED, the hand-over — a cash-out leg handed to a custodian that adopted after its block left every body
    /// window (`crate::btc_payout::LegShareMsg`, signed by the bonded custodian that sent it): an ask naming the owed
    /// burn a payout proposal just named, or the signed parts of that cash-out's object. Processed and relayed only
    /// under a bonded custodian's signature, a bounded count per signer; the asker books a leg only if the custody
    /// quorum signed exactly those parts (`Node::recover_peg_out_leg_signed`).
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a nullifier the payout proposal on this same mesh already names, public
    /// custodian keys and signatures, commitments and envelopes a block carried — no destination, amount or opened leg.
    LegShare(Vec<u8>),
    /// ⭐ SPEC §12.6 (lane goods, 2026-11-11) — THE PICTURE DOOR, request: the blake3 digests (32 bytes each, concatenated,
    /// at most [`PIC_REQ_MAX`]) of pictures this node's directory records name and it does not hold. The directory's
    /// records name a picture (an asset's, a collection's cover) by digest and the bytes are kept apart from the
    /// certified sequence, so a node that took its records by refill, or let bytes go, asks for them here.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: digests of pictures their creators published to the chain (DeFi-layer public
    /// data), asked by a NODE for its own store, never by or for a wallet: it says which public pictures a node lacks
    /// (all of them, for a joiner), and nothing about a person, a note, a holding or what anyone looks at.
    PicReq(Vec<u8>),
    /// ⭐ SPEC §12.6 — THE PICTURE DOOR, response: the pictures the answerer holds among those asked for, framed
    /// `len(u32 LE) ‖ bytes` repeated. NO digest rides beside a picture: the asker computes it from the bytes and keeps
    /// them only if one of its own records names that digest (`Directory::keep_pic`), so an answer cannot place bytes
    /// under a name they do not hash to, and bytes nothing names are dropped.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: published pictures, identical for every asker.
    PicResp(Vec<u8>),
    /// ⭐ SAFE AT SCALE, stage three (spec §3g.1) — one custodian's signature over a statement of a vault rebalance
    /// (`crate::vault_rebalance_tx::VaultRebalanceSig::wire`): a carve, a cancel, the receiving vault's consent or its take.
    /// Gathered over the message the receiver's OWN chain forms, kept by the custodians of the vaults party to it and relayed
    /// once by every other node; a custodian holding two thirds of its vault frames the step.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: vault indexes, commitments every node holds, a key's recorded block score and public
    /// custodian keys — chain structure; no user, note, amount or deposit.
    VaultRebalanceSig(Vec<u8>),
    /// ⭐ IONSWAP POOLS (lane goods, 2026-11-11) — THE POOLS-CACHE REFILL, request: one 32-byte contract id, "your next
    /// leaves of the contract tree after this one" (the zero key: from the start). Sent by a node whose own copy of the
    /// tree is not its ledger's (it joined by a certified state, which carries the tree's root and not its leaves).
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: asked by a NODE for its own store, never by or for a wallet, and it names a place
    /// in the whole tree, never a pool: it says this node lacks the public tree (all of it, for a joiner) and nothing
    /// about a person, an order, a holding or which pool anyone looks at.
    IonReq(Vec<u8>),
    /// ⭐ IONSWAP POOLS — THE POOLS-CACHE REFILL, response: one `ion_pool_tx::IonCachePage` (leaves with their own
    /// paths, and the rows of the pools among them). The asker keeps only what a path proves against its own root.
    /// Appended after every earlier variant, so each keeps its wire tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: published contract leaves and pool rows (DeFi-layer public data by the pool
    /// class's own closed list), identical for every asker.
    IonResp(Vec<u8>),
    /// ⭐ §14 THE BUNDLE RELAY — A BUNDLE INVENTORY: `n (u8) ‖ n × (bundle id 32 ‖ payments u8)`, 1 ≤ n ≤
    /// [`BUNDLE_INV_MAX`] — bundles this node proved and holds free. A producer about to produce takes one from the link it
    /// arrived on (bulk kinds 31 and 32), leased to it alone; nobody else pulls anything (BORROWED: Bitcoin `inv`, with
    /// the body fetched by the one node that will use it). Appended after every earlier variant, so each keeps its tag.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a bundle id names a run of public tree-form ids, never a payment, note, amount, key or
    /// owner; the count rides in clear as every pooled transaction's own inventory already shows it (`TxInv`), and the
    /// holder is the node the payment was pushed to, never its origin.
    BundleInv(Vec<u8>),
}

/// ⭐ §14 — the bundles one [`WireMsg::BundleInv`] names at most (one cell: `1 + 64 × 33 = 2,113` payload bytes).
pub const BUNDLE_INV_MAX: usize = 64;
const _: () = assert!(3 + 1 + 33 * BUNDLE_INV_MAX <= crate::net::CHUNK_DATA, "a bundle inventory must fit one cell");

/// The most digests one [`WireMsg::PicReq`] names, and so the most pictures one answer carries: 8 pictures of at most
/// 24 KB are at most 192 KB a frame, inside the transport's frame bound, and a node owing more asks again on its next
/// maintenance pass until it owes none. A SIZE OF ONE MESSAGE, never a bound on what a node may hold or fetch.
pub const PIC_REQ_MAX: usize = 8;

/// ⭐ DB-444 — the ids one [`WireMsg::TxInv`] carries at most: the inventory always fits ONE cell (`1 + 120 × 32 = 3,841`
/// payload bytes plus the message's 1-byte variant tag and 2-byte length, under `net::CHUNK_DATA` = 4,080), so it rides
/// the writer's control class whole.
pub const TX_INV_MAX: usize = 120;
const _: () = assert!(3 + 1 + 32 * TX_INV_MAX <= crate::net::CHUNK_DATA, "a tx inventory must fit one cell");

/// The body of a [`WireMsg::TipBeacon`] — the UNTRUSTED tip hint that drives Beacon-Adopt convergence.
/// `genesis_commit` scopes the hint to ONE network (a mismatched-genesis beacon is ignored, never adopted);
/// `blue_work`/`blue_score` are the GHOSTDAG heaviest-tip ordering a receiver compares against its own tip.
/// It carries NO proof — adoption is gated solely by the #29 DSYNC decider verify it may trigger, so a forged
/// beacon can never move consensus (Pillar 3: soundness rides the proof, not the hint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipBeaconBody {
    pub genesis_commit: Vec<u8>,
    pub tip: [u8; 32],
    pub blue_work: u128,
    pub blue_score: u64,
    /// ⭐ TASK #21 — record-parity visibility: how many DA records the beaconing node HOLDS. The ledger's
    /// durability is mesh replication (records are RAM by user decision), so every node must be able to SEE
    /// peer record-parity to detect sole-copy risk — MEASURED 2026-08-13: three same-window restarts silently
    /// reset the record layer mesh-wide, twice, because nothing surfaced peer parity anywhere. A COUNT only
    /// (the same figure /get_info already serves publicly): never a record id, note, amount, key or owner.
    /// `serde(default)` keeps mixed-version beacons parseable (an old beacon reads as 0 = "unknown").
    /// cons: 8 bytes per beacon (a fixed protocol constant per already-flowing message, no new message and
    /// no per-block growth).
    #[serde(default)]
    pub records_held: u64,
    /// ⭐ The beaconing node's DENSE record-ordinal top — the coordinate its range serve walks. Added
    /// 2026-08-19 because `records_held` COUNTS real-note records (~7k) while the serve is keyed by
    /// ordinal (~180k): a "newest page" ask computed from the count fetched ancient history — the
    /// recurring ordinal-vs-count coordinate defect, this time on the wire. Same public class as the
    /// figures beside it (/get_info serves it already); `serde(default)` keeps old beacons parseable.
    #[serde(default)]
    pub served_top: u64,
    /// ⭐ Correction 7 (derived-ordinal stage 3) — THE RECORD-SPINE SPLIT DETECTOR, the spine twin of
    /// `unspent_root` directly above: the beaconing node's spine (frontier) root as its own fold held
    /// it at `spine_shell`. Two level peers whose numberings forked BEFORE the derivation roll (a
    /// pre-derivation snapshot, an old-code peer) sit on the SAME tip refusing each other's rows
    /// forever — measured 2026-09-05: one party held a rid at ordinal 48 the other held at 9, every
    /// sidecar row refused, nothing re-anchored, because no record-spine value ever crossed the wire.
    /// Carrying the root at a SHELL coordinate (highest multiple of 8 below the folded top, so both
    /// sides advertise the same coordinate) lets the pair compare exactly and the deterministic loser
    /// re-anchor through the existing certified lane. A beacon is still ONLY a hint: the value moves
    /// no state — the loser merely stops folding and asks for the certified bundle, whose decider
    /// verify is the adopt gate, so a forged beacon costs at most one stopped fold that the very next
    /// certified bundle restores. PUBLIC class: a commitment over record placement, the same figure
    /// the served DSYNC bundle certifies — never a note, amount, key or owner. `serde(default)` keeps
    /// mixed-version beacons parseable (an old beacon reads `[0;4]`/0 = "unknown"; every lane skips
    /// it). cons: 40 bytes per beacon, a fixed constant on an already-flowing message — no new
    /// message, no per-block growth.
    #[serde(default)]
    pub spine_root: crate::spend_frontier::Digest4,
    /// The shell ordinal `spine_root` stands at (0 = "unknown", skipped by every receiver).
    #[serde(default)]
    pub spine_shell: u64,
    /// ⭐ LEG 4 (lane b, 2026-10-23) — the beaconing node's band pointer (`Node::band_next_ordinal`, the fold ordinal its
    /// band waits at): the figure its served #29 bundle certifies as `nullifier.band_next_ordinal`. A receiver whose own
    /// band trails it by more than the band journal's reach can be relayed none of the steps between by any peer, so its
    /// certified ask must go out even while its DAG tip is level (`band_past_journal_reach`). A hint only: the bundle's
    /// decider verify is the adopt gate, and the receive side re-judges the SERVED bundle's band. PUBLIC class: a fold
    /// coordinate the bundle already serves to any asker — never a tag, note, amount, key or owner. 0 = an unknown or
    /// idle band, which is past no one's reach.
    /// cons: ≤ 10 bytes per beacon (a varint on an already-flowing message), no new message, no per-block growth.
    #[serde(default)]
    pub band_next: u64,
}

impl WireMsg {
    /// Encode for the onion transport (postcard). The transport frames the result into fixed-size
    /// cells (and chunks a >1-cell payload such as a decider bundle).
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode a received frame. A corrupt / truncated / unknown message returns `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<WireMsg> {
        crate::chain_object::decode_exact(bytes)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn every_variant_roundtrips_on_the_wire() {
        for m in [
            WireMsg::Block(vec![1, 2, 3]),
            WireMsg::Tx(vec![9, 8, 7]),
            WireMsg::Site(vec![5u8; 40]),
            WireMsg::Vote(vec![6u8; 40]),
            WireMsg::SpendLock(vec![7u8; 40]),
            WireMsg::SealedInv(vec![5u8; 37]),
            WireMsg::OpeningShare(vec![6u8; 40]),
            WireMsg::VaultKeySig(vec![7u8; 40]),
            WireMsg::ReserveCostSig(vec![8u8; 40]),
            WireMsg::CoinShare(vec![9u8; 40]),
            WireMsg::XmrSweep(vec![10u8; 40]),
            WireMsg::VaultMergeSig(vec![11u8; 40]),
            WireMsg::VaultRebalanceSig(vec![12u8; 40]),
            WireMsg::LegShare(vec![12u8; 40]),
            WireMsg::PicReq(vec![7u8; 64]),
            WireMsg::PicResp(vec![8u8; 40]),
            WireMsg::IonReq(vec![9u8; 32]),
            WireMsg::IonResp(vec![10u8; 40]),
            WireMsg::Name(vec![8u8; 40]),
            WireMsg::Clue(vec![9u8; 40]),
            WireMsg::NoteClue(vec![10u8; 40]),
            WireMsg::Govern(vec![11u8; 40]),
            WireMsg::SyncRequest,
            WireMsg::SyncResponse(vec![4u8; 100]),
            WireMsg::TipBeacon(vec![3u8; 32]),
            WireMsg::Settlement(vec![7u8; 64]),
            WireMsg::TxInv(vec![1u8; 33]),
            WireMsg::BundleInv(vec![1u8; 34]),
            WireMsg::ClueDigest(vec![2u8; 2048]),
        ] {
            let bytes = m.to_wire();
            assert!(!bytes.is_empty());
            assert_eq!(
                WireMsg::from_wire(&bytes),
                Some(m),
                "message must survive the wire intact"
            );
        }
    }

    #[test]
    fn corrupt_or_empty_frame_fails_closed() {
        assert_eq!(WireMsg::from_wire(&[]), None);
        assert_eq!(WireMsg::from_wire(&[0xff, 0xff, 0xff]), None);
        // a truncated valid frame does not decode (no partial command).
        let bytes = WireMsg::SyncResponse(vec![7u8; 64]).to_wire();
        assert_eq!(WireMsg::from_wire(&bytes[..bytes.len() / 2]), None);
    }
}

/// Ids per [`WireMsg::TxReq`] — a CONSTANT, so the request's size never encodes how many txs a node
/// actually lacks. Padded with ids drawn from blocks the requester already holds, which are public either
/// way; a responder simply serves whichever of them it has pooled.
pub const TX_REQ_FIXED_COUNT: usize = 32;

/// H5 / DB-273 (C): the per-wallet account-bucket lookup is retired; the route answers RETIRED and records no want.
pub const ACCOUNT_BUCKET_RETIRED: bool = true;

/// The byte budget of one by-record-id ANSWER on the bulk lane (`serve.rs`): the answer stops at a whole-record boundary.
pub const RECORD_ANSWER_BUDGET_BYTES: usize = 1_048_576;
/// The sidecars one served record carries beside its 256 notes (OLI tags 256 × 48 B, account targets, letters), bounded.
pub const RECORD_SIDECAR_MAX_BYTES: usize = 16_384;
/// ⭐ H5 / DB-350 — THE BY-RECORD-ID ASK HAS ONE WIDTH. The ask names exactly this many record addresses, always: the real
/// wants plus decoys (the asker's own placed records, chosen by a secret PRF). It is the number of WHOLE assembled records
/// one answer carries (MEASURED 2026-10-05: the 1 MiB answer carried 3 of a 32-id ask; the rest were re-asked), so every
/// id asked is answered and padding costs no throughput. Before: `1 + 8·n` bytes, `n` = this node's own record debts — a
/// count that moved with its sends (census row `Ask::record_by_id`).
/// ⭐ B13 (lane funds 2026-10-27, T3 liveness at the scale floor): the by-id SERVE now answers the record's CANONICAL reals
/// (the form the receiver stores and re-assembles: `accept_fetched_record_judged` folds
/// `assemble_fixed_note_payload_det(notes, seq)` first, so reals and the padded shape reach one root), not the 295,168-byte
/// padded shape — so one 1 MiB answer carries the whole fixed-count ask, and the width is the by-range lane's
/// `TX_REQ_FIXED_COUNT`. MEASURED before (scratchpad/funds/harness-34.log, 10 in-process parties, 120 s): width 3 of padded
/// records per ~3.5 s round trip against 2 blocks/s of production, so no fold ever caught its tip (party 5: certified
/// position 0 at tip 225). cons: a node holding fewer than 31 placed records pads a shorter ask (a joiner's first ~16 s;
/// its `records_held` is already in its beacon).
pub const RECORD_ASK_WIDTH: usize = TX_REQ_FIXED_COUNT;
const _: () = assert!(RECORD_ASK_WIDTH >= 1, "an answer must carry at least one whole record");

/// Positions per BATCHED `/get_my_pq_notes` `by_record_id` request — a PROTOCOL CONSTANT, never
/// caller-chosen (an unbounded caller-chosen count is a request-shaped growth axis and a which-item
/// timing amplifier). 64 is the wallet's own detection fan-out (`OLI_FETCH_PAGES`), so one wallet
/// detection pass is exactly ONE round-trip instead of the measured 64 serial ones. A request naming
/// MORE than this many positions is REFUSED whole (loudly, never truncated — a silent truncation is a
/// cap wearing a costume), and the caller splits. Each position in the reply carries its record
/// ADDRESS and SLOT explicitly, so the reader never derives a slot from array position (the
/// lib.rs:2083 fund-loss class).
pub const PQ_NOTES_BATCH_FIXED_COUNT: usize = 64;

/// ⭐⭐⭐ P4′b — ONE LEDGER RECORD AS IT TRAVELS IN A BACKFILL PAGE.
///
/// A record is not just its note bytes. A note whose LOCATOR TAG did not travel with it is a note its owner
/// can never find from their seed, and a note whose ACCOUNT TARGET did not travel is one the recipient's own
/// node files into no bucket — both are money on chain that its owner cannot reach. The backfill page used to
/// carry the record address, the notes and the targets and nothing else, which is why a node that obtained
/// its history by FETCHING (every joiner, every restart) rebuilt the notes and an EMPTY locator index —
/// measured as `[oli-tagdrain] drained ZERO locator tag(s)`.
///
/// The nullifier tags ride for the same reason on the spend side: a verifier reconstructs a served block's
/// fold inputs from its DA-nf shard, and a node that never held the block cannot rebuild that shard from
/// notes alone.
pub struct LedgerRecord {
    /// The record's CANONICAL address (a pure function of its block id — the same on every node).
    pub rid: u64,
    /// The block's confidential note payload (fixed-width notes, concatenated).
    pub notes: Vec<u8>,
    /// Account-DA targets, as the account layer already frames them per note.
    pub targets: Vec<u8>,
    /// OLI locator tags for this record, framed as the DA tag shard already frames them.
    pub oli_tags: Vec<u8>,
    /// This block's settled nullifier tags, 32-byte values concatenated.
    pub nf_tags: Vec<u8>,
    /// ⭐ This block's anchored sealed LETTER blobs (`len(u32 LE) ‖ blob` repeated) — the Letter messenger's
    /// content column, riding the SAME replication pages as every sidecar above so mail is mesh-durable and
    /// a wallet restores its whole history from seed (USER-APPROVED column, 2026-08-23 in-chat). Every
    /// blob's 32-byte commitment rides the block's consensus `letter_set` (the fixed 64-slot shape,
    /// consensus-enforced), so a fetched blob is SELF-VERIFYING against the chain at any age — a forged
    /// page entry fails the re-hash and is refused. Opaque end-to-end ciphertext; replicating it reveals
    /// nothing the gossip didn't. Private + accessors: the framing invariant lives in one place (this is a
    /// TRANSIENT wire-page struct, encoded per backfill page — at-rest bytes live only in the record row).
    letters: Vec<u8>,
    /// ⭐ §20.2 — the record's COVER KEY (32 B, or empty when the server holds none): what a receiver assembles and strips the
    /// record's cover under. Rides on every node-to-node page beside the reals; a wallet route never carries it.
    pub cover_key: Vec<u8>,
}

impl LedgerRecord {
    /// §20.2 — the carried cover key, when the page carries one (32 B); `None` otherwise.
    #[must_use]
    pub fn key(&self) -> Option<crate::cover::CoverKey> {
        self.cover_key.as_slice().try_into().ok()
    }

    /// THE ONE constructor every page-builder uses (private letters column ⇒ no struct literal outside this
    /// module, so the framing invariant lives in one place). `parts` is the five content columns in wire
    /// order: `(notes, targets, oli_tags, nf_tags, letters)` — the same order
    /// [`encode_ledger_page`] writes and [`decode_ledger_page`] reads.
    pub fn assemble(
        rid: u64,
        parts: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
        cover_key: Option<crate::cover::CoverKey>,
    ) -> Self {
        let (notes, targets, oli_tags, nf_tags, letters) = parts;
        LedgerRecord {
            rid,
            cover_key: cover_key.map(|k| k.to_vec()).unwrap_or_default(),
            notes,
            targets,
            oli_tags,
            nf_tags,
            letters,
        }
    }
    /// The letters column (framed `len ‖ blob` repeated; empty = the serving node held none for this block).
    pub fn letters(&self) -> &[u8] {
        &self.letters
    }
}

/// THE ONE encoding of a backfill page body (everything AFTER the 32-byte page header), used by every serve
/// site and inverted by [`decode_ledger_page`]. Five hand-rolled copies of this loop existed and each had to
/// be updated in lockstep with the parser — the exact drift shape that has cost this codebase a payment more
/// than once, so there is now one definition and no second place to forget.
///
/// Each entry writes the record address as 8 little-endian bytes, then each of the four payload fields in a
/// fixed order (notes, targets, locator tags, nullifier tags) as a 4-byte little-endian length followed by
/// that many bytes. Every field is length-prefixed, so a reader that stops early stops CLEANLY.
pub fn encode_ledger_page(entries: &[LedgerRecord]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for e in entries {
        out.extend_from_slice(&e.rid.to_le_bytes());
        for field in [
            &e.notes,
            &e.targets,
            &e.oli_tags,
            &e.nf_tags,
            &e.letters,
            &e.cover_key,
        ] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field);
        }
    }
    out
}

/// THE ONE decoding, the exact inverse of [`encode_ledger_page`]. A truncated page yields the entries that
/// parsed WHOLE and stops — never a fabricated or partial record, because a half-read record would be
/// offered to the verified-fetch door as if it were the peer's real answer.
/// COORDINATE PAGE (the kind-5 lane) — per record, its ordinal and its address, in ordinal order:
/// `[ordinal u64][rid u64]` per entry, little-endian. This is how a node that skipped a span learns
/// which record address sits at each ordinal so its wants can name records by id. It carried the
/// deletion-model's receive/deletion sidecars until Z1 (2026-09-22); those columns are gone with the
/// unspent tree — a coordinate list, never a note, amount, key or owner.
pub fn encode_sidecar_page(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(entries.len() * 16);
    for (ord, rid) in entries {
        out.extend_from_slice(&ord.to_le_bytes());
        out.extend_from_slice(&rid.to_le_bytes());
    }
    out
}

/// Inverse of [`encode_sidecar_page`]; a truncated tail stops clean at the last whole entry.
pub fn decode_sidecar_page(body: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(body.len() / 16);
    let mut i = 0usize;
    while i + 16 <= body.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&body[i..i + 8]);
        let ord = u64::from_le_bytes(w);
        w.copy_from_slice(&body[i + 8..i + 16]);
        let rid = u64::from_le_bytes(w);
        out.push((ord, rid));
        i += 16;
    }
    out
}

/// ROOTS RUN (bulk kind 6) — the HEADERS-FIRST door's wire: a contiguous run of per-record block
/// roots starting at `from`, ≤ one DA ladder span (4096 × 32 B = 128 KB). A jumped node folds the run
/// from the certified accumulator it holds and admits it only if it lands EXACTLY on the certified
/// target (`Node::accept_fetched_root_run`); every by-id record then verifies individually against the
/// run's per-ordinal accumulators. Framing: `[from u64][count u32]` ‖ count × 4 × u64 LE limbs.
/// A root is a public per-record commitment already implied by every served copath; never a note,
/// amount, key or owner.
/// ⛔⛔⛔ THE WIRE WIDTH OF ONE ROOT, DERIVED FROM THE DIGEST — NEVER A LITERAL.
///
/// `Digest4` IS A NAME, NOT A WIDTH: it is `poseidon2_compress::Digest` = `[u64; DIGEST_LANES]`, and
/// `DIGEST_LANES` is **8**. The encoder below has always written every limb (64 bytes); the decoder's
/// length check said `12 + count * 32`, so **`decode_roots_run` returned `None` for every run this
/// encoder has ever produced** — a silent `None`, on a path whose only other exit logs loudly.
///
/// MEASURED 2026-09-24, `roots_run_tests::a_jumper_asks…`: A served a 2,645-byte run for the 41 roots B
/// asked for (9 magic + 12 header + 41x64 = 2,645 exactly), B decoded nothing, and its ask came back
/// unchanged — `ask Some((1, 41))` after the run as before it.
///
/// ⛔ WHAT THAT COST, and it is not a test-only cost: the roots run is the HEADERS-FIRST DOOR a jumped
/// node closes before it may fetch record bytes. With it dead the span never closes, so
/// `accept_fetched_record` refuses every by-id record — the shape `block_root_at_ordinal` already
/// records from a live gate: *"[da-fetch] 0/1 peer record(s) verified against roots we hold, gap frozen
/// at 118 blocks"*. A wallet asking a jumped node for its notes gets nothing, at any height.
///
/// Same class as the 2026-09-23 wallet defect (a 4-limb decoder against an 8-lane digest), which is why
/// this is a derived constant and not a corrected number: the next width change must break the build,
/// not the chain.
pub const ROOT_WIRE_BYTES: usize = usdm_decider::poseidon2_compress::DIGEST_LANES * 8;

pub fn encode_roots_run(from: u64, roots: &[crate::spend_frontier::Digest4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + roots.len() * ROOT_WIRE_BYTES);
    out.extend_from_slice(&from.to_le_bytes());
    out.extend_from_slice(&(roots.len() as u32).to_le_bytes());
    for r in roots {
        for limb in r {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
    debug_assert_eq!(
        out.len(),
        12 + roots.len() * ROOT_WIRE_BYTES,
        "the encoder and ROOT_WIRE_BYTES must agree, or the decoder refuses every run"
    );
    out
}

/// Inverse of [`encode_roots_run`]; a truncated body yields `None` (a run is all-or-nothing).
pub fn decode_roots_run(body: &[u8]) -> Option<(u64, Vec<crate::spend_frontier::Digest4>)> {
    if body.len() < 12 {
        return None;
    }
    let mut w = [0u8; 8];
    w.copy_from_slice(&body[..8]);
    let from = u64::from_le_bytes(w);
    let mut c = [0u8; 4];
    c.copy_from_slice(&body[8..12]);
    let count = u32::from_le_bytes(c) as usize;
    if body.len() != 12 + count * ROOT_WIRE_BYTES {
        return None;
    }
    let mut roots = Vec::with_capacity(count);
    for i in 0..count {
        let mut r = usdm_decider::poseidon2_compress::zero_digest();
        for (k, limb) in r.iter_mut().enumerate() {
            let off = 12 + i * ROOT_WIRE_BYTES + k * 8;
            w.copy_from_slice(&body[off..off + 8]);
            *limb = u64::from_le_bytes(w);
        }
        roots.push(r);
    }
    Some((from, roots))
}

pub fn decode_ledger_page(body: &[u8]) -> Vec<LedgerRecord> {
    let mut out: Vec<LedgerRecord> = Vec::new();
    let mut i = 0usize;
    'entry: while i + 8 <= body.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&body[i..i + 8]);
        let rid = u64::from_le_bytes(w);
        let mut j = i + 8;
        let mut fields: [Vec<u8>; 6] = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for f in fields.iter_mut() {
            if j + 4 > body.len() {
                break 'entry;
            }
            let mut ln = [0u8; 4];
            ln.copy_from_slice(&body[j..j + 4]);
            let n = u32::from_le_bytes(ln) as usize;
            if j + 4 + n > body.len() {
                break 'entry;
            }
            *f = body[j + 4..j + 4 + n].to_vec();
            j += 4 + n;
        }
        let [notes, targets, oli_tags, nf_tags, letters, cover_key] = fields;
        out.push(LedgerRecord {
            rid,
            notes,
            targets,
            oli_tags,
            nf_tags,
            letters,
            cover_key,
        });
        i = j;
    }
    out
}

#[cfg(all(test, feature = "pins-core"))]
mod sidecar_page_tests {
    use super::*;

    /// Two parties on the wire: the SERVER encodes rows it holds, the JOINER decodes them; every row
    /// (including a seed-only record with EMPTY sidecars) round-trips, and a page cut mid-row yields
    /// exactly the whole rows before the cut and never a fabricated one.
    #[test]
    fn a_sidecar_page_round_trips_every_row_and_a_truncated_page_stops_clean() {
        let rows = vec![(7u64, 0x1122_3344_5566_7788u64), (8u64, 11u64), (9u64, u64::MAX)];
        let wire = encode_sidecar_page(&rows);
        assert_eq!(wire.len(), rows.len() * 16, "sixteen bytes per coordinate row, nothing else");
        assert_eq!(decode_sidecar_page(&wire), rows, "the joiner reads exactly what the server wrote");
        let cut = &wire[..wire.len() - 5];
        let partial = decode_sidecar_page(cut);
        assert_eq!(partial, rows[..2].to_vec(), "a page cut mid-row yields only the whole rows before the cut");
        assert!(decode_sidecar_page(&wire[..3]).is_empty(), "a body shorter than one row is no row");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod ledger_page_tests {
    use super::*;

    /// A page must survive the wire EXACTLY — every sidecar, in order, for every entry. This is the test that
    /// would have caught the class it was written for: the locator tags silently absent from the page while
    /// notes and targets arrived fine, which reads downstream as "this block simply had no tagged notes".
    #[test]
    fn a_ledger_page_round_trips_every_sidecar_and_a_truncated_page_stops_clean() {
        let entries = vec![
            LedgerRecord {
                rid: 288_221_910_316_966_119,
                notes: vec![7u8; 1153],
                targets: vec![1u8; 66],
                oli_tags: vec![2u8; 17],
                nf_tags: vec![3u8; 64],
                letters: vec![6u8; 90],
                cover_key: vec![0x5a; 32],
            },
            // An IDLE-shaped record: notes but no sidecars at all. Empty must round-trip as EMPTY, never as
            // "absent" — the two are different claims and the apply side treats them differently.
            LedgerRecord {
                rid: 42,
                notes: vec![9u8; 1153],
                targets: Vec::new(),
                oli_tags: Vec::new(),
                nf_tags: Vec::new(),
                letters: Vec::new(),
                cover_key: Vec::new(),
            },
        ];
        let wire = encode_ledger_page(&entries);
        let back = decode_ledger_page(&wire);
        assert_eq!(back.len(), 2, "both entries must survive the round trip");
        for (a, b) in entries.iter().zip(back.iter()) {
            assert_eq!(a.rid, b.rid, "the record address must survive");
            assert_eq!(a.notes, b.notes, "the notes must survive");
            assert_eq!(a.targets, b.targets, "the account targets must survive");
            assert_eq!(
                a.oli_tags, b.oli_tags,
                "the LOCATOR TAGS must survive — a note whose tag is dropped here is unfindable forever"
            );
            assert_eq!(a.nf_tags, b.nf_tags, "the nullifier tags must survive");
            assert_eq!(
                a.letters, b.letters,
                "the LETTER blobs must survive — dropped mail here is silent message loss on the fetching node"
            );
        }
        // TRUNCATION: cut mid-way through the second entry. The FIRST must parse whole and the second must be
        // dropped entirely — never half-built and offered as a real record.
        let cut = wire.len() - 30;
        let partial = decode_ledger_page(&wire[..cut]);
        assert_eq!(
            partial.len(),
            1,
            "a truncated page yields only the entries that parsed WHOLE"
        );
        assert_eq!(
            partial[0].oli_tags, entries[0].oli_tags,
            "and that entry is intact, sidecars included"
        );
    }
}

// ── THE MONEROUSD INTERNET: SITE ASSETS TRAVEL, NOT JUST THEIR ROOT ──────────────────────────────────
//
// ⛔ WHAT WAS MISSING, read from live code 2026-09-04. `SiteGossip` propagates a site's ROOT and signature
// across the mesh, so every node learns which bytes are authentic — and NOTHING carries the bytes. There is
// no wire message that serves a bundle to a peer, and the sovereign server binds loopback only. So the
// chain-anchored web was ANCHORED but not DISTRIBUTED: a node without the bundle could not be served the
// site by anyone, which is the difference between a private internet and a private bookmark.
//
// THE SHAPE, and it needs no trust at all. `SiteBundle::serve` already returns a `ServedAsset` carrying the
// bytes, the manifest index and a Merkle inclusion proof, and `site::verify_served` already checks that
// triple against the anchored root. So a peer can hand over any asset and the receiver VERIFIES it against
// the root it learned from gossip — a lying or corrupted server is refused by construction, exactly as the
// local sovereign surface already self-verifies before it returns a byte.
//
// DIGITAL-CASH-PRIVACY-REVIEWED: a request names a SITE and a PATH — public, chain-anchored content that
// every node may hold, with no account, note, amount or holder in it. This lane carries published web
// assets and nothing else; it must never be reused to ask for anything keyed to a user.

/// One asset of one site, on the wire.
/// `[site_id 32][path_len u16][path][content_type_len u16][content_type][index u32][proof_len u16][proof 32×n][bytes_len u32][bytes]`
pub fn encode_site_asset(
    site_id: &crate::hash::Hash32,
    path: &str,
    served: &crate::site::ServedAsset,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + path.len() + served.bytes.len() + served.proof.len() * 32);
    out.extend_from_slice(site_id.as_bytes());
    out.extend_from_slice(&(path.len() as u16).to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(&(served.content_type.len() as u16).to_le_bytes());
    out.extend_from_slice(served.content_type.as_bytes());
    out.extend_from_slice(&(served.index as u32).to_le_bytes());
    out.extend_from_slice(&(served.proof.len() as u16).to_le_bytes());
    for h in &served.proof {
        out.extend_from_slice(h.as_bytes());
    }
    out.extend_from_slice(&(served.bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&served.bytes);
    out
}

/// All-or-nothing: a truncated or malformed page yields `None` rather than a partly-read asset, because a
/// half-read asset would be verified against a root it was never going to match and the failure would look
/// like a lying peer instead of a short read.
pub fn decode_site_asset(
    b: &[u8],
) -> Option<(crate::hash::Hash32, String, crate::site::ServedAsset)> {
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Option<()> {
        if *o + n > b.len() {
            return None;
        }
        *o += n;
        Some(())
    };
    let start = o;
    take(&mut o, 32)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&b[start..start + 32]);

    let pl_at = o;
    take(&mut o, 2)?;
    let pl = u16::from_le_bytes([b[pl_at], b[pl_at + 1]]) as usize;
    let p_at = o;
    take(&mut o, pl)?;
    let path = String::from_utf8(b[p_at..p_at + pl].to_vec()).ok()?;

    let cl_at = o;
    take(&mut o, 2)?;
    let cl = u16::from_le_bytes([b[cl_at], b[cl_at + 1]]) as usize;
    let c_at = o;
    take(&mut o, cl)?;
    let content_type = String::from_utf8(b[c_at..c_at + cl].to_vec()).ok()?;

    let i_at = o;
    take(&mut o, 4)?;
    let index = u32::from_le_bytes([b[i_at], b[i_at + 1], b[i_at + 2], b[i_at + 3]]) as usize;

    let nl_at = o;
    take(&mut o, 2)?;
    let n = u16::from_le_bytes([b[nl_at], b[nl_at + 1]]) as usize;
    let mut proof = Vec::with_capacity(n);
    for _ in 0..n {
        let h_at = o;
        take(&mut o, 32)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&b[h_at..h_at + 32]);
        proof.push(crate::hash::Hash32(h));
    }

    let bl_at = o;
    take(&mut o, 4)?;
    let bl = u32::from_le_bytes([b[bl_at], b[bl_at + 1], b[bl_at + 2], b[bl_at + 3]]) as usize;
    let b_at = o;
    take(&mut o, bl)?;
    let bytes = b[b_at..b_at + bl].to_vec();

    Some((
        crate::hash::Hash32(id),
        path,
        crate::site::ServedAsset { content_type, bytes, index, proof },
    ))
}

/// A request for one asset: `[site_id 32][path]`. No account, no holder, no amount — a site and a path.
pub fn encode_site_asset_req(site_id: &crate::hash::Hash32, path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + path.len());
    out.extend_from_slice(site_id.as_bytes());
    out.extend_from_slice(path.as_bytes());
    out
}

pub fn decode_site_asset_req(b: &[u8]) -> Option<(crate::hash::Hash32, String)> {
    if b.len() < 33 {
        return None; // a request with no path names no asset
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&b[..32]);
    let path = String::from_utf8(b[32..].to_vec()).ok()?;
    Some((crate::hash::Hash32(id), path))
}

#[cfg(all(test, feature = "pins-core"))]
mod site_asset_lane_tests {
    use super::{decode_site_asset, decode_site_asset_req, encode_site_asset, encode_site_asset_req};
    use crate::hash::Hash32;
    use crate::site::{Asset, SiteBundle};

    fn a_published_site() -> (SiteBundle, Hash32) {
        let b = crate::site::build_bundle(vec![
            Asset {
                path: "/index.html".into(),
                content_type: "text/html".into(),
                bytes: b"<h1>Ion Swap</h1>".to_vec(),
            },
            Asset {
                path: "/app.js".into(),
                content_type: "text/javascript".into(),
                bytes: vec![7u8; 512],
            },
        ])
        .expect("the bundle builds");
        let root = b.manifest.root();
        (b, root)
    }

    /// `ServedAsset` does not derive Clone, and it should not have to for a test to tamper with a copy.
    fn copy_of(a: &crate::site::ServedAsset) -> crate::site::ServedAsset {
        crate::site::ServedAsset {
            content_type: a.content_type.clone(),
            bytes: a.bytes.clone(),
            index: a.index,
            proof: a.proof.clone(),
        }
    }

    /// ⭐ THE PROPERTY: a peer hands over bytes and the receiver believes them ONLY because they verify
    /// against the root the chain already anchored. No trust in the server, which is what makes this an
    /// internet rather than a hosting arrangement.
    #[test]
    fn an_asset_fetched_from_a_peer_verifies_against_the_anchored_root() {
        let (bundle, root) = a_published_site();
        let served = bundle.serve("/index.html").expect("the holder serves it");
        let site_id = Hash32::hash(b"ionswap-monerousd-org");
        let wire = encode_site_asset(&site_id, "/index.html", &served);
        let (got_id, got_path, got) = decode_site_asset(&wire).expect("the page decodes");
        assert_eq!(got_id, site_id, "the asset names its site");
        assert_eq!(got_path, "/index.html");
        assert!(
            crate::site::verify_served(&root, &got_path, &got),
            "an honestly served asset must verify against the anchored root"
        );
    }

    /// ⭐ THE ADVERSARIAL HALF: a peer that alters a byte, a path, or a proof is REFUSED. Without this the
    /// lane would be a way to serve anybody anything and call it MonerousD.
    #[test]
    fn a_tampered_asset_is_refused_by_the_root_it_claims_to_belong_to() {
        let (bundle, root) = a_published_site();
        let site_id = Hash32::hash(b"ionswap-monerousd-org");
        let honest = bundle.serve("/app.js").expect("serves");

        let mut bad_bytes = copy_of(&honest);
        bad_bytes.bytes[0] ^= 1;
        assert!(
            !crate::site::verify_served(&root, "/app.js", &bad_bytes),
            "⛔ a single flipped byte verified — then a peer can serve altered code under our root"
        );

        let mut bad_index = copy_of(&honest);
        bad_index.index = bad_index.index.wrapping_add(1);
        assert!(!crate::site::verify_served(&root, "/app.js", &bad_index), "a moved index must not verify");

        let mut bad_proof = copy_of(&honest);
        if let Some(h) = bad_proof.proof.first_mut() {
            *h = Hash32::hash(b"not the sibling");
        }
        assert!(!crate::site::verify_served(&root, "/app.js", &bad_proof), "a forged proof must not verify");

        // …and the honest asset served under ANOTHER path is not that path's asset.
        let wire = encode_site_asset(&site_id, "/index.html", &honest);
        let (_, path, got) = decode_site_asset(&wire).expect("decodes");
        assert!(
            !crate::site::verify_served(&root, &path, &got),
            "⛔ an asset verified under a path it does not occupy — then a peer can swap one file for another"
        );
    }

    /// A truncated page is refused whole rather than half-read, so a short read cannot masquerade as a
    /// lying peer.
    #[test]
    fn a_truncated_page_yields_nothing_rather_than_half_an_asset() {
        let (bundle, _root) = a_published_site();
        let served = bundle.serve("/app.js").expect("serves");
        let wire = encode_site_asset(&Hash32::hash(b"s"), "/app.js", &served);
        for cut in [1usize, 33, 64, wire.len() - 1] {
            assert!(
                decode_site_asset(&wire[..cut]).is_none(),
                "a page cut at {cut} decoded to something — a partial asset is not an asset"
            );
        }
        assert!(decode_site_asset(&wire).is_some(), "the whole page still decodes");
    }

    /// A request names a site and a path and nothing else — no holder, no amount, nothing user-keyed.
    #[test]
    fn a_request_names_only_a_site_and_a_path() {
        let id = Hash32::hash(b"site");
        let req = encode_site_asset_req(&id, "/styles.css");
        let (got_id, path) = decode_site_asset_req(&req).expect("decodes");
        assert_eq!((got_id, path.as_str()), (id, "/styles.css"));
        assert!(decode_site_asset_req(&req[..32]).is_none(), "a request with no path names no asset");
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// DATA-AVAILABILITY CHUNK ASK — `NotesReq` marker kind 10, and its answer.
//
// ⛔ THE ASK THAT DID NOT EXIST. A block header commits `output_notes_root = da::commit(bytes).root`
// and, until this landed, `da::inclusion_proof`, `da::verify_chunk` and `da::sample_indices` had ZERO
// production callers — so a producer could commit to data it WITHHELD and no node could catch it. That
// is a SOUNDNESS gap, not a storage one: a note nobody can ever open, under a root every node accepted.
//
// ⭐ ONE ENCODING, BOTH DIRECTIONS, ONE FILE. The serve side and the ask side call these, so the shape
// cannot drift between the party that writes it and the party that reads it — the defect class this
// tree pays most for (kill list §AI).
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The `NotesReq` marker byte for a DA chunk ask.
///
/// ⛔ 13 BYTES IS LEGAL AND THE LAW SAYS WHY: no marker kind may define a TWELVE-byte ask (that length
/// belongs to the pre-marker range door, dispatched before any marker arm). Kinds 5, 6 and 8 are already
/// 13 bytes and are told apart by this same marker byte.
pub const DA_CHUNK_REQ_KIND: u8 = 10;

/// The answer's magic, so a page of one kind can never be read as another.
pub const DA_CHUNK_RESP_MAGIC: &[u8; 7] = b"DACHUNK";

/// `[10][addr u64 LE][index u32 LE]` — 13 bytes, constant, independent of the record's size.
#[must_use]
pub fn encode_da_chunk_req(addr: u64, index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.push(DA_CHUNK_REQ_KIND);
    out.extend_from_slice(&addr.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out
}

/// Inverse of [`encode_da_chunk_req`]. `None` on any other shape — fail-closed, never a guess.
#[must_use]
pub fn decode_da_chunk_req(b: &[u8]) -> Option<(u64, u32)> {
    if b.len() != 13 || b[0] != DA_CHUNK_REQ_KIND {
        return None;
    }
    let addr = u64::from_le_bytes(b[1..9].try_into().ok()?);
    let index = u32::from_le_bytes(b[9..13].try_into().ok()?);
    Some((addr, index))
}

/// `DACHUNK ‖ [addr u64][index u32][chunk_len u32][chunk][n_proof u16][proof: n×32]`.
#[must_use]
pub fn encode_da_chunk_resp(
    addr: u64,
    index: u32,
    chunk: &[u8],
    proof: &[crate::hash::Hash32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + 8 + 4 + 4 + chunk.len() + 2 + proof.len() * 32);
    out.extend_from_slice(DA_CHUNK_RESP_MAGIC);
    out.extend_from_slice(&addr.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    out.extend_from_slice(chunk);
    out.extend_from_slice(&(proof.len() as u16).to_le_bytes());
    for n in proof {
        out.extend_from_slice(n.as_bytes());
    }
    out
}

/// Inverse of [`encode_da_chunk_resp`]. Every length is read from the frame and CHECKED against what
/// remains, so a truncated or over-long page decodes to `None` rather than to a short chunk that would
/// then fail an inclusion proof for the wrong reason.
///
/// ⛔ THE ROOT IS DELIBERATELY NOT IN THIS FRAME. A peer that answers with a chunk, a proof AND the root
/// to check them against has proved nothing; the asker must anchor on the root its own accepted header
/// committed (§AH — every consumer anchors on self-derived state).
#[must_use]
pub fn decode_da_chunk_resp(b: &[u8]) -> Option<(u64, u32, Vec<u8>, Vec<crate::hash::Hash32>)> {
    let m = DA_CHUNK_RESP_MAGIC.len();
    if b.len() < m + 8 + 4 + 4 || &b[..m] != DA_CHUNK_RESP_MAGIC.as_slice() {
        return None;
    }
    let addr = u64::from_le_bytes(b[m..m + 8].try_into().ok()?);
    let index = u32::from_le_bytes(b[m + 8..m + 12].try_into().ok()?);
    let clen = u32::from_le_bytes(b[m + 12..m + 16].try_into().ok()?) as usize;
    let cstart = m + 16;
    let cend = cstart.checked_add(clen)?;
    if b.len() < cend + 2 {
        return None;
    }
    let chunk = b[cstart..cend].to_vec();
    let n = u16::from_le_bytes(b[cend..cend + 2].try_into().ok()?) as usize;
    let pstart = cend + 2;
    if b.len() != pstart + n * 32 {
        return None; // exact: a trailing byte is a different frame, not this one
    }
    let mut proof = Vec::with_capacity(n);
    for i in 0..n {
        let o = pstart + i * 32;
        proof.push(crate::hash::Hash32(b[o..o + 32].try_into().ok()?));
    }
    Some((addr, index, chunk, proof))
}


#[cfg(all(test, feature = "pins-core"))]
mod roots_run_wire_tests {
    //! ⛔⛔⛔ THE ROOTS RUN MUST SURVIVE ITS OWN ENCODER. It did not, for as long as the digest has been
    //! 8 lanes: the decoder's length check read `12 + count * 32` against a 64-byte-per-root body, so it
    //! returned `None` every time — silently, on a path whose only other exit logs loudly.
    //!
    //! ROOT-LAYER: the wire WIDTH of one root, which is a property of the digest and of nothing else.
    //! MEASURED 2026-09-24: a 41-root run encodes to 2,633 bytes (12 + 41x64) and decoded to nothing.
    //! MUST-STAY-GREEN: the run stays all-or-nothing — a truncated or over-long body is still `None`.
    use super::*;

    fn root(seed: u64) -> crate::spend_frontier::Digest4 {
        let mut r = usdm_decider::poseidon2_compress::zero_digest();
        for (k, limb) in r.iter_mut().enumerate() {
            *limb = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(k as u64);
        }
        r
    }

    #[test]
    fn a_run_round_trips_at_the_digests_own_width() {
        let roots: Vec<_> = (0..41u64).map(root).collect();
        let body = encode_roots_run(7, &roots);
        assert_eq!(
            body.len(),
            12 + 41 * ROOT_WIRE_BYTES,
            "⛔ the encoder does not write ROOT_WIRE_BYTES per root, so the decoder's exact-length check \
             can only ever refuse it"
        );
        let (from, back) = decode_roots_run(&body).expect(
            "⛔ THE DECODER REFUSED ITS OWN ENCODER'S OUTPUT. This is the shape that shipped: a jumped \
             node could never close its headers-first span, so accept_fetched_record refused every by-id \
             record and its DA gap never healed.",
        );
        assert_eq!(from, 7);
        assert_eq!(back, roots, "every limb of every root survives the hop");
    }

    #[test]
    fn a_truncated_or_over_long_run_is_still_refused_whole() {
        let roots: Vec<_> = (0..3u64).map(root).collect();
        let body = encode_roots_run(1, &roots);
        assert!(decode_roots_run(&body[..body.len() - 1]).is_none(), "a truncated run is None");
        let mut long = body.clone();
        long.push(0);
        assert!(decode_roots_run(&long).is_none(), "a trailing byte is a different frame, not this one");
        // …and a body whose declared count disagrees with its length is refused rather than read short.
        let mut lying = body.clone();
        lying[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            decode_roots_run(&lying).is_none(),
            "⛔ a count that disagrees with the body length must be refused — reading short here would \
             fold a partial run onto the cursor and call it a span"
        );
    }
}
