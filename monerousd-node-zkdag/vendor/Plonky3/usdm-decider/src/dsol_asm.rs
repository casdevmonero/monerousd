// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE DSOL ASSEMBLER — how a site's author writes the back end they host on the chain (Veil spec §12).
//!
//! One instruction a line; `;` starts a comment. `entry NAME:` marks an entrypoint (a call names it), `NAME:` a jump
//! label. Mnemonics are the machine's opcodes ([`crate::dsol_vm::op`]) in lower case (`push`, `sload`, `sstore`,
//! `map_load`, `map_store`, `concat`, `add`, `jumpi`, `return`, …); `push` takes a number (`42`, `0x2a`) for a word or a
//! quoted string (`"hello"`, with `\n \t \" \\` escapes) for bytes; `jump`/`jumpi` take a label; `local.get`/`local.set`/
//! `locals` and `syscall` take a number; `call`/`libcall` take an entrypoint name. The output is the machine's own v2
//! bytecode (`dsol_vm::parse_entries`'s header, then the body), so what assembles is exactly what the VM and the circuit
//! run; nothing here is trusted by a node (the code's id is its blake3, the contract's proof is the machine's).
//!
//! What protects it (AI RESISTANT): (b) ordinary code — an authoring tool; a wrong program only harms its own contract,
//! and every call it makes is still proven. SCALE: two passes over the source, bounded by the code bound.
//! Cons: none — the assembler writes nothing anywhere; it is f(the source text). The programs it builds keep their
//! state in their own contract, at most `W(h)` slots (33 at class 14), carried whole by each call: 33 × 1120 B = 37 KB a
//! call at class 14, a constant of the class, never a term in height or in how many calls came before.

use crate::dsol_vm::{entry_hash, op, DSOL_VERSION};

/// The immediate an opcode takes.
#[derive(Clone, Copy)]
enum Imm {
    None,
    U16,
    Label,
    Entry,
}

fn mnemonic(m: &str) -> Option<(u8, Imm)> {
    use Imm::{Entry, Label, None as N, U16};
    Some(match m {
        "pop" => (op::POP, N),
        "dup" => (op::DUP, N),
        "swap" => (op::SWAP, N),
        "add" => (op::ADD_U64, N),
        "sub" => (op::SUB_U64, N),
        "mul" => (op::MUL_U64, N),
        "div" => (op::DIV_U64, N),
        "mod" => (op::MOD_U64, N),
        "lt" => (op::LT, N),
        "eq" => (op::EQ, N),
        "not" => (op::NOT, N),
        "and" => (op::AND, N),
        "or" => (op::OR, N),
        "jump" => (op::JUMP, Label),
        "jumpi" => (op::JUMPI, Label),
        "return" => (op::RETURN, N),
        "revert" => (op::REVERT, N),
        "sload" => (op::SLOAD, N),
        "sstore" => (op::SSTORE, N),
        "sstore_priv" => (op::SSTORE_PRIV, N),
        "commit" => (op::COMMIT_U64, N),
        "nullifier" => (op::NULLIFIER, N),
        "syscall" => (op::SYSCALL, U16),
        "sender" => (op::MSG_SENDER, N),
        "subaddress" => (op::MSG_SUBADDRESS, N),
        "block" => (op::BLOCK_NUMBER, N),
        "contract" => (op::CONTRACT_ID, N),
        "tx_hash" => (op::TX_HASH, N),
        "poseidon" => (op::POSEIDON, N),
        "emit" => (op::EMIT, N),
        "local.get" => (op::LOCAL_GET, U16),
        "local.set" => (op::LOCAL_SET, U16),
        "locals" => (op::ALLOC_LOCALS, U16),
        "u64_from_bytes" => (op::U64_FROM_BYTES, N),
        "u64_to_bytes" => (op::U64_TO_BYTES, N),
        "map_load" => (op::MAP_LOAD, N),
        "map_store" => (op::MAP_STORE, N),
        "map_store_priv" => (op::MAP_STORE_PRIV, N),
        "concat" => (op::CONCAT, N),
        "len" => (op::BYTES_LEN, N),
        "str_eq" => (op::STR_EQ, N),
        "to_dec" => (op::U64_TO_DEC_STR, N),
        "mul_hi" => (op::MUL_HI, N),
        "adc" => (op::ADC, N),
        "sbb" => (op::SBB, N),
        "divmod128" => (op::DIVMOD128, N),
        "call" => (op::CALL, Entry),
        "libcall" => (op::LIBCALL, Entry),
        _ => return None,
    })
}

fn number(s: &str) -> Option<u64> {
    let s = s.replace('_', "");
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// A quoted string literal's bytes.
fn literal(s: &str) -> Result<Vec<u8>, String> {
    let body = s.strip_prefix('"').and_then(|t| t.strip_suffix('"')).ok_or("a string is written between double quotes")?;
    let mut out = Vec::with_capacity(body.len());
    let mut it = body.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            let mut b = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            continue;
        }
        out.push(match it.next() {
            Some('n') => b'\n',
            Some('t') => b'\t',
            Some('"') => b'"',
            Some('\\') => b'\\',
            _ => return Err("an unknown escape (use \\n \\t \\\" \\\\)".into()),
        });
    }
    if out.len() > usize::from(u16::MAX) {
        return Err("a string literal is too long".into());
    }
    Ok(out)
}

/// The line without its comment (a `;` outside a string).
fn code_of(line: &str) -> &str {
    let mut quoted = false;
    let mut esc = false;
    for (i, c) in line.char_indices() {
        if quoted && esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if quoted => esc = true,
            '"' => quoted = !quoted,
            ';' if !quoted => return line[..i].trim(),
            _ => {}
        }
    }
    line.trim()
}

/// ASSEMBLE a DSOL program into v2 bytecode. `Err` names the line and what is wrong with it.
pub fn assemble(src: &str) -> Result<Vec<u8>, String> {
    // pass 1: lay the body with every jump target at zero, recording where each label and entry sits
    let mut entries: Vec<(u32, u32)> = Vec::new();
    let mut labels: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut fixups: Vec<(usize, String, usize)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    for (n, raw) in src.lines().enumerate() {
        let line = code_of(raw);
        let at = |e: String| format!("line {}: {e}", n + 1);
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_suffix(':') {
            let (is_entry, name) = match name.strip_prefix("entry ") {
                Some(e) => (true, e.trim()),
                None => (false, name.trim()),
            };
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
                return Err(at(format!("`{name}` is not a name")));
            }
            let here = u32::try_from(body.len()).map_err(|_| at("the program is too long".into()))?;
            if is_entry {
                let sel = entry_hash(name.as_bytes());
                if entries.iter().any(|(s, _)| *s == sel) {
                    return Err(at(format!("entry `{name}` is defined twice")));
                }
                entries.push((sel, here));
            } else if labels.insert(name.to_string(), here).is_some() {
                return Err(at(format!("label `{name}` is defined twice")));
            }
            continue;
        }
        let (m, arg) = match line.split_once(char::is_whitespace) {
            Some((m, a)) => (m, a.trim()),
            None => (line, ""),
        };
        let m = m.to_ascii_lowercase();
        if m == "push" {
            if arg.starts_with('"') {
                let b = literal(arg).map_err(at)?;
                body.push(op::PUSH_BYTES);
                body.extend_from_slice(&(b.len() as u16).to_le_bytes());
                body.extend_from_slice(&b);
            } else {
                let v = number(arg).ok_or_else(|| at(format!("`{arg}` is not a number or a string")))?;
                body.push(op::PUSH_U64);
                body.extend_from_slice(&v.to_le_bytes());
            }
            continue;
        }
        let (code, imm) = mnemonic(&m).ok_or_else(|| at(format!("`{m}` is not an instruction")))?;
        body.push(code);
        match imm {
            Imm::None if !arg.is_empty() => return Err(at(format!("`{m}` takes nothing after it"))),
            Imm::None => {}
            Imm::U16 => {
                let v = number(arg).and_then(|v| u16::try_from(v).ok()).ok_or_else(|| at(format!("`{m}` takes a number up to 65535")))?;
                body.extend_from_slice(&v.to_le_bytes());
            }
            Imm::Label => {
                if arg.is_empty() {
                    return Err(at(format!("`{m}` takes a label")));
                }
                fixups.push((body.len(), arg.to_string(), n + 1));
                body.extend_from_slice(&0u32.to_le_bytes());
            }
            Imm::Entry => {
                if arg.is_empty() {
                    return Err(at(format!("`{m}` takes an entrypoint name")));
                }
                body.extend_from_slice(&entry_hash(arg.as_bytes()).to_le_bytes());
            }
        }
    }
    if entries.is_empty() {
        return Err("the program has no `entry NAME:`".into());
    }
    // pass 2: every target is an offset in the whole code, the header included
    let hdr = u32::try_from(5 + entries.len() * 8).map_err(|_| "too many entries".to_string())?;
    for (at, label, line) in fixups {
        let t = labels.get(&label).ok_or_else(|| format!("line {line}: no label `{label}`"))?;
        body[at..at + 4].copy_from_slice(&(t + hdr).to_le_bytes());
    }
    let mut out = vec![DSOL_VERSION];
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (sel, pc) in &entries {
        out.extend_from_slice(&sel.to_le_bytes());
        out.extend_from_slice(&(pc + hdr).to_le_bytes());
    }
    out.extend_from_slice(&body);
    Ok(out)
}

/// A guestbook back end: `post` keeps its argv (a message) under the next number and counts it; `last` returns the
/// newest message. The example a site's author starts from (Sovereign's Publish screen offers it) and the program the
/// real-node check `backend.py` hosts.
pub const GUESTBOOK: &str = r#"; A guestbook: every visitor's message, kept in order.
entry post:
    locals 2
    local.set 0          ; the message
    push "n"
    sload
    local.set 1          ; how many are kept
    push "m"
    local.get 1
    to_dec
    local.get 0
    map_store            ; m[count] = message
    push "n"
    local.get 1
    push 1
    add
    sstore               ; count + 1
    push "ok"
    return

entry last:
    pop
    push "m"
    push "n"
    sload
    push 1
    sub
    to_dec
    map_load
    return
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsol_vm::{run, str_digest, NoHost, StorageTrie, VmCtx, VmVal};

    #[test]
    fn the_guestbook_assembles_runs_and_reads_its_own_stored_text_back_on_a_later_call() {
        let code = assemble(GUESTBOOK).expect("assembles");
        assert_eq!(crate::dsol_vm::parse_entries(&code).unwrap().len(), 2);
        let mut storage = StorageTrie::default();
        for msg in [&b"hello from the first visitor"[..], b"and a second one"] {
            let t = run(&code, "post", msg, VmCtx::default(), storage.clone(), 1 << 18, &mut NoHost).expect("post runs");
            assert_eq!(t.run.ret, b"ok");
            storage = t.run.storage;
        }
        assert_eq!(storage.get(&str_digest(b"n")), Some(VmVal::Word(2)));
        let slot = crate::dsol_vm::map_slot(&str_digest(b"m"), &str_digest(b"1"));
        assert_eq!(storage.get(&slot), Some(VmVal::Str { digest: str_digest(b"and a second one"), len: 16 }));
        assert_eq!(storage.contents.get(&str_digest(b"and a second one")).map(Vec::as_slice), Some(&b"and a second one"[..]), "the written text rides the storage");
        // a LATER call reads the stored text and returns its bytes: the machine re-supplies them from the storage
        let t = run(&code, "last", b"", VmCtx::default(), storage.clone(), 1 << 18, &mut NoHost).expect("last runs");
        assert_eq!(t.run.ret, b"and a second one");
        // without the bytes, the same read cannot be run (the hole D4's string slots close)
        let mut bare = storage.clone();
        bare.contents.clear();
        assert!(run(&code, "last", b"", VmCtx::default(), bare, 1 << 18, &mut NoHost).is_err());
    }

    #[test]
    fn a_wrong_program_is_refused_with_its_line() {
        assert!(assemble("push 1\nreturn").unwrap_err().contains("no `entry"));
        assert!(assemble("entry main:\n  frob").unwrap_err().starts_with("line 2"));
        assert!(assemble("entry main:\n  jump nowhere").unwrap_err().contains("no label `nowhere`"));
        assert!(assemble("entry main:\n  push \"a;b\" ; a comment\n  return").is_ok(), "a ; inside a string is not a comment");
        assert!(assemble("entry main:\nentry main:\n return").unwrap_err().contains("twice"));
    }
}
