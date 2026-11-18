// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// Declaring the app commands in the manifest turns on Tauri's ACL for app commands: the wallet's OWN window is
// granted every command by capabilities/default.json, while an EMBEDDED dApp origin (ion.monerousd.org … / the
// sovereign node mirror) is granted ONLY the `dapp_provider_*` bridge by capabilities/dapp.json — so a remote page
// can reach `window.monerousd` (connect / balance / chain RPC) but never the wallet's private commands.
fn main() {
    emit_build_stamp();
    embed_info_plist();
    emit_app_sites();
    let commands = app_commands();
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(commands)))
        .expect("failed to run tauri-build");
}

/// ⭐⭐⭐ THE APP'S COMMANDS, READ FROM THE ONE LIST THE APP REGISTERS — and a build that REFUSES a command its own window
/// is not granted (found 2026-11-10 by the audit lane).
///
/// THE DEFECT THIS CLOSES. Declaring commands here turns on the framework's permission check for app commands: a command
/// its window holds no `allow-…` permission for is refused at run time, in every real build, with "not allowed by ACL"
/// (tauri 2.11 `webview/mod.rs`: `has_app_acl_manifest && invoke.acl.is_none()` → reject). The list that stood here was
/// written by hand and last touched on 2026-10-22; the app registers 185 commands (`wallet_invoke_handler!`) and this
/// list named 66 of them. So the app refused its own cash-out, coin swap, SAT market, borrowing, private deposit,
/// purchases, sales, Veil and proof-tag commands, on the desktop and on the phone, while every harness check (which
/// calls the Rust functions directly and never passes this door) stayed green.
///
/// THE FIX IS ONE SOURCE. The manifest's list is DERIVED from `wallet_invoke_handler!` in `src/lib.rs`, the list the app
/// actually registers, so a command cannot be registered and left undeclared. And the wallet window's capability
/// (`capabilities/default.json`, which grants the wallet's own UI every app command) is CHECKED against the same list
/// here: a registered command the capability does not grant fails the BUILD, naming it, instead of failing a user.
/// O1-INFINITY-REVIEWED: a BUILD-time read of this crate's own source and capability file on the build machine; no node
/// or wallet state is read from disk, at build time or at run time.
fn app_commands() -> &'static [&'static str] {
    let source = std::fs::read_to_string("src/lib.rs").expect("the wallet's source is beside its build script");
    let at = source.find("macro_rules! wallet_invoke_handler").expect("src/lib.rs registers its commands in wallet_invoke_handler!");
    let body = &source[at..];
    let open = body.find("tauri::generate_handler![").expect("wallet_invoke_handler! expands to generate_handler!") + "tauri::generate_handler![".len();
    let close = body[open..].find(']').expect("the command list closes");
    let mut names: Vec<&'static str> = body[open..open + close]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("#["))
        .filter_map(|l| l.split("//").next())
        .map(|l| l.trim().trim_end_matches(','))
        .filter_map(|l| l.rsplit("::").next())
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        .map(|n| &*Box::leak(n.to_string().into_boxed_str()))
        .collect();
    names.sort_unstable();
    names.dedup();
    assert!(names.len() > 100, "wallet_invoke_handler! read as {} commands: its format changed and this reader must follow", names.len());
    let granted = std::fs::read_to_string("capabilities/default.json").expect("the wallet window's capability file");
    println!("cargo:rerun-if-changed=capabilities/default.json");
    let missing: Vec<&str> = names.iter().copied().filter(|n| !granted.contains(&format!("\"allow-{}\"", n.replace('_', "-")))).collect();
    assert!(
        missing.is_empty(),
        "capabilities/default.json does not grant {} registered command(s) to the wallet's own window, so the app would \
         refuse them at run time (\"not allowed by ACL\"): add \"allow-<name-with-dashes>\" for each of {:?}",
        missing.len(),
        missing
    );
    Box::leak(names.into_boxed_slice())
}

/// ⭐ THE LAUNCHPAD'S APPS, COMPILED INTO A PHONE BUILD (user 2026-11-10: the phone's apps "have no way" to work and many
/// features said to open the desktop wallet).
///
/// The launchpad's apps are served by the node's site host on loopback. The desktop wallet starts that host as a second
/// process and hands it a `sites/` directory; a phone can do neither (no second process, no directory beside the binary),
/// so every app tile on a phone pointed at a port nothing listened on, and each app, finding no wallet, told the user to
/// install the desktop wallet. This writes the table a phone build compiles in: every file of every app the launchpad
/// lists, by `include_bytes!`, so the phone's in-process host (`lib.rs`, `embedded_site_server`) serves the same bytes
/// the desktop's does. The table is compiled only under `cfg(any(ios, android, test))`: a desktop build takes none of it.
///
/// Left out: backups and hidden files, and any single file above 4 MB (one: the website's 28.8 MB film, whose page
/// shows its poster instead). cons: about 20 MB of app size on a phone, and the same again in RAM while the host runs
/// (constant: it does not move with height, blocks or notes).
///
/// LOCAL-STORAGE-REQUIRED: this is the BUILD script, not the wallet: it writes cargo's own generated-source file in
/// OUT_DIR (the include table), which exists only on the build machine. Nothing at run time writes or reads a file here.
/// bound: one generated file per build, about 60 KB of source lines; no term in height, blocks or notes.
/// O1-INFINITY-REVIEWED: a BUILD-time walk of the app sources on the build machine (a fixed list of seven directories
/// named below); no node or wallet state is read from disk, at build time or at run time.
fn emit_app_sites() {
    use std::fmt::Write as _;
    const SITES: [&str; 7] = [
        "ionswap-monerousd-org",
        "explorer-monerousd-org",
        "ide-monerousd-org",
        "letter-monerousd-org",
        "faucet-monerousd-org",
        "monerousd-org",
        "usdm-pay",
    ];
    const FILE_MAX: u64 = 4 * 1024 * 1024;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../monerousd-node-zkdag/sites");
    let mut out = String::from("pub static APP_SITES: &[(&str, &[(&str, &[u8])])] = &[\n");
    for site in SITES {
        let site_root = root.join(site);
        println!("cargo:rerun-if-changed={}", site_root.display());
        let mut files: Vec<(String, std::path::PathBuf)> = Vec::new();
        let mut stack = vec![site_root.clone()];
        while let Some(folder) = stack.pop() {
            let Ok(listing) = std::fs::read_dir(&folder) else { continue }; // O1-INFINITY-REVIEWED: build-time source walk
            for entry in listing.flatten().map(|e| e.path()) {
                let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                if name.starts_with('.') || name.contains(".bak") || name.contains(".pre") {
                    continue;
                }
                if entry.is_dir() {
                    stack.push(entry);
                    continue;
                }
                if std::fs::metadata(&entry).map(|m| m.len() > FILE_MAX).unwrap_or(true) {
                    continue;
                }
                let Ok(rel) = entry.strip_prefix(&site_root) else { continue };
                files.push((format!("/{}", rel.to_string_lossy().replace('\\', "/")), entry.clone()));
            }
        }
        files.sort(); // one table whatever order the filesystem lists in
        let _ = writeln!(out, "    ({site:?}, &[");
        for (served, source) in &files {
            println!("cargo:rerun-if-changed={}", source.display());
            let abs = source.canonicalize().unwrap_or_else(|_| source.clone());
            let _ = writeln!(out, "        ({served:?}, include_bytes!({:?})),", abs.display().to_string());
        }
        out.push_str("    ]),\n");
    }
    out.push_str("];\n");
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("app_sites.rs");
    std::fs::write(&dest, out).expect("write the app-site table into OUT_DIR");
}

// ⛔ EMBED THE BLUETOOTH USAGE DESCRIPTION INTO THE BARE BINARY.
//
// macOS TCC does not merely DENY a process with no usage description — it SIGABRTs it. Measured: the
// `wallet-harness` binary died with EXC_CRASH the instant it took the CoreBluetooth PERIPHERAL role, and the
// crash report said exactly why: "The app's Info.plist must contain an NSBluetoothAlwaysUsageDescription
// key". A bare Mach-O has no Info.plist, so a CLI that touches the radio cannot run at all outside a bundle.
//
// The linker can carry one: `-sectcreate __TEXT __info_plist <file>` embeds it in the executable itself, and
// TCC reads it from there. This is what makes the two-process tap runnable at all — merchant and payer are
// CLI processes, not app bundles.
#[cfg(target_os = "macos")]
fn embed_info_plist() {
    let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Info.plist");
    if plist.exists() {
        println!("cargo:rerun-if-changed=Info.plist");
        println!(
            "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn embed_info_plist() {}

/// ⛔⛔⛔ EVERY BUILD STAMPS ITS OWN BUILD TIME AND SOURCE FINGERPRINT.
///
/// Nothing here carried a build date, so "is this binary running live code?" could only ever be guessed —
/// and guessing wrong cost a whole afternoon: a wallet built from new code was driven against a node binary
/// built from old code, and the resulting rejections were blamed on the protocol through two wrong diagnoses.
/// A user hits the same wall in a worse form: an app that looks current, behaves like an old one, and gives
/// them no way to tell.
///
/// The fingerprint is over the SOURCE, not the clock, so it changes iff the code changed. The timestamp says
/// WHEN, the fingerprint says WHAT — together they make staleness visible instead of inferable.
fn emit_build_stamp() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("cargo:rustc-env=MONEROUSD_BUILD_UNIX={secs}");

    // Source fingerprint: every .rs under src/, hashed by (path, len, mtime). Cheap, and it moves the instant
    // any source moves — which is precisely the question "is this build current?" asks.
    let mut acc: u64 = 0xcbf29ce484222325;
    let mut stack = vec![std::path::PathBuf::from("src")];
    let mut files = 0u64;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort(); // deterministic: directory order is not stable across filesystems
        for path in entries {
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            files += 1;
            let mut feed = path.display().to_string();
            if let Ok(m) = std::fs::metadata(&path) {
                feed.push_str(&m.len().to_string());
                if let Ok(t) = m.modified().and_then(|t| t.duration_since(UNIX_EPOCH).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))) {
                    feed.push_str(&t.as_secs().to_string());
                }
            }
            for b in feed.as_bytes() {
                acc ^= *b as u64;
                acc = acc.wrapping_mul(0x100000001b3);
            }
        }
    }
    println!("cargo:rustc-env=MONEROUSD_SRC_FINGERPRINT={acc:016x}");
    println!("cargo:rustc-env=MONEROUSD_SRC_FILES={files}");
    // Re-run whenever any source changes, so the stamp can never go stale while the binary is rebuilt.
    println!("cargo:rerun-if-changed=src");
}
