// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ THE ONE-CLICK WALLET UPDATE (lane speed5, 2026-11-18; user: "is there a way for testers to receive over the air optional
//! wallet updates so they dont have to keep redownloading the wallet" · "lets build the one click ota update for the wallet now
//! and then prove that it works and then release it on all platforms").
//!
//! OPTIONAL, NEVER SILENT (user 2026-10-05: "the nodes auto receiving updates comes with its own exploits … bitcoins model"): the
//! wallet LOOKS for a release and SHOWS it; nothing is downloaded or installed until the person presses Install.
//!
//! THE CHAIN OF TRUST, every link checked here:
//! 1. `wallet-manifest.json` and its `wallet-manifest.json.sig` come from the project's GitHub release download
//!    (`DEFAULT_BASE`), fetched over a Tor exit (`tor::https_get`): GitHub sees a Tor exit, never this device.
//! 2. The signature is ML-DSA-65 by the release key whose public half is compiled in (`release_pubkey.bin`), over
//!    `MANIFEST_DOMAIN ‖ the manifest's exact bytes` (the release tool `wallet_release sign` writes it). A manifest that
//!    does not verify is refused, whatever it says.
//! 3. The manifest names, per platform, the file, its exact size and its blake3. The downloaded file is refused unless both
//!    match before anything runs.
//! 4. Only a version strictly newer than this build's is offered.
//!
//! ROOT-LAYER: this module is where a release is PRODUCED for this device (fetched, verified, written, handed to the OS) — the
//! one place; the UI only asks `update_check` / `update_install` and shows their answer.
//! MUST-STAY-GREEN: this module's three tests (a tampered manifest, a foreign key and a swapped file are refused).
//! AI RESISTANT: (a) for the file — a release is installed only when the compiled-in key signed the statement "this is version
//! V, these are its files and hashes"; a lying server, a swapped file or a persuasive page gains nothing, since the most it can
//! do is make this wallet install the genuine signed latest release. (c) for the key — one release key on one machine signs
//! today, named plainly; before real funds it becomes a threshold of keys on separate machines (charter §2).
//! PRIVACY: the request is a fixed URL with a fixed User-Agent over Tor; it carries no address, balance, note or identity.
//! Disk: ONE installer at a time (today's ~45–110 MB, at most 400 MB) in the app's cache folder, deleted when the next update
//! downloads — 0 B/year of growth. Network: the manifest (~1 KB) and its signature (3,309 B) per check, the installer once per
//! update the person accepts, all over Tor.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The domain every release signature covers — the same bytes as the node crate's `wallet_release` tool.
pub const MANIFEST_DOMAIN: &[u8] = b"MUSD-wallet-release-v1\0";
/// The release key's public half (ML-DSA-65, 1,952 bytes). Its secret half never leaves the release machine.
const RELEASE_PK: &[u8] = include_bytes!("release_pubkey.bin");
/// The project's latest release download: the manifest, its signature and every installer are assets of one release.
const DEFAULT_BASE: &str = "https://github.com/casdevmonero/monerousd/releases/latest/download/";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SIG_BYTES: usize = 8 * 1024;
const MAX_ASSET_BYTES: u64 = 400 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub product: String,
    pub version: String,
    #[serde(default)]
    pub notes: String,
    pub assets: BTreeMap<String, Asset>,
}

/// Where releases are read from. `MONEROUSD_UPDATE_BASE` may point the wallet at a release folder served on THIS machine
/// (`http://127.0.0.1:<port>/`) — the proof's local server; any other override is refused, so nothing but GitHub over Tor or
/// this machine's own loopback is ever asked.
fn base() -> Result<String, String> {
    match std::env::var("MONEROUSD_UPDATE_BASE") {
        Ok(b) if !b.is_empty() => {
            let ok = b.starts_with("http://127.0.0.1:") && b.ends_with('/');
            if ok { Ok(b) } else { Err("MONEROUSD_UPDATE_BASE must be http://127.0.0.1:<port>/ (this machine only)".into()) }
        }
        _ => Ok(DEFAULT_BASE.to_string()),
    }
}

fn get(url: &str, max: usize, timeout_s: u64) -> Result<Vec<u8>, String> {
    if url.starts_with("http://127.0.0.1:") {
        let resp = ureq::get(url).timeout(std::time::Duration::from_secs(timeout_s)).call().map_err(|e| format!("{e}"))?;
        let mut body = Vec::new();
        use std::io::Read;
        resp.into_reader().take(max as u64 + 1).read_to_end(&mut body).map_err(|e| format!("{e}"))?;
        if body.len() > max {
            return Err(format!("refused: larger than {max} bytes"));
        }
        return Ok(body);
    }
    // A Tor exit can fail one stream (MEASURED 2026-11-19 on the published release: "remote hostname lookup failure" on the
    // first try, the manifest read and verified on the next): each attempt takes a fresh isolated circuit (`https_get`).
    let mut last = String::new();
    for _ in 0..3 {
        match crate::tor::https_get(url, max, timeout_s) {
            Ok(b) => return Ok(b),
            Err(e) if e.starts_with("refused") => return Err(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The manifest's key for the platform this build runs on.
pub fn platform_key() -> &'static str {
    if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") { "macos-aarch64" } else { "macos-x86_64" }
    } else if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else if std::env::var_os("APPIMAGE").is_some() {
        "linux-x86_64-appimage"
    } else {
        "linux-x86_64-deb"
    }
}

/// `a > b` for dotted numeric versions ("0.3.0" > "0.2.9"); anything that does not parse is never newer.
pub fn newer(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Option<Vec<u64>> { v.trim_start_matches('v').split('.').map(|p| p.parse().ok()).collect() };
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x > y,
        _ => false,
    }
}

/// The signed manifest, verified: the signature under the compiled-in key, then the product. `Err` says why it was refused.
pub fn verified_manifest(body: &[u8], sig: &[u8], pk: &[u8]) -> Result<Manifest, String> {
    let mut msg = MANIFEST_DOMAIN.to_vec();
    msg.extend_from_slice(body);
    if !usdmd_node::pqauth::ml_dsa_verify(&msg, pk, sig) {
        return Err("refused: the release manifest is not signed by the MonerousD release key".into());
    }
    let m: Manifest = serde_json::from_slice(body).map_err(|e| format!("refused: the signed manifest does not parse ({e})"))?;
    if m.product != "monerousd-wallet" {
        return Err("refused: the signed manifest is not a wallet release".into());
    }
    Ok(m)
}

/// One downloaded file against the signed manifest's entry: exact size, then blake3.
pub fn file_matches(bytes: &[u8], a: &Asset) -> Result<(), String> {
    if bytes.len() as u64 != a.size {
        return Err(format!("refused: {} is {} bytes, the signed release says {}", a.name, bytes.len(), a.size));
    }
    let h = blake3::hash(bytes).to_hex().to_string();
    if !h.eq_ignore_ascii_case(&a.blake3) {
        return Err(format!("refused: {} does not match the signed release's hash", a.name));
    }
    Ok(())
}

/// A file name the manifest may name: plain, no path (a signed manifest still never chooses where a file lands).
fn safe_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 200 && !n.contains('/') && !n.contains('\\') && !n.starts_with('.') && n != ".."
}

fn fetch_manifest() -> Result<Manifest, String> {
    let b = base()?;
    let body = get(&format!("{b}wallet-manifest.json"), MAX_MANIFEST_BYTES, 180)?;
    let sig = get(&format!("{b}wallet-manifest.json.sig"), MAX_SIG_BYTES, 180)?;
    verified_manifest(&body, &sig, RELEASE_PK)
}

/// `update_check`: `{available, version, notes, size, current}` — never downloads an installer.
pub fn check() -> Result<serde_json::Value, String> {
    let current = env!("CARGO_PKG_VERSION");
    let m = fetch_manifest()?;
    let asset = m.assets.get(platform_key()).cloned();
    let available = newer(&m.version, current) && asset.is_some();
    Ok(serde_json::json!({
        "available": available,
        "version": m.version,
        "current": current,
        "notes": m.notes,
        "size": asset.as_ref().map(|a| a.size),
        "platform": platform_key(),
    }))
}

/// `update_install`: fetch and verify the manifest again (never a cached offer), download this platform's file, check its
/// size and blake3, then hand it to the system. Returns what happens next for the person to read.
pub fn install() -> Result<serde_json::Value, String> {
    let current = env!("CARGO_PKG_VERSION");
    let m = fetch_manifest()?;
    if !newer(&m.version, current) {
        return Err(format!("this wallet ({current}) is already the latest release"));
    }
    let a = m.assets.get(platform_key()).cloned().ok_or("the release has no file for this system")?;
    if !safe_name(&a.name) || a.size > MAX_ASSET_BYTES {
        return Err("refused: the signed release names a file this wallet will not write".into());
    }
    let bytes = get(&format!("{}{}", base()?, a.name), a.size as usize, 3600)?;
    file_matches(&bytes, &a)?;
    let dir = dirs::cache_dir().ok_or("no cache folder on this system")?.join("MoneroUSD").join("updates");
    // the previous installer is removed first, so one file is ever kept
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("the update folder: {e}"))?;
    let file = dir.join(&a.name);
    std::fs::write(&file, &bytes).map_err(|e| format!("could not write the update: {e}"))?;
    hand_to_system(&file, &m.version)
}

/// The wallet's OWN node service (its per-port launchd label, `lib.rs` `start_node_service`): restarted after an update so it
/// runs the new release's node from the replaced bundle (the same path, so launchd's definition is unchanged). Never the
/// origin's classic `org.monerousd.node` label.
#[cfg(target_os = "macos")]
fn node_label() -> String {
    let u = crate::node_url();
    let port = u.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse::<u16>().ok()).unwrap_or(27780);
    format!("org.monerousd.node-{port}")
}

/// ⭐ UPDATE-TO-APPLICATIONS (lane livediag, 2026-11-27; user: "downloading the update should auto update the mac build version as
/// well") — THE BUNDLE AN UPDATE REPLACES IS THE INSTALLED ONE. A wallet run from anywhere but `/Applications` (a mounted disk
/// image's folder copy, Downloads, a build folder) updates `/Applications/<name>.app` and reopens from there, so the copy the
/// person opens from Launchpad and the Dock is the one that moves.
/// MEASURED why (2026-11-27): a tester's wallet ran from a build folder since Nov 22; its update replaced that folder's copy
/// (now 0.3.6) and `/Applications/MoneroUSD Wallet.app` stayed 0.3.3, so the next launch from Applications would open 0.3.3.
/// BORROWED: macOS's move-to-Applications pattern (LetsMove, used with Sparkle updates). The reopened wallet re-points its own node
/// service at its bundle on start (`lib.rs` `start_node_service` replaces a definition naming another binary), so the node
/// follows. Where `/Applications` cannot be written, the running bundle is replaced as before (nothing is lost, nothing waits).
/// AI RESISTANT: (b) code — the bundle written is still only the signed, hash-checked release (`hand_to_system`'s callers).
/// SCALE: one probe file write and remove, once per accepted update. LONG-TERM: nothing is kept; the old copy is left where it was.
#[cfg(target_os = "macos")]
fn install_target(running: &std::path::Path) -> std::path::PathBuf {
    let apps = std::path::Path::new("/Applications");
    if running.starts_with(apps) {
        return running.to_path_buf();
    }
    let Some(name) = running.file_name() else { return running.to_path_buf() };
    let probe = apps.join(format!(".musd-update-probe-{}", std::process::id()));
    let writable = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    if writable {
        apps.join(name)
    } else {
        running.to_path_buf()
    }
}

#[cfg(target_os = "macos")]
fn hand_to_system(file: &std::path::Path, version: &str) -> Result<serde_json::Value, String> {
    // The running app's bundle: …/MoneroUSD Wallet.app/Contents/MacOS/<exe>
    let exe = std::env::current_exe().map_err(|e| format!("{e}"))?;
    let app = exe.ancestors().nth(3).ok_or("this wallet is not running from an app bundle")?.to_path_buf();
    if app.extension().and_then(|x| x.to_str()) != Some("app") {
        return Err("this wallet is not running from an app bundle; open the downloaded file to update".into());
    }
    let app = install_target(&app);
    let mnt = std::env::temp_dir().join(format!("musd-update-{}", std::process::id()));
    // A helper that outlives this process: wait for the wallet to quit, replace the bundle from the verified image (a disk image,
    // or the zip the release ships), restart the wallet's own node on the new release's binary, relaunch.
    let script = format!(
        r#"set -e
while kill -0 {pid} 2>/dev/null; do sleep 0.5; done
mkdir -p "{mnt}"
case "{dmg}" in
  *.zip) ditto -x -k "{dmg}" "{mnt}" ;;
  *) hdiutil attach -nobrowse -readonly -mountpoint "{mnt}" "{dmg}" >/dev/null ;;
esac
src=$(ls -d "{mnt}"/*.app | head -1)
rm -rf "{app}.updating" && ditto "$src" "{app}.updating"
hdiutil detach "{mnt}" >/dev/null 2>&1 || rm -rf "{mnt}"
rm -rf "{app}" && mv "{app}.updating" "{app}"
# MONEROUSD_UPDATE_RELAUNCH=0 (the proof on a developer Mac only): the bundle is replaced, nothing is restarted or reopened, so a
# test copy never starts a second wallet against the developer's own wallet data and node services
if [ "${{MONEROUSD_UPDATE_RELAUNCH:-1}}" != 0 ]; then
  launchctl kickstart -k "gui/$(id -u)/{label}" >/dev/null 2>&1 || true
  open "{app}"
fi
"#,
        label = node_label(),
        pid = std::process::id(),
        mnt = mnt.display(),
        dmg = file.display(),
        app = app.display()
    );
    spawn_helper(&script)?;
    Ok(serde_json::json!({ "ok": true, "version": version, "next": "restart", "message": format!("Installing version {version}: the wallet closes and reopens on its own.") }))
}

#[cfg(target_os = "windows")]
fn hand_to_system(file: &std::path::Path, version: &str) -> Result<serde_json::Value, String> {
    // The NSIS installer replaces the installed wallet and its bundled node. The node's .exe is in use while it runs, so the
    // wallet's own node is stopped first (on a tester's PC the only usdmd-node); the wallet starts it again when it reopens.
    let _ = std::process::Command::new("taskkill").args(["/IM", "usdmd-node.exe", "/F"]).output();
    std::process::Command::new(file).spawn().map_err(|e| format!("starting the installer: {e}"))?;
    Ok(serde_json::json!({ "ok": true, "version": version, "next": "restart", "message": format!("The installer for version {version} is open; the wallet closes so it can update.") }))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn hand_to_system(file: &std::path::Path, version: &str) -> Result<serde_json::Value, String> {
    if let Some(image) = std::env::var_os("APPIMAGE") {
        // An AppImage replaces itself: the verified image takes the running one's path, then starts.
        let image = std::path::PathBuf::from(image);
        let next = image.with_extension("AppImage.updating");
        std::fs::copy(file, &next).map_err(|e| format!("{e}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o755)).map_err(|e| format!("{e}"))?;
        let script = format!(
            "while kill -0 {pid} 2>/dev/null; do sleep 0.5; done\nmv \"{next}\" \"{image}\"\nsystemctl --user restart monerousd-node.service >/dev/null 2>&1 || true\n\"{image}\" >/dev/null 2>&1 &\n",
            pid = std::process::id(),
            next = next.display(),
            image = image.display()
        );
        spawn_helper(&script)?;
        return Ok(serde_json::json!({ "ok": true, "version": version, "next": "restart", "message": format!("Installing version {version}: the wallet closes and reopens on its own.") }));
    }
    // A .deb needs the system's package installer (it asks for the administrator's password itself).
    std::process::Command::new("xdg-open").arg(file).spawn().map_err(|e| format!("opening the package: {e}"))?;
    Ok(serde_json::json!({ "ok": true, "version": version, "next": "installer", "message": format!("Your system's installer is open for version {version}; restart the wallet when it finishes.") }))
}

#[cfg(unix)]
fn spawn_helper(script: &str) -> Result<(), String> {
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("starting the update: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(m: &serde_json::Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (pk, sk) = usdmd_node::pqauth::ml_dsa_keypair();
        let body = serde_json::to_vec(m).unwrap();
        let mut msg = MANIFEST_DOMAIN.to_vec();
        msg.extend_from_slice(&body);
        (body, usdmd_node::pqauth::ml_dsa_sign(&msg, &sk).unwrap(), pk)
    }

    fn manifest(blake: &str, size: u64) -> serde_json::Value {
        serde_json::json!({ "product": "monerousd-wallet", "version": "9.9.9", "notes": "n",
            "assets": { platform_key(): { "name": "w.dmg", "size": size, "blake3": blake } } })
    }

    /// A signed manifest verifies; one byte changed, a foreign key, or another product is refused (the tamper test).
    #[test]
    fn a_release_is_taken_only_under_the_release_key_and_refused_when_tampered() {
        let (body, sig, pk) = signed(&manifest("00", 1));
        assert!(verified_manifest(&body, &sig, &pk).is_ok());
        let mut bad = body.clone();
        let i = bad.iter().position(|b| *b == b'9').unwrap();
        bad[i] = b'8';
        assert!(verified_manifest(&bad, &sig, &pk).is_err(), "a changed manifest verified");
        let (other_pk, _) = usdmd_node::pqauth::ml_dsa_keypair();
        assert!(verified_manifest(&body, &sig, &other_pk).is_err(), "another key's manifest verified");
        let (wbody, wsig, wpk) = signed(&serde_json::json!({ "product": "x", "version": "1", "assets": {} }));
        assert!(verified_manifest(&wbody, &wsig, &wpk).is_err(), "a non-wallet product was taken");
        assert!(verified_manifest(&body, &sig, RELEASE_PK).is_err(), "a test key's manifest verified under the release key");
    }

    /// A file is taken only at the signed size and hash.
    #[test]
    fn a_download_is_taken_only_at_the_signed_size_and_hash() {
        let file = b"installer bytes";
        let a = Asset { name: "w.dmg".into(), size: file.len() as u64, blake3: blake3::hash(file).to_hex().to_string() };
        assert!(file_matches(file, &a).is_ok());
        assert!(file_matches(b"installer bytez", &a).is_err(), "a swapped file was taken");
        assert!(file_matches(b"installer byte", &a).is_err(), "a short file was taken");
    }

    #[test]
    fn only_a_newer_version_is_offered_and_names_stay_plain() {
        assert!(newer("0.3.0", "0.2.0") && newer("0.10.0", "0.9.9") && !newer("0.2.0", "0.2.0") && !newer("x", "0.1.0"));
        assert!(safe_name("MoneroUSD-Wallet-macOS-testnet.dmg") && !safe_name("../x") && !safe_name("a/b") && !safe_name(".hidden"));
    }
}
