// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 7 — KEEP-AWAKE, WITH CONSENT (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §22 7).
//!
//! A validator's duties need the machine awake. At "Become a validator" the wallet asks once whether to keep this computer
//! awake while validating; on yes, the node holds the operating system's own keep-awake for itself — only while it holds a
//! custody seat — and lets it go when validation stops or the consent is withdrawn. On no, it validates while awake and the
//! bench (§22 2) absorbs the sleep. Each platform's own mechanism, never a workaround:
//! - macOS: `caffeinate -s -w <pid>` — no system sleep while on power (a closed lid on battery still sleeps), released by the
//!   holder or by this process exiting;
//! - Linux: `systemd-inhibit --what=sleep --mode=block … sleep infinity`, released when the holder ends it;
//! - Windows: the inhibitor is a child PowerShell holding `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` until
//!   the holder ends it.
//!
//! Process-local by design: the consent is the operator's choice for this machine, never chain state.

/// The command that holds this platform's keep-awake for process `pid`, or `None` where none exists.
#[must_use]
pub fn command_for(os: &str, pid: u32) -> Option<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    match os {
        "macos" => Some(v(&["caffeinate", "-s", "-w", &pid.to_string()])),
        "linux" => Some(v(&[
            "systemd-inhibit",
            "--what=sleep",
            "--who=MonerousD validator",
            "--why=Validating: duties need this computer awake",
            "--mode=block",
            "sleep",
            "infinity",
        ])),
        "windows" => Some(v(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "Add-Type -Name P -Namespace W -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern uint \
             SetThreadExecutionState(uint f);'; [W.P]::SetThreadExecutionState(0x80000001) | Out-Null; \
             while ($true) { Start-Sleep -Seconds 3600 }",
        ])),
        _ => None,
    }
}

/// A held keep-awake: the platform's inhibitor runs until this is dropped.
pub struct KeepAwake {
    child: std::process::Child,
}

impl KeepAwake {
    /// Take this platform's keep-awake for this process. `None` where the platform has none or its tool is absent — the node
    /// then validates while the machine is awake, and the bench absorbs the rest.
    #[must_use]
    pub fn take() -> Option<Self> {
        let cmd = command_for(std::env::consts::OS, std::process::id())?;
        let (prog, args) = cmd.split_first()?;
        let child = std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(KeepAwake { child })
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ §22 7 — each platform's own keep-awake, tied to this process where the platform allows it: macOS prevents system
    /// sleep (on power) for exactly this pid, Linux blocks sleep through logind, Windows requests the system stay on; a
    /// platform with no mechanism gets none (the bench absorbs the sleep, never a workaround).
    /// TWO-PARTY-REVIEWED: a local OS facility with no second endpoint — the duty it protects is pinned across nodes in
    /// node::pins::a_validator_inactive_for_seven_days_is_unbonded_without_slash_on_every_node.
    #[test]
    fn each_platform_holds_its_own_keep_awake_for_this_process() {
        assert_eq!(command_for("macos", 4242), Some(vec!["caffeinate".into(), "-s".into(), "-w".into(), "4242".into()]));
        let linux = command_for("linux", 1).expect("linux");
        assert_eq!(linux[0], "systemd-inhibit");
        assert!(linux.contains(&"--what=sleep".to_string()) && linux.contains(&"--mode=block".to_string()));
        let win = command_for("windows", 1).expect("windows");
        assert!(win[0] == "powershell" && win[3].contains("SetThreadExecutionState(0x80000001)"), "ES_CONTINUOUS | ES_SYSTEM_REQUIRED");
        assert_eq!(command_for("ios", 1), None);
        assert_eq!(command_for("android", 1), None);
    }
}
