// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A NODE MUST NEVER GROW THE OPERATOR'S DISK WITH ITS OWN LOG.** Under a supervisor (launchd), fd 2
//! is an append-only file the supervisor opened; nothing rotates it. This module rotates it from INSIDE
//! the process: when the file behind fd 2 passes the cap, the current file is renamed to `<path>.1`
//! (replacing an older `.1`) and a fresh file is dup2'd onto fd 2. Worst case on disk: 2 × cap, forever.
//! MEASURED 2026-09-03 on the live pair: 52 MB and 70 MB after ~5 h, growing ~300 KB/min.

/// 16 MB per node per generation — days of the current line rate, minutes to read, bounded forever.
pub const STDERR_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Rotate `path` if it exceeds `cap`: `<path>.1` is replaced by the current file and a fresh file is
/// created at `path`. Returns the size that triggered the rotation. Pure file logic, unit-tested.
pub fn rotate_path_if_over(path: &std::path::Path, cap: u64) -> Option<u64> {
    let len = std::fs::metadata(path).ok()?.len();
    if len <= cap {
        return None;
    }
    let mut prev = path.as_os_str().to_owned();
    prev.push(".1");
    let prev = std::path::PathBuf::from(prev);
    let _ = std::fs::remove_file(&prev);
    std::fs::rename(path, &prev).ok()?;
    std::fs::OpenOptions::new().create(true).append(true).open(path).ok()?;
    Some(len)
}

/// Rotate the file behind fd 2 if it exceeds `cap`, re-pointing fd 2 at the fresh file in-process.
/// A no-op when fd 2 is a terminal/pipe (no path) or under the cap.
pub fn rotate_stderr_if_over(cap: u64) -> Option<u64> {
    let path = crate::oscall::path_of_stderr()?;
    let len = std::fs::metadata(&path).ok()?.len();
    if len <= cap {
        return None;
    }
    let n = rotate_path_if_over(&path, cap)?;
    let fresh = std::fs::OpenOptions::new().append(true).open(&path).ok()?;
    crate::oscall::replace_stderr_with(&fresh).ok()?;
    Some(n)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ Under the cap: untouched. Past the cap: the big file becomes `.1`, a fresh empty file takes its
    /// place, and a second rotation replaces the old `.1` — so disk never exceeds two generations.
    #[test]
    fn rotation_keeps_at_most_two_generations_and_never_touches_a_small_log() {
        let dir = std::env::temp_dir().join(format!("musd-logcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("node.err.log");
        std::fs::write(&p, vec![b'x'; 100]).unwrap();
        assert!(rotate_path_if_over(&p, 1_000).is_none(), "a small log is never rotated");
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 100);
        std::fs::write(&p, vec![b'a'; 5_000]).unwrap();
        assert_eq!(rotate_path_if_over(&p, 1_000), Some(5_000), "past the cap it rotates");
        let p1 = std::path::PathBuf::from(format!("{}.1", p.display()));
        assert_eq!(std::fs::metadata(&p1).unwrap().len(), 5_000, "the big file is now .1");
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 0, "a fresh file took its place");
        std::fs::write(&p, vec![b'b'; 3_000]).unwrap();
        assert_eq!(rotate_path_if_over(&p, 1_000), Some(3_000));
        assert_eq!(std::fs::metadata(&p1).unwrap().len(), 3_000, ".1 was REPLACED, not accumulated");
        assert!(!dir.join("node.err.log.2").exists(), "never a third generation");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
