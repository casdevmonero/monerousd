// MonerousD Protocol — RED-then-GREEN tamper test of the monotone-persist refusal in `persist::save`.
//
// The snapshot is the node's ONE fixed-size resume checkpoint — a singleton, single-slot file that
// overwrites in place (never per-item, never growing; the node's authority stays the recursive proof).
// The save gate REFUSES a write lighter than the heaviest (blue_score, height) this process has loaded
// or saved for that path — heaviest = highest cumulative blue score, the DAG's longest-chain
// generalization. A lighter write is the banned island-clobber shape, and this guard-class test proves
// the refusal fires and that honest heavier saves still land.
//
// ⛔ MEASURED 2026-08-13 on the live desktop node: a mis-spawned twin process produced ~300 island
// blocks and overwrote the 111,797-block checkpoint at exit; the next boot "resumed" the island and the
// tall chain's local state was gone. That exact shape is the RED case below.

use usdmd_node::persist;

fn scratch(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()))
        .join(format!("musd-{name}-{}", std::process::id()))
}

#[test]
fn a_lighter_snapshot_can_never_overwrite_the_tall_checkpoint() {
    let dir = scratch("monotone");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("state-test.snap");

    let node = usdmd_node::node::Node::new(usdmd_node::block::genesis_block()).unwrap();
    let island = node.export_snapshot().expect("genesis snapshot");
    // The persistence gate compares these two counters. Genesis already has its minimum weight.
    let mut tall = node.export_snapshot().expect("incumbent snapshot");
    tall.blue_score = island.blue_score + 1;
    tall.height = island.height + 1;

    persist::save(&path, &tall).expect("tall checkpoint saves");
    let on_disk = persist::load(&path).expect("tall checkpoint loads back");
    assert_eq!(
        (on_disk.blue_score, on_disk.height),
        (tall.blue_score, tall.height),
        "round-trips"
    );

    // RED: the ISLAND — same path, lighter weight, the exact measured clobber shape. Must be REFUSED.
    assert!(
        (island.blue_score, island.height) < (tall.blue_score, tall.height),
        "candidate must be strictly lighter: candidate {:?}, incumbent {:?}",
        (island.blue_score, island.height),
        (tall.blue_score, tall.height),
    );
    persist::save(&path, &island).expect("refusal returns Ok so shutdown paths still complete");
    let after = persist::load(&path).expect("checkpoint still present");
    assert_eq!(
        (after.blue_score, after.height),
        (tall.blue_score, tall.height),
        "the lighter island write must NOT replace the tall checkpoint"
    );

    // GREEN: a genuinely HEAVIER checkpoint still saves — monotone, never frozen.
    let mut heavier = node.export_snapshot().expect("snapshot again");
    heavier.blue_score = tall.blue_score + 1;
    heavier.height = tall.height + 1;
    persist::save(&path, &heavier).expect("heavier saves");
    let after2 = persist::load(&path).expect("loads");
    assert_eq!(
        (after2.blue_score, after2.height),
        (heavier.blue_score, heavier.height),
        "a heavier checkpoint replaces the old one normally"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
