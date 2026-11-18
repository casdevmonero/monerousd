// Protocol: MonerousD — decode-door fuzz target `name_registry_file` (B1 (ii)): libFuzzer bytes through the production decoder
// behind `usdmd_node::decode_doors::NAME_REGISTRY_FILE`. A panic, a timeout or an allocation past the run's limits is a crash input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = std::hint::black_box(usdmd_node::decode_doors::drive(usdmd_node::decode_doors::NAME_REGISTRY_FILE, data));
});
