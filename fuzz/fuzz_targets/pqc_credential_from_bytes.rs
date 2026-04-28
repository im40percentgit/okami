#![no_main]

// @decision DEC-OKAMI-022
// Fuzz target for PqcCredential::from_bytes.
// Contract: must NEVER panic on arbitrary input. Returning Err is correct for
// malformed bytes. DEC-OKAMI-016 allocation caps (4 KiB for credentials) must
// hold for crafted length prefixes. libFuzzer treats a panic as a discovered bug.

use libfuzzer_sys::fuzz_target;
use okami::identity::PqcCredential;

fuzz_target!(|data: &[u8]| {
    let _ = PqcCredential::from_bytes(data);
});
