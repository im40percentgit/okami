#![no_main]

// @decision DEC-OKAMI-022
// Fuzz target for SpiffeId::parse.
// Contract: must NEVER panic on arbitrary input. The function accepts &str so we
// attempt UTF-8 conversion first; invalid UTF-8 yields Err before parse is even
// called. Returning Err for malformed SPIFFE URIs is correct. libFuzzer treats
// a panic as a discovered bug.

use libfuzzer_sys::fuzz_target;
use okami::identity::SpiffeId;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = SpiffeId::parse(s);
    }
});
