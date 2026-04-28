#![no_main]

// @decision DEC-OKAMI-022
// Fuzz target for SignedAuditEvent::from_bytes.
// Contract: must NEVER panic on arbitrary input. Returning Err is correct for
// malformed bytes. DEC-OKAMI-016 allocation caps (16 KiB for audit events) must
// hold for crafted length prefixes. libFuzzer treats a panic as a discovered bug.

use libfuzzer_sys::fuzz_target;
use okami::audit::SignedAuditEvent;

fuzz_target!(|data: &[u8]| {
    let _ = SignedAuditEvent::from_bytes(data);
});
