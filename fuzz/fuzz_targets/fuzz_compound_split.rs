#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    smb2::fuzzing::fuzz_compound_split(data);
});
