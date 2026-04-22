#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    smb2::fuzzing::fuzz_create_request_parse(data);
});
