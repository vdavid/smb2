#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    smb2::fuzzing::fuzz_fs_attributes_parse(data);
});
