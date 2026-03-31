#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fuzz_target!(|data: &str| {
    let _ = inetnum::asn::Asn16::from_str(data);
});
