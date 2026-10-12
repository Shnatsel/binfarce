#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let binfarce::Format::PE = binfarce::detect_format(data) {
        if let Ok(parsed) = binfarce::pe::parse(data) {
            let _ = parsed.symbols();
            if let Some(Some(section)) = parsed.section_with_name("a").ok() {
                let _ = section.range();
            }
        }
    }
});
