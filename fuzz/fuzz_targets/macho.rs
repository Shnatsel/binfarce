#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let binfarce::Format::Macho = binfarce::detect_format(data) {
        if let Ok(parsed) = binfarce::macho::parse(data) {
            if let Some(Some(section)) = parsed.section_with_name("a", "a").ok() {
                section.range();
            }
        }
    }
});
