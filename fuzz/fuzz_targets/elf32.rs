#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let binfarce::Format::Elf32 { byte_order } = binfarce::detect_format(data) {
        if let Ok(parsed) = binfarce::elf32::parse(data, byte_order) {
            if let Some(Some(section)) = parsed.section_with_name("a").ok() {
                section.range();
            }
        }
    }
});
