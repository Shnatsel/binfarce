#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kuduk::Format::Elf32 { byte_order } = kuduk::detect_format(data) {
        if let Ok(parsed) = kuduk::elf32::parse(data, byte_order) {
            if let Some(section)  = parsed.section_with_name("a") {
                section.range();
            }
            for section in parsed.sections() {
                section.range();
            }
        }
    }
});
