//! Program images: parse, read every header, validate. Anything validate
//! accepts must stay inside the user region, clear of the stack.
#![no_main]
use cdk::elf;
use cdk::paging::{is_user_range, USER_BASE, USER_TOP};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(img) = elf::parse(data) else { return };
    for i in 0..img.phnum as usize {
        let _ = elf::program_header(&img, i);
    }
    if elf::validate(&img).is_ok() {
        assert!(is_user_range(img.entry, 1));
        for i in 0..img.phnum as usize {
            let ph = elf::program_header(&img, i).unwrap();
            if ph.p_type != elf::PT_LOAD {
                continue;
            }
            let end = ph.p_vaddr.checked_add(ph.p_memsz).unwrap();
            assert!(ph.p_vaddr >= USER_BASE && end <= USER_TOP);
            assert!(ph.p_offset + ph.p_filesz <= data.len() as u64);
            assert!(
                end <= elf::USER_STACK_TOP - (elf::USER_STACK_PAGES + 1) * 4096
                    || ph.p_vaddr >= elf::USER_STACK_TOP
            );
        }
    }
});
