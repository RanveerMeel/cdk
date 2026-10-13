//! In-kernel syscall fuzzer (roadmap 4.3): thousands of syscalls with hostile
//! arguments — kernel and unmapped pointers, read-only code pages, buffers
//! straddling page and region boundaries, huge lengths, unknown numbers and
//! handles. Every one must come back as an error (or a harmless success);
//! the kernel must not crash, write where it shouldn't, or leak.
//!
//!   cdk> spawn chaos
//!   cdk> grant <pid> obj-2 send,recv        (optional: exercise handle paths)
//!   cdk> elf-run <pid>

#![no_std]
#![no_main]

use cdk_user::{println, raw_syscall};

const ROUNDS: u32 = 20_000;
const USER_BASE: u64 = 1 << 39;
const USER_TOP: u64 = USER_BASE + (1 << 39);
const CODE: u64 = USER_BASE + 0x40_0000;

/// A page the kernel may legitimately write into (e.g. `recv`, `cap_list`).
static mut SCRATCH: [u8; 8192] = [0; 8192];
/// Must never change: nothing is supposed to write here.
static CANARY: [u8; 64] = [0xA5; 64];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[(self.next() % xs.len() as u64) as usize]
    }
}

fn hostile_ptr(r: &mut Rng, scratch: u64, canary: u64) -> u64 {
    match r.next() % 12 {
        0 => 0,
        1 => 0x1000 + (r.next() % 0x10_0000), // low kernel-shared memory
        2 => 0xFFFF_8000_0000_0000 + (r.next() & 0xFFFF_FFF0), // kernel half
        3 => CODE + (r.next() % 0x1000),      // read-only code
        4 => canary,                          // read-only data
        5 => USER_TOP - (r.next() % 64),      // straddles the top of the region
        6 => USER_BASE - 8,                   // just below the region
        7 => scratch + 8192 - (r.next() % 16), // runs off a mapped buffer
        8 => USER_BASE + 0x7FFF_F000 + (r.next() % 0x1000), // unmapped user page
        9 => r.next(),                        // anything
        _ => scratch + (r.next() % 4096),     // valid
    }
}

fn hostile_len(r: &mut Rng) -> u64 {
    let any = r.next();
    r.pick(&[
        0,
        1,
        8,
        63,
        64,
        65,
        4095,
        4096,
        4097,
        1 << 20,
        u64::MAX,
        u64::MAX / 2,
        any,
    ])
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let scratch = core::ptr::addr_of_mut!(SCRATCH) as u64;
    let canary = CANARY.as_ptr() as u64;
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    // Per syscall number: [successes, errors by code 0..=15].
    let mut stats = [[0u32; 17]; 13];
    for _ in 0..ROUNDS {
        // Never SYS_EXIT (1); SYS_WRITE (2) only with invalid buffers, so the
        // console isn't flooded.
        let nr = r.pick(&[0u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 99, u64::MAX]);
        let mut a = [0u64; 5];
        for x in a.iter_mut() {
            *x = match r.next() % 3 {
                0 => hostile_ptr(&mut r, scratch, canary),
                1 => hostile_len(&mut r),
                _ => r.next() % 20, // small: handles, masks
            };
        }
        if nr == 2 {
            a[0] = r.pick(&[
                0,
                USER_TOP,
                0xFFFF_8000_0000_0000,
                USER_TOP - 4,
                USER_BASE + 0x7FFF_F000,
            ]);
            a[1] = 64;
        }
        if (3..=9).contains(&nr) && nr != 8 && r.next() % 4 != 0 {
            // Mostly a real handle (h0 is granted; derives add more), so the
            // pointer and length checks behind the handle lookup are reached.
            a[0] = r.pick(&[0, 0, 0, 1, 2, 15, 16, u64::MAX]);
        }
        if nr == 3 {
            a[1] %= 32; // cap_list max entries
        }
        if nr == 4 && a[0] == 0 {
            a[0] = 1; // keep h0, so the handle paths stay reachable
        }
        if nr == 9 {
            a[4] = a[4].min(1 << 20); // result buffer length
        }
        let ret = unsafe { raw_syscall(nr, a[0], a[1], a[2], a[3], a[4]) };
        let row = &mut stats[(nr as usize).min(12)];
        if ret > u64::MAX - 16 {
            row[1 + (ret.wrapping_neg() as usize).min(15)] += 1;
        } else {
            row[0] += 1;
        }
    }
    let intact = CANARY.iter().all(|&b| b == 0xA5);
    println!("chaos: {} syscalls (per nr: ok, then -errno:count)", ROUNDS);
    for (nr, row) in stats.iter().enumerate() {
        if row.iter().all(|&n| n == 0) {
            continue;
        }
        cdk_user::print!(
            "  nr {:>2}{}: ok {}",
            nr,
            if nr == 12 { "+" } else { "" },
            row[0]
        );
        for (code, n) in row[1..].iter().enumerate() {
            if *n > 0 {
                cdk_user::print!(", -{}:{}", code, n);
            }
        }
        println!();
    }
    println!(
        "chaos: read-only canary {}",
        if intact { "intact" } else { "MODIFIED" }
    );
    if intact {
        0
    } else {
        1
    }
}
