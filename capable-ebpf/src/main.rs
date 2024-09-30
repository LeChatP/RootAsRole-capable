#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

mod capable;
pub mod ebpf_util;

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
};
use crate::capable::try_capable;


#[kprobe]
pub fn capable(ctx: ProbeContext) -> u32 {
    try_capable(&ctx).unwrap_or_else(|ret| ret as u32)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
