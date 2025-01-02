#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_get_current_uid_gid, bpf_probe_read_kernel}, macros::{kprobe, map}, maps::stack_trace::StackTrace, programs::ProbeContext
};
use aya_ebpf::maps::Stack;
use vmlinux::{ns_common, pid_namespace, task_struct};
use capable_common::Request;

#[kprobe]
pub fn capable(ctx: ProbeContext) -> u32 {
    try_capable(&ctx).unwrap_or_else(|ret| ret as u32)
}


pub type TaskStructPtr = *mut task_struct;
pub const MAX_PID: u32 = 2 * 1024 * 1024;
pub const EPERM : i32 = 1;


#[map]
static mut ENTRY_STACK: Stack<Request> = Stack::with_max_entries(MAX_PID, 0);

#[map]
static mut STACKTRACE_MAP: StackTrace = StackTrace::with_max_entries(MAX_PID, 0);

pub fn try_capable(ctx: &ProbeContext) -> Result<u32, i64> {
    unsafe {
        let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let task = bpf_probe_read_kernel(&task)?;
        let ppid: i32 = get_ppid(task)?;
        let pid: i32 = bpf_probe_read_kernel(&(*task).pid)? as i32;
        let capability: u8 = ctx.arg::<u8>(2).unwrap();
        let uid_gid: u64 = bpf_get_current_uid_gid();
        let nsid: u32 = get_ns_inode(task)?;
        let pnsid_nsid: u64 = Into::<u64>::into(get_parent_ns_inode(task)?) << 32
            | Into::<u64>::into(nsid);
        let stackid = STACKTRACE_MAP.get_stackid(ctx, 0)?;
        let request = Request {
            pid,
            uid_gid,
            ppid,
            pnsid_nsid,
            capability,
            stackid,
        };
        ENTRY_STACK.push(&request, 0).expect("Failed to insert request");

    }
    Ok(0)
}

unsafe fn get_ppid(task: TaskStructPtr) -> Result<i32, i64> {
    let parent_task: TaskStructPtr = get_parent_task(task)?;
    bpf_probe_read_kernel(&(*parent_task).pid)
}

unsafe fn get_parent_task(task: TaskStructPtr) -> Result<TaskStructPtr, i64> {
    bpf_probe_read_kernel(&(*task).parent)
}

unsafe fn get_parent_ns_inode(task: TaskStructPtr) -> Result<u32, i64> {
    let parent_task: TaskStructPtr = get_parent_task(task)?;
    get_ns_inode(parent_task)
}


pub unsafe fn get_ns_inode(task: TaskStructPtr) -> Result<u32, i64> {
    let nsp = bpf_probe_read_kernel(&(*task).nsproxy).map_err(|e| e as u32)?;
    let pns: *mut pid_namespace =
        bpf_probe_read_kernel(&(*nsp).pid_ns_for_children).map_err(|e| e as u32)?;
    let nsc: ns_common = bpf_probe_read_kernel(&(*pns).ns).map_err(|e| e as u32)?;
    bpf_probe_read_kernel(&nsc.inum)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}