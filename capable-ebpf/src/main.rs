#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_get_current_uid_gid, bpf_probe_read_kernel}, macros::{kprobe, map}, maps::HashMap, programs::ProbeContext
};
use vmlinux::{ns_common, nsproxy, pid_namespace, task_struct};

#[kprobe]
pub fn capable(ctx: ProbeContext) -> u32 {
    try_capable(&ctx).unwrap_or_else(|ret| ret as u32)
}

type Key = i32;
pub type TaskStructPtr = *mut task_struct;
pub const MAX_PID: u32 = 4 * 1024 * 1024;
pub const EPERM : i32 = 1;

#[map]
static mut CAPABILITIES_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID, 0);
#[map]
static mut UID_GID_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID, 0);
#[map]
static mut PPID_MAP: HashMap<Key, i32> = HashMap::with_max_entries(MAX_PID, 0);
#[map]
static mut PNSID_NSID_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID, 0);

pub fn try_capable(ctx: &ProbeContext) -> Result<u32, i64> {
    unsafe {
        let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let task = bpf_probe_read_kernel(&task)?;
        let ppid: i32 = get_ppid(task)?;
        let pid: i32 = bpf_probe_read_kernel(&(*task).pid)? as i32;
        let cap: u64 = (1 << ctx.arg::<u8>(2).unwrap()) as u64;
        let uid: u64 = bpf_get_current_uid_gid();
        let zero = 0;
        let capval: u64 = *CAPABILITIES_MAP.get(&pid).unwrap_or(&zero);
        let pinum_inum: u64 = Into::<u64>::into(get_parent_ns_inode(task)?) << 32
            | Into::<u64>::into(get_ns_inode(task)?);
        UID_GID_MAP
            .insert(&pid, &uid, 0)
            .expect("failed to insert uid");
        PNSID_NSID_MAP
            .insert(&pid, &pinum_inum, 0)
            .expect("failed to insert pnsid");
        PPID_MAP
            .insert(&pid, &ppid, 0)
            .expect("failed to insert ppid");
        CAPABILITIES_MAP
            .insert(&pid, &(capval | cap), 0)
            .expect("failed to insert cap");
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
    let nsp: *mut nsproxy = bpf_probe_read_kernel(&(*task).nsproxy).map_err(|e| e as u32)?;
    let pns: *mut pid_namespace =
        bpf_probe_read_kernel(&(*nsp).pid_ns_for_children).map_err(|e| e as u32)?;
    let nsc: ns_common = bpf_probe_read_kernel(&(*pns).ns).map_err(|e| e as u32)?;
    bpf_probe_read_kernel(&nsc.inum)
}



#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}