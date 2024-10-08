#![no_std]

#[cfg(feature = "aya")]
use aya::Pod;

pub type Pid = i32;
pub type Nsid = u32;
pub type StackId = i64;
pub type UidGid = u64;
pub type Uid = u32;
pub type Gid = u32;
pub type PnsidNsid = u64;
pub type Capabilities = u64;



#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub pid: Pid,
    pub ppid : Pid,
    pub uid_gid : UidGid,
    pub pnsid_nsid : PnsidNsid,
    pub capability : u8,
    pub stackid : StackId,
}

#[cfg(feature = "aya")]
unsafe impl Pod for Request {}