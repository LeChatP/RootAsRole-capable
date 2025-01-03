use std::{
    fmt::Display, fs, os::linux::fs::MetadataExt, path::Path
};

use bitflags::bitflags;
use log::warn;
use serde::Serialize;
use tracing::debug;

use crate::{dac_read_search_effective, strace::Syscall};

bitflags! {
    #[derive(PartialEq, Clone)]
    pub struct Pos: u8 {
        const One       = 0b1;
        const Two       = 0b10;
        const Three     = 0b100;
        const Four      = 0b1000;
        const Five      = 0b10000;
    }
}

impl Into<usize> for Pos {
    fn into(self) -> usize {
        match self {
            Pos::One => 0,
            Pos::Two => 1,
            Pos::Three => 2,
            Pos::Four => 3,
            Pos::Five => 4,
            _ => panic!("Invalid conversion"),
        }
    }
}

impl Display for Pos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut pos = Vec::new();
        if self.contains(Pos::One) {
            pos.push("1");
        }
        if self.contains(Pos::Two) {
            pos.push("2");
        }
        if self.contains(Pos::Three) {
            pos.push("3");
        }
        if self.contains(Pos::Four) {
            pos.push("4");
        }
        if self.contains(Pos::Five) {
            pos.push("5");
        }
        write!(f, "{}", pos.join(","))
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct Access: u8 {
        const R   = 0b100;
        const W   = 0b010;
        const X   = 0b001;
        const RW  = 0b110;
        const RX  = 0b101;
        const WX  = 0b011;
        const RWX = 0b111;
    }
}

impl PartialEq for Access {
    fn eq(&self, other: &Self) -> bool {
        self.bits() == other.bits()
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut access = String::new();
        if self.contains(Access::R) {
            access.push('R');
        }
        if self.contains(Access::W) {
            access.push('W');
        }
        if self.contains(Access::X) {
            access.push('X');
        }
        write!(f, "{}", access)
    }
}

impl Serialize for Access {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

pub struct SyscallAccessEntry {
    pub path: String,
    pub access: Access,
    pub syscall: String,
}

pub const CALLS: [(&str, Pos, Access); 130] = [
    ("access", Pos::One, Access::empty()), // Special case
    ("acct", Pos::One, Access::empty()),
    ("bsd43_fstat", Pos::empty(), Access::empty()),
    ("bsd43_fstatfs", Pos::empty(), Access::empty()),
    ("bsd43_lstat", Pos::empty(), Access::empty()),
    ("bsd43_oldfstat", Pos::empty(), Access::empty()),
    ("bsd43_oldstat", Pos::empty(), Access::empty()),
    ("bsd43_stat", Pos::empty(), Access::empty()),
    ("bsd43_statfs", Pos::empty(), Access::empty()),
    ("chdir", Pos::One, Access::empty()),
    ("chmod", Pos::One, Access::empty()),   // CAP_FOWNER
    ("chown", Pos::One, Access::empty()),   // CAP_CHOWN
    ("chown32", Pos::One, Access::empty()), // CAP_CHOWN
    ("chroot", Pos::One, Access::empty()),  // CAP_SYS_CHROOT
    ("creat", Pos::One, Access::W),
    ("execv", Pos::One, Access::RX),
    ("execve", Pos::One, Access::RX),
    ("execveat", Pos::One, Access::RX),
    ("faccessat", Pos::One, Access::empty()),
    ("faccessat2", Pos::One, Access::empty()),
    ("fanotify_mark", Pos::Five, Access::empty()), // CAP_SYS_ADMIN ??
    ("fchmodat", Pos::Two, Access::empty()),       // CAP_FOWNER
    ("fchmodat2", Pos::One, Access::empty()),      // CAP_FOWNER
    ("fchownat", Pos::One, Access::empty()),       // CAP_CHOWN
    ("fsconfig", Pos::Five, Access::empty()),      // ?? CAP_SYS_ADMIN ??
    ("fspick", Pos::Two, Access::empty()),         // ?? CAP_SYS_ADMIN ??
    ("fstat", Pos::empty(), Access::empty()), // None, as it is already a opened file descriptor
    ("fstat64", Pos::empty(), Access::empty()), // None "
    ("fstatat64", Pos::empty(), Access::empty()), // None "
    ("fstatfs", Pos::empty(), Access::empty()), // None "
    ("fstatfs64", Pos::empty(), Access::empty()), // None "
    ("futimesat", Pos::One, Access::W),       // CAP_FOWNER
    ("getcwd", Pos::One, Access::empty()),    // None
    ("getxattr", Pos::One, Access::R),
    ("inotify_add_watch", Pos::One, Access::empty()), // CAP_FOWNER ??
    ("lchown", Pos::One, Access::empty()),            // CAP_CHOWN
    ("lchown32", Pos::One, Access::empty()),          // CAP_CHOWN
    ("lgetxattr", Pos::One, Access::R),
    ("link", Pos::Two, Access::W),
    ("linkat", Pos::Four, Access::W),
    ("listxattr", Pos::One, Access::R),
    ("llistxattr", Pos::One, Access::R),
    ("lremovexattr", Pos::One, Access::W),
    ("lsetxattr", Pos::One, Access::W),
    ("lstat", Pos::One, Access::empty()), // I guess
    ("lstat64", Pos::One, Access::empty()),
    ("mkdir", Pos::One, Access::W),
    ("mkdirat", Pos::Two, Access::W),
    ("mknod", Pos::One, Access::W),
    ("mknodat", Pos::Two, Access::W),
    ("mount", Pos::empty(), Access::empty()), // CAP_SYS_ADMIN
    ("mount_setattr", Pos::empty(), Access::empty()), // CAP_SYS_ADMIN
    ("move_mount", Pos::empty(), Access::empty()), // CAP_SYS_ADMIN
    ("name_to_handle_at", Pos::Two, Access::R),
    ("newfstatat", Pos::Two, Access::R),
    ("oldfstat", Pos::empty(), Access::empty()),
    ("oldlstat", Pos::empty(), Access::empty()),
    ("oldstat", Pos::empty(), Access::empty()),
    ("oldumount", Pos::empty(), Access::empty()),
    ("open", Pos::One, Access::empty()),
    ("openat", Pos::Two, Access::empty()),
    ("openat2", Pos::Two, Access::empty()),
    ("open_tree", Pos::Two, Access::empty()),
    ("osf_fstat", Pos::empty(), Access::empty()),
    ("osf_fstatfs", Pos::empty(), Access::empty()),
    ("osf_fstatfs64", Pos::empty(), Access::empty()),
    ("osf_lstat", Pos::empty(), Access::empty()),
    ("osf_old_fstat", Pos::empty(), Access::empty()),
    ("osf_old_lstat", Pos::empty(), Access::empty()),
    ("osf_old_stat", Pos::empty(), Access::empty()),
    ("osf_stat", Pos::empty(), Access::empty()),
    ("osf_statfs", Pos::empty(), Access::empty()),
    ("osf_statfs64", Pos::empty(), Access::empty()),
    ("osf_utimes", Pos::One, Access::W),       // CAP_FOWNER
    ("pivot_root", Pos::One, Access::empty()), // CAP_SYS_CHROOT
    ("posix_fstat", Pos::empty(), Access::empty()),
    ("posix_fstatfs", Pos::empty(), Access::empty()),
    ("posix_lstat", Pos::empty(), Access::empty()),
    ("posix_stat", Pos::empty(), Access::empty()),
    ("posix_statfs", Pos::empty(), Access::empty()),
    ("quotactl", Pos::empty(), Access::empty()),
    ("readlink", Pos::One, Access::R),
    ("readlinkat", Pos::Two, Access::R),
    ("removexattr", Pos::One, Access::empty()), // CAP_FOWNER ? CAP_SYS_ADMIN ? CAP_LINUX_IMMUTABLE ?
    ("rename", Pos::One, Access::W),
    ("renameat", Pos::Two, Access::W),
    ("renameat2", Pos::Two, Access::W),
    ("rmdir", Pos::One, Access::W),
    ("setxattr", Pos::One, Access::empty()), // CAP_FOWNER ? CAP_SYS_ADMIN ? CAP_LINUX_IMMUTABLE ?
    ("stat", Pos::empty(), Access::empty()),
    ("stat64", Pos::empty(), Access::empty()),
    ("statfs", Pos::empty(), Access::empty()),
    ("statfs64", Pos::empty(), Access::empty()),
    ("statx", Pos::Two, Access::empty()),
    ("svr4_fstat", Pos::empty(), Access::empty()),
    ("svr4_fstatfs", Pos::empty(), Access::empty()),
    ("svr4_fstatvfs", Pos::empty(), Access::empty()),
    ("svr4_fxstat", Pos::empty(), Access::empty()),
    ("svr4_lstat", Pos::empty(), Access::empty()),
    ("svr4_lxstat", Pos::empty(), Access::empty()),
    ("svr4_stat", Pos::empty(), Access::empty()),
    ("svr4_statfs", Pos::empty(), Access::empty()),
    ("svr4_statvfs", Pos::empty(), Access::empty()),
    ("svr4_xstat", Pos::empty(), Access::empty()),
    ("swapoff", Pos::One, Access::empty()), //CAP_SYS_ADMIN
    ("swapon", Pos::One, Access::empty()),  //CAP_SYS_ADMIN
    ("symlink", Pos::One, Access::W),
    ("symlinkat", Pos::Two, Access::W),
    ("sysv_fstat", Pos::empty(), Access::empty()),
    ("sysv_fstatfs", Pos::empty(), Access::empty()),
    ("sysv_fstatvfs", Pos::empty(), Access::empty()),
    ("sysv_fxstat", Pos::empty(), Access::empty()),
    ("sysv_lstat", Pos::empty(), Access::empty()),
    ("sysv_lxstat", Pos::empty(), Access::empty()),
    ("sysv_quotactl", Pos::empty(), Access::empty()),
    ("sysv_stat", Pos::empty(), Access::empty()),
    ("sysv_statfs", Pos::empty(), Access::empty()),
    ("sysv_statvfs", Pos::empty(), Access::empty()),
    ("sysv_xstat", Pos::empty(), Access::empty()),
    ("truncate", Pos::One, Access::W),
    ("truncate64", Pos::One, Access::W),
    ("umount", Pos::empty(), Access::empty()),
    ("umount2", Pos::empty(), Access::empty()),
    ("unlink", Pos::One, Access::W),
    ("unlinkat", Pos::Two, Access::W),
    ("uselib", Pos::empty(), Access::empty()), // No idea
    ("utime", Pos::One, Access::W),
    ("utimensat", Pos::Two, Access::W),
    ("utimensat_time64", Pos::Two, Access::W),
    ("utimes", Pos::One, Access::W),
];

/**
 * Check entire path for access rights
 */
fn check_directories_access<P:AsRef<Path> + Clone>(initial_path: P, syscall: &Syscall, create_or_delete: bool) -> Vec<SyscallAccessEntry> {
    // for each directory in the path
    let mut result = Vec::new();
    let mut parent = initial_path.as_ref();
    while parent.parent().is_some() {
        parent = parent.parent().expect("No parent found (impossible)");
        let metadata = match fs::symlink_metadata(&parent) {
            Ok(metadata) => metadata,
            Err(_) => {
                warn!("Cannot retrieve metadata for path: {}", parent.display());
                continue;
            }
        };
        let mode = Access::from_bits_truncate((metadata.st_mode() & 0o7).try_into().expect("Invalid Access mode"));
        let access = Access::X | if create_or_delete && initial_path.as_ref().parent() == Some(parent) {
            Access::W
        } else {
            Access::empty()
        };
        if mode.intersection(access).eq(&access) {
            debug!("{} has {} rights for others, so ignoring", parent.display(), mode);
            continue;
        }
        result.push(SyscallAccessEntry {
            access,
            syscall: syscall.syscall.clone(),
            path: parent.canonicalize().unwrap_or(parent.to_path_buf()).display().to_string(),
        });
    }
    result
}

pub fn syscall_to_entry(syscall: &Syscall) -> Option<Vec<SyscallAccessEntry>> {
    for (name, pos, access) in CALLS.iter() {
        if pos.is_empty() {
            continue;
        }
        if *name == syscall.syscall {
            let mut result = Vec::new();
            let path = syscall
            .args
            .clone()
            .into_iter()
            .nth((*pos).clone().into())
            .expect(&format!("No argument found for syscall {} at position {}", syscall.syscall, pos))
            .to_string();
            let mut create_or_delete = false;
            let mut access = access.clone();
            match *name {
                "open" | "openat" | "openat2" => {
                    let flags = if syscall.args.len() > 2 {
                        syscall.args[2].to_string()
                    } else {
                        syscall.args[1].to_string()
                    };
                    if flags.contains("O_RDONLY") {
                        access |= Access::R;
                        debug!("Found O_RDONLY");
                    }
                    if flags.contains("O_CREAT") {
                        access |= Access::W;
                        create_or_delete = true;
                        debug!("Found O_CREAT");
                    }
                    if flags.contains("O_WRONLY") {
                        access |= Access::W;
                        debug!("Found O_WRONLY");
                    }
                    if flags.contains("O_RDWR") {
                        access |= Access::RW;
                        debug!("Found O_RDWR");
                    }
                },
                "mkdir" | "mkdirat" | "mknod" | "mknodat" | "symlink" | "symlinkat" | "unlink" | "unlinkat" => {
                    create_or_delete = true;
                },
                _ => {}
            }
            result.extend(check_directories_access(&path, syscall, create_or_delete));
            if access.is_empty() {
                continue;
            }
            debug!("{} is requesting {} at {}", name, access, &path);
            if syscall
                .return_code
                .constant
                .as_ref()
                .and_then(|r| if r == "ENOENT" { Some(r) } else { None })
                .is_some()
            {
                debug!("Ignoring {} with ENOENT", path);
                return None;
            }
            // retrieve POSIX access rights
            let _ = dac_read_search_effective(true);
            match fs::symlink_metadata(&path) {
                // TODO: Add folder permission checks
                Ok(metadata) => {
                    let mode =
                        Access::from_bits_truncate((metadata.st_mode() & 0o7).try_into().expect("Invalid Access mode from file metadata"));
                    // if mode is a superset then None
                    if access.intersection(mode).eq(&access) {
                        debug!("{} has {} rights for others, so ignoring", path, mode);
                        return None;
                    }
                }
                Err(_) => {
                    warn!("Cannot retrieve metadata for path: {}", path);
                    return None;
                }
            }
            let _ = dac_read_search_effective(false);
            let abs_path = Path::new(&path).canonicalize().unwrap_or(Path::new(&path).to_path_buf());
            result.push(SyscallAccessEntry {
                path: abs_path.display().to_string(),
                access,
                syscall: syscall.syscall.clone(),
            });
            if result.is_empty() {
                return None;
            } else {
                return Some(result);
            }
        }
    }
    None
}
