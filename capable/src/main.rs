use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error;
use std::ffi::CString;
use std::fs::{canonicalize, metadata, File};
use std::hash::Hash;
use std::io::Write;
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use aya::maps::{MapData, Stack, StackTraceMap};
use aya::programs::KProbe;
use aya::util::{kernel_symbols, KernelVersion};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use bus::{run_dbus_monitor, Memory};
use capable_common::{Nsid, Pid, Request};
use capctl::{ambient, Cap, CapSet, CapState, ParseCapError};
use log::{debug, warn};
use nix::sys::signal::kill;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, getpid, ForkResult, Uid};
use serde::{Deserialize, Serialize};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, thread, vec};
use strace::read_strace;
use syscalls::SyscallAccessEntry;
use tabled::settings::object::Columns;
use unshare::ExitStatus;

use tabled::settings::{Modify, Style, Width};
use tabled::{Table, Tabled};
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;

mod strace;
mod syscalls;
mod version;
mod bus;

struct Cli {
    /// Specify a delay before killing the process
    sleep: Option<u64>,
    /// collecting data on system and print result at the end
    daemon: bool,

    /// Pass all capabilities when executing the command,
    capabilities: CapSet,

    /// Specify a file to write policy result, reactivate stdin/out/err
    output: Option<PathBuf>,

    /// Specify a command to execute with arguments
    command: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            sleep: None,
            daemon: false,
            output: None,
            capabilities: CapSet::empty(),
            command: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CapSetEntry {
    pub pid: Pid,
    pub ppid: Pid,
    pub uid: capable_common::Uid,
    pub gid: capable_common::Gid,
    pub ns: Nsid,
    pub parent_ns: Nsid,
    pub capabilities: CapSet,
}

impl CapSetEntry {
    pub fn new(
        pid: Pid,
        ppid: Pid,
        uid: capable_common::Uid,
        gid: capable_common::Gid,
        parent_ns: Nsid,
        ns: Nsid,
    ) -> CapSetEntry {
        CapSetEntry {
            pid,
            ppid,
            uid,
            gid,
            parent_ns,
            ns,
            capabilities: CapSet::empty(),
        }
    }
    pub fn add(&mut self, cap: Cap) {
        self.capabilities.add(cap);
    }
}

impl Hash for CapSetEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.ppid.hash(state);
        self.uid.hash(state);
        self.gid.hash(state);
        self.parent_ns.hash(state);
        self.ns.hash(state);
    }
}

impl PartialEq for CapSetEntry {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.ppid == other.ppid
            && self.uid == other.uid
            && self.parent_ns == other.parent_ns
            && self.ns == other.ns
    }
}

impl Eq for CapSetEntry {}

#[derive(Tabled, Serialize, Deserialize)]
#[tabled(rename_all = "UPPERCASE")]
struct CapabilitiesTable {
    pid: Pid,
    ppid: i32,
    uid: String,
    gid: String,
    ns: u32,
    parent_ns: u32,
    name: String,
    capabilities: String,
}

const MAX_CHECK: u64 = 10;

pub fn capset_to_vec(set: &CapSet) -> Vec<String> {
    set.iter().map(|c| format!("CAP_{:?}", c)).collect()
}

pub fn capset_to_string(set: &CapSet) -> String {
    if set == &!CapSet::empty() {
        return String::from("ALL");
    }
    set.iter()
        .fold(String::new(), |mut acc, cap| {
            acc.push_str(&format!("CAP_{:?} ", cap));
            acc
        })
        .trim_end()
        .to_string()
}

fn get_cap(val: u8) -> Option<Cap> {
    match val {
        0 => Some(Cap::CHOWN),
        1 => Some(Cap::DAC_OVERRIDE),
        2 => Some(Cap::DAC_READ_SEARCH),
        3 => Some(Cap::FOWNER),
        4 => Some(Cap::FSETID),
        5 => Some(Cap::KILL),
        6 => Some(Cap::SETGID),
        7 => Some(Cap::SETUID),
        8 => Some(Cap::SETPCAP),
        9 => Some(Cap::LINUX_IMMUTABLE),
        10 => Some(Cap::NET_BIND_SERVICE),
        11 => Some(Cap::NET_BROADCAST),
        12 => Some(Cap::NET_ADMIN),
        13 => Some(Cap::NET_RAW),
        14 => Some(Cap::IPC_LOCK),
        15 => Some(Cap::IPC_OWNER),
        16 => Some(Cap::SYS_MODULE),
        17 => Some(Cap::SYS_RAWIO),
        18 => Some(Cap::SYS_CHROOT),
        19 => Some(Cap::SYS_PTRACE),
        20 => Some(Cap::SYS_PACCT),
        21 => Some(Cap::SYS_ADMIN),
        22 => Some(Cap::SYS_BOOT),
        23 => Some(Cap::SYS_NICE),
        24 => Some(Cap::SYS_RESOURCE),
        25 => Some(Cap::SYS_TIME),
        26 => Some(Cap::SYS_TTY_CONFIG),
        27 => Some(Cap::MKNOD),
        28 => Some(Cap::LEASE),
        29 => Some(Cap::AUDIT_WRITE),
        30 => Some(Cap::AUDIT_CONTROL),
        31 => Some(Cap::SETFCAP),
        32 => Some(Cap::MAC_OVERRIDE),
        33 => Some(Cap::MAC_ADMIN),
        34 => Some(Cap::SYSLOG),
        35 => Some(Cap::WAKE_ALARM),
        36 => Some(Cap::BLOCK_SUSPEND),
        37 => Some(Cap::AUDIT_READ),
        38 => Some(Cap::PERFMON),
        39 => Some(Cap::BPF),
        40 => Some(Cap::CHECKPOINT_RESTORE),
        _ => None,
    }
}

fn union_all_childs(
    nsinode: u32,
    graph: &std::collections::HashMap<u32, Vec<u32>>,
    cap_graph: &std::collections::HashMap<u32, CapSet>,
) -> CapSet {
    let mut result = CapSet::empty();
    for ns in graph.get(&nsinode).unwrap_or(&Vec::new()) {
        result |= *cap_graph.get(ns).unwrap_or(&CapSet::empty());
        if graph.contains_key(&ns) && *ns != nsinode {
            result |= union_all_childs(*ns, graph, cap_graph);
        }
    }
    result
}

fn program_capabilities<T, V>(
    nsinode: &u32,
    request_map: &mut Stack<V, Request>,
    stacktrace_map: &StackTraceMap<T>,
    ksyms: &std::collections::BTreeMap<u64, String>,
) -> Result<CapSet, Box<dyn Error>>
where
    T: Borrow<MapData>,
    V: BorrowMut<MapData>,
{
    let mut graph = std::collections::HashMap::new();
    let mut init = CapSet::empty();
    setbpf_effective(true)?;

    let mut nsid_caps = std::collections::HashMap::new();
    let set_entry = aggregate_cap_set_entries(request_map, stacktrace_map, ksyms)?;
    for CapSetEntry {
        capabilities,
        parent_ns,
        ns,
        ..
    } in set_entry
    {
        let capset = nsid_caps.entry(ns).or_insert_with(CapSet::empty);
        *capset |= capabilities;
        graph.entry(parent_ns).or_insert_with(Vec::new).push(ns);
    }
    setbpf_effective(false)?;
    init |= union_all_childs(*nsinode, &graph, &nsid_caps);
    Ok(init)
}

fn find_from_envpath<P>(exe_name: &P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

fn get_exec_and_args(command: &mut Vec<String>) -> (PathBuf, Vec<String>) {
    let mut exec_path: PathBuf = command[0].parse().expect("Failed to get exec path to PathBuf");
    let mut exec_args;
    // encapsulate the command in sh command
    command[0] = canonicalize(exec_path.clone())
        .unwrap_or(exec_path)
        .to_str()
        .expect("Failed to get exec path to string (canonicalize)")
        .to_string();
    if let Ok(strace) = which::which("strace") {
        exec_path = strace;
        exec_args = vec![
            "-D".to_string(),
            "-f".to_string(),
            "-e".to_string(),
            "ptrace,file".to_string(),
            "-o".to_string(),
            format!("/tmp/capable_strace_{}.log", getpid()),
        ];
        exec_args.extend(command.clone());
    } else if let Ok(sh) = which::which("sh") {
        exec_path = sh;
        exec_args = vec!["-c".to_string(), shell_words::join(command)];
    } else {
        panic!("Failed to find sh or strace in $PATH");
    }
    (exec_path, exec_args)
}

fn extract_ns(pinum_inum: u64) -> (u32, u32) {
    let ns = (pinum_inum & 0xffffffff) as u32;
    let parent_ns = (pinum_inum >> 32) as u32;
    (ns, parent_ns)
}

fn read_exe_link(pid: &Pid) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .unwrap_or_else(|_| std::path::PathBuf::from(""))
        .to_str()
        .unwrap_or("")
        .to_string()
}

fn get_username(uid: &u32) -> String {
    nix::unistd::User::from_uid(Uid::from_raw(*uid))
        .map_or(uid.to_string(), |u| u.map_or(uid.to_string(), |u| u.name))
}

fn get_groupname(gid: &u32) -> String {
    nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(*gid))
        .map_or(gid.to_string(), |g| g.map_or(gid.to_string(), |g| g.name))
}

fn process_data_map<T, V>(
    data_map: &mut Stack<T, Request>,
    capabilities_table: &mut Vec<CapabilitiesTable>,
    stacktrace_map: &StackTraceMap<V>,
    ksyms: &std::collections::BTreeMap<u64, String>,
) -> Result<(), anyhow::Error>
where
    T: BorrowMut<MapData>,
    V: Borrow<MapData>,
{
    let set_entry = aggregate_cap_set_entries(data_map, stacktrace_map, ksyms)?;
    for CapSetEntry {
        pid,
        ppid,
        uid,
        gid,
        ns,
        parent_ns,
        capabilities,
    } in set_entry
    {
        let name = read_exe_link(&pid);
        let username = get_username(&uid);
        let groupname = get_groupname(&gid);
        capabilities_table.push(CapabilitiesTable {
            pid,
            ppid,
            uid: username,
            gid: groupname,
            ns,
            parent_ns,
            name,
            capabilities: capset_to_string(&capabilities),
        });
    }
    Ok(())
}

fn aggregate_cap_set_entries<T, V>(
    data_map: &mut Stack<V, Request>,
    stacktrace_map: &StackTraceMap<T>,
    ksyms: &std::collections::BTreeMap<u64, String>,
) -> Result<HashSet<CapSetEntry>, anyhow::Error>
where
    T: Borrow<MapData>,
    V: BorrowMut<MapData>,
{
    let mut set_entry = HashSet::new();
    while let Ok(Request {
        pid,
        ppid,
        uid_gid,
        pnsid_nsid,
        capability,
        stackid,
    }) = data_map.pop(0)
    {
        assert!(stackid <= i32::MAX as i64); // Inconsistent StackTraceMap key type
        let (ns, parent_ns) = extract_ns(pnsid_nsid);
        let uid = uid_gid as u32 as capable_common::Uid;
        let gid = (uid_gid >> 32) as capable_common::Gid;
        let mut entry = CapSetEntry::new(pid, ppid, uid, gid, parent_ns, ns);
        let mut binding = set_entry.take(&entry);
        let entry = binding.as_mut().unwrap_or(&mut entry);
        let stack = stacktrace_map.get(&(stackid as u32), 0)?;
        if !((capability == Cap::SETUID as u8
            && skip_priv_sym(&stack, ksyms, "cap_bprm_creds_from_file"))
            || capability == Cap::DAC_OVERRIDE as u8
            || (capability == Cap::DAC_READ_SEARCH as u8
            && skip_priv_sym(&stack, ksyms, "may_open"))
            || capability == Cap::SYS_PTRACE as u8)
        {
            entry.add(get_cap(capability).expect(&format!("Unknown capability: {}", capability)));
            // debug the stack trace
            for frame in stack.frames() {
                if let Some(sym) = ksyms.range(..=frame.ip).next_back().map(|(_, s)| s) {
                    debug!("{}()", sym);
                }
            }
        }

        //debug!("new entry: {:?}", entry);

        set_entry.insert(entry.clone());
    }
    Ok(set_entry)
}

fn skip_priv_sym(
    stack: &aya::maps::stack_trace::StackTrace,
    ksyms: &std::collections::BTreeMap<u64, String>,
    symbol: &str,
) -> bool {
    for frame in stack.frames() {
        if let Some(sym) = ksyms.range(..=frame.ip).next_back().map(|(_, s)| s) {
            if sym == symbol {
                return true;
            }
        }
    }
    false
}

fn print_all<T, V>(
    data_map: &mut Stack<T, Request>,
    stacktrace_map: &StackTraceMap<V>,
    ksyms: &std::collections::BTreeMap<u64, String>,
    output: Option<PathBuf>,
) -> Result<(), anyhow::Error>
where
    T: BorrowMut<MapData>,
    V: Borrow<MapData>,
{
    let mut capabilities_table = Vec::new();
    process_data_map(data_map, &mut capabilities_table, stacktrace_map, ksyms)?;
    if let Some(output) = output {
        let mut file = File::create(output)?;
        writeln!(file, "{:?}", serde_json::to_string(&capabilities_table)?)?;
        file.flush()?;
    } else {
        println!(
            "\n{}",
            Table::new(&capabilities_table)
                .with(Style::modern())
                .with(Modify::new(Columns::single(3)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(2)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(6)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::last()).with(Width::wrap(52).keep_words()))
        );
    }

    Ok(())
}

fn remove_outer_quotes(input: &str) -> String {
    if input.len() >= 2 && input.starts_with('"') && input.ends_with('"') {
        remove_outer_quotes(&input[1..input.len() - 1])
    } else if input.len() >= 2 && input.starts_with('\'') && input.ends_with('\'') {
        remove_outer_quotes(&input[1..input.len() - 1])
    } else {
        input.to_string()
    }
}

pub fn escape_parser_string<S>(s: S) -> String
where
    S: AsRef<str>,
{
    remove_outer_quotes(s.as_ref()).replace("\"", "\\\"")
}

pub fn parse_capset_iter<'a, I>(iter: I) -> Result<CapSet, ParseCapError>
where
    I: Iterator<Item = &'a str>,
{
    let mut res = CapSet::empty();

    for part in iter {
        match part.parse() {
            Ok(cap) => res.add(cap),
            Err(error) => {
                return Err(error);
            }
        }
    }
    Ok(res)
}

const CAPABILITIES_ERROR: &str =
    "You need at least setpcap, sys_admin, bpf, sys_resource, sys_ptrace capabilities to run capable";
fn cap_effective_error(caplist: &str) -> String {
    format!(
        "Unable to toggle {} privilege. {}",
        caplist, CAPABILITIES_ERROR
    )
}

pub fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

pub fn dac_read_search_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_READ_SEARCH, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("DAC_READ_SEARCH"));
    })
}

fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SETPCAP"));
    })
}

fn setbpf_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::BPF, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("BPF"));
    })
}

fn setadmin_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_ADMIN, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_ADMIN"));
    })
}

fn setresource_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_RESOURCE, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_RESOURCE"));
    })
}

pub fn setptrace_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_PTRACE, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_PTRACE"));
    })
}

fn getopt<S, I>(s: I) -> Result<Cli, anyhow::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = Cli::default();
    let mut iter = s.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "-s" | "--sleep" => {
                args.sleep = iter.next().and_then(|s| s.as_ref().parse::<u64>().ok());
            }
            "-d" | "--daemon" => {
                args.daemon = true;
            }
            "-c" | "--capabilities" => {
                args.capabilities = iter
                    .next()
                    .and_then(|s| {
                        if s.as_ref().to_ascii_uppercase() == "ALL" {
                            return Some(capctl::bounding::probe());
                        }
                        Some(
                            parse_capset_iter(s.as_ref().split(','))
                                .ok()
                                .unwrap_or(CapSet::empty()),
                        )
                    })
                    .unwrap_or(CapSet::empty());
            }
            "-o" | "--output" => {
                args.output = iter.next().map(|s| PathBuf::from(s.as_ref()));
            }
            "-l" | "--log-level" => {
                let level = iter.next().map(|s| s.as_ref().to_string()).unwrap_or("info".to_string());
                env::set_var("RUST_LOG", level);
            }
            _ => {
                if arg.as_ref().starts_with('-') {
                    return Err(anyhow::anyhow!("Unknown option: {}", arg.as_ref()));
                } else {
                    args.command.push(escape_parser_string(arg));
                    break;
                }
            }
        }
    }
    while let Some(arg) = iter.next() {
        args.command.push(escape_parser_string(arg));
    }
    Ok(args)
}

fn run_command(
    cli_args: &mut Cli,
    nsclone: Rc<RefCell<u32>>,
    pid: &mut i32,
) -> Result<ExitStatus, anyhow::Error> {
    let (path, args) = get_exec_and_args(&mut cli_args.command);
    let namespaces = vec![&unshare::Namespace::Pid];
    let capabilities = cli_args.capabilities.clone();
    let mut cmd = unshare::Command::new(path);

    unsafe {
        cmd.pre_exec(move || {
            let mut capstate = CapState::empty();
            nix::sys::prctl::set_keepcaps(false).expect("Failed to set keepcaps");
            setpcap_effective(true).expect("Failed to setpcap effective");
            ambient::clear().expect("Failed to clear ambiant caps");
            capstate.inheritable = capabilities;
            capstate.permitted = capabilities;
            capstate.effective = capabilities;
            capstate.set_current().expect("Failed to set current cap");
            Ok(())
        })
    };
    setadmin_effective(true)?;

    //avoid output
    let child: Arc<Mutex<unshare::Child>> = Arc::new(Mutex::new(
        cmd.args(&args)
            .before_unfreeze(move |id| {
                setptrace_effective(true)?;
                let fnspid =
                    metadata(format!("/proc/{}/ns/pid", id)).expect("failed to open pid ns");
                setptrace_effective(false)?;
                nsclone.as_ref().replace(fnspid.ino() as u32);
                Ok(())
            })
            .unshare(namespaces)
            .stdout(if cli_args.output.is_none() {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .stderr(if cli_args.output.is_none() {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .stdin(if cli_args.output.is_none() {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .spawn()
            .expect("failed to spawn child"),
    ));
    setadmin_effective(false)?;
    let cloned = child.clone();
    *pid = child.try_lock().expect("failed to lock execution child").id() as i32;
    let pid_cloned = pid.clone();
    let term = Arc::new(AtomicBool::new(false));
    for sig in TERM_SIGNALS {
        flag::register(*sig, Arc::clone(&term))?;
    }

    thread::spawn(move || {
        while !term.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(400));
        }
        let nixpid = nix::unistd::Pid::from_raw(pid_cloned);
        nix::sys::signal::kill(nixpid, nix::sys::signal::Signal::SIGINT)
            .expect("failed to send SIGINT");
        let mut i = 0;
        if nix::sys::wait::waitpid(nixpid, Some(WaitPidFlag::WNOHANG)).expect("Fail to wait pid")
            == WaitStatus::StillAlive
            && i < MAX_CHECK
        {
            i += 1;
            thread::sleep(Duration::from_millis(100));
        }
        if i >= MAX_CHECK {
            eprintln!("SIGINT wait is timed-out\n");
            child
                .try_lock()
                .expect("failed to lock execution child for sending SIGKILL")
                .kill()
                .expect("failed to send SIGKILL");
            i = 0;
            while nix::sys::wait::waitpid(nixpid, Some(WaitPidFlag::WNOHANG))
                .expect("Fail to wait pid")
                == WaitStatus::StillAlive
                && i < MAX_CHECK
            {
                thread::sleep(Duration::from_millis(100));
                i += 1;
            }
            if i >= MAX_CHECK {
                exit(-1);
            }
        }
        Ok::<(), ()>(())
    });

    let exit_status = cloned
        .try_lock()
        .expect("failed to lock execution child for waiting")
        .wait()
        .expect("failed to wait on child");
    debug!("child exited with {:?}", exit_status);
    //print_all(&capabilities_map, &pnsid_nsid_map, &uid_gid_map, &ppid_map)?;

    Ok(exit_status)
}

#[cfg(debug_assertions)]
pub fn subsribe(tool: &str) {
    use std::io;

    use tracing::level_filters::LevelFilter;
    let identity = CString::new(tool).expect("Failed to create CString");
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let _syslog = syslog_tracing::Syslog::new(identity, options, facility).expect("Failed to create syslog");
    tracing_subscriber::fmt()
        .with_max_level(env::var("RUST_LOG").unwrap_or("info".to_string()).parse::<LevelFilter>().expect("Failed to parse log level"))
        .with_file(true)
        .with_line_number(true)
        .with_writer(io::stdout)
        .finish()
        .init();
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) {
    use std::panic::set_hook;

    let identity = CString::new(tool).expect("Failed to create CString");
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).expect("Failed to create syslog");
    tracing_subscriber::fmt()
        .compact()
        .with_max_level(Level::WARN)
        .with_file(false)
        .with_timer(false)
        .with_line_number(false)
        .with_target(false)
        .without_time()
        .with_writer(syslog)
        .finish()
        .init();
    set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<String>() {
            println!("{}", s);
        }
    }));
}

#[derive(Serialize)]
struct ProgramResult {
    capabilities: Vec<String>,
    files: std::collections::HashMap<String, syscalls::Access>,
    dbus: Vec<String>,
    env_vars: std::collections::HashMap<String, String>,
}

const DBUS_JSON_PATH: &str = "/tmp/capable_dbus.json";

fn main() -> Result<(), anyhow::Error> {
    let mut cli_args = getopt(std::env::args()).context("Arguments error")?;
    subsribe("capable");
    //env_logger::init();
    //ambient::clear().expect("Failed to clear ambiant caps");
    debug!("capable started");

    if KernelVersion::current()?.code() != version::LINUX_VERSION_CODE {
        let major = version::LINUX_VERSION_CODE >> 16;
        let minor = (version::LINUX_VERSION_CODE >> 8) & 0xff;
        let patch = version::LINUX_VERSION_CODE & 0xff;
        let current = KernelVersion::current().context("Unable to get kernel version")?.code();
        let current_major = current >> 16;
        let current_minor = (current >> 8) & 0xff;
        let current_patch = current & 0xff;
        warn!("This program was compiled for kernel version {}.{}.{}, but the current kernel version is {}.{}.{}",
              major, minor, patch, current_major, current_minor, current_patch);
        warn!("This may cause the program to fail or behave unexpectedly");
    }

    debug!("setting capabilities");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    setresource_effective(true)?;
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    setresource_effective(false)?;
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    setbpf_effective(true)?;
    setadmin_effective(true)?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/capable"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF {}", e);
    }
    debug!("loading and attaching program {}", "capable");
    setbpf_effective(true)?;
    setadmin_effective(true)?;
    let program: &mut KProbe = bpf.program_mut("capable").expect("failed to get Kprobe capable program").try_into().context("Failed to get Kprobe")?;
    program.load()?;
    program.attach("cap_capable", 0)?;
    setbpf_effective(false)?;
    setadmin_effective(false)?;
    debug!("program {} loaded and attached", "capable");
    let mut requests_map: Stack<_, Request> =
        Stack::try_from(bpf.take_map("ENTRY_STACK").expect("Unable to obtain Stack requests"))?;
    let stack_traces = StackTraceMap::try_from(bpf.borrow().map("STACKTRACE_MAP").expect("unable to get Stacktrace map"))?;
    let ksyms: std::collections::BTreeMap<u64, String> = kernel_symbols()?;
    setbpf_effective(false)?;
    setadmin_effective(false)?;
    
    
    {
        if cli_args.daemon || cli_args.command.is_empty() {
            println!("Waiting for Ctrl-C...");
            let term = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;
            while !term.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(400));
            }
            print_all(&mut requests_map, &stack_traces, &ksyms, cli_args.output)?;
        } else {
            let nsinode: Rc<RefCell<u32>> = Rc::new(0.into());
            let mut pid = 0;
            //we need to fork

            let forked = unsafe { fork().expect("Failed to fork") };
            match forked {
                ForkResult::Child => {
                    let term_now = Arc::new(Memory::default());
                    for sig in TERM_SIGNALS {
                        // When terminated by a second term signal, exit with exit code 1.
                        // This will do nothing the first time (because term_now is false).
                        flag::register_conditional_shutdown(*sig, 1, Arc::clone(&term_now.cancel))?;
                        // But this will "arm" the above for the second time, by setting it to true.
                        // The order of registering these is important, if you put this one first, it will
                        // first arm and then terminate ‒ all in the first round.
                        flag::register(*sig, Arc::clone(&term_now.cancel))?;
                    }
                    nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).expect("Failed to setuid");
                    if let Ok(res) = run_dbus_monitor(term_now.clone()) {
                        //debug!("MEMORY : {:?}", term_now);
                        let mut file = File::create(DBUS_JSON_PATH)?;
                        write!(file,"{}",&serde_json::to_string(&res)?)?;
                        file.flush()?;
                        
                    }
                    exit(0);

                }
                // let's setuid(root)
                ForkResult::Parent { child } => {
                    let exit = run_command(&mut cli_args, nsinode.clone(), &mut pid)?;
                    kill(child, nix::sys::signal::Signal::SIGINT)
                        .expect("failed to send SIGINT to child");
                    waitpid(child, Some(WaitPidFlag::empty()))?;
                    if !exit.success() && cli_args.output.is_none() {
                        eprintln!("Command failed with exit status: {}", exit);
                        eprintln!("Please check the command and try again with requested capabilities as you want to reach");
                    }

                    let mut capset = program_capabilities(
                        &nsinode.as_ref().borrow(),
                        &mut requests_map,
                        &stack_traces,
                        &ksyms,
                    )
                    .expect("failed to print capabilities");
                    let file_path= format!("/tmp/capable_strace_{}.log", getpid());
                    let access: Vec<SyscallAccessEntry> = if metadata(&file_path).is_ok() {
                        read_strace(file_path)?
                        .iter()
                        .map(|syscall| {
                            if syscall.syscall.trim() == "ptrace" {
                                capset.add(Cap::SYS_PTRACE);
                            }
                            syscalls::syscall_to_entry(syscall)
                        })
                        .flatten()
                        .flatten()
                        .collect()
                    } else {
                        vec![]
                    };
                    let mut map = std::collections::HashMap::new();
                    for entry in access {
                        let key = entry.path.clone();
                        let value = entry.access;
                        *map.entry(key).or_insert(value) |= entry.access;
                    }

                    // dbus filtering
                    // if DBUS_JSON_PATH exists, we will use it to filter the dbus methods
                    let method_list = if metadata(DBUS_JSON_PATH).is_ok() {
                        bus::get_dbus_methods(DBUS_JSON_PATH, nsinode.clone())?
                    } else {
                        vec![]
                    };

                    let mut env_vars = std::collections::HashMap::new();
                    for (key,value) in env::vars() {
                        env_vars.insert(key, value);
                    }
                     
                    let result = ProgramResult {
                        capabilities: capset_to_vec(&capset),
                        files: map,
                        dbus: method_list,
                        env_vars: env_vars,
                    };
                    if let Some(output) = cli_args.output {
                        let mut file = File::create(output)?;
                        writeln!(file, "{}", serde_json::to_string_pretty(&result)?)?;
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    }
                    if !exit.success() {
                        //set the exit code to the command exit code
                        //copy the exit message
                        std::process::exit(exit.code().unwrap_or(-1));
                    }
                }
            }
        }
    }
    Ok(())
}
