use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{metadata, read_to_string};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Error;
use dashmap::DashMap;
use dbus::arg::{self, Arg, ArgType, Get, RefArg, Variant};
use dbus::channel::Sender;
use dbus::message::MatchRule;
use dbus::{blocking::Connection, channel::MatchingReceiver};
use dbus::{Message, MessageType};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::debug;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbusMsg {
    #[serde(rename = "type", serialize_with = "msg_type_to_string", deserialize_with = "msg_type_from_string")]
    msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ProcessFd {
    fd: u32,
    path: String,
    read: bool,
    write: bool,
}

#[warn(dead_code)]
#[derive(Debug, Serialize)]
struct ConnectionCredentials {
    process_id: u32,
    unix_user_id: u32,
    unix_group_ids: Vec<u32>,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct MsgKey {
    sender: String,
    serial: u32,
}

#[derive(Debug)]
pub struct Memory {
    pub cancel: Arc<AtomicBool>,
    //                            "Systemd (1.7, 21)", "1.21"
    pub credentials_requests: DashMap<MsgKey, String>, // Conversation_key -> Requested Credentials
    pub messages: Mutex<Vec<DbusMsg>>,
    //      "namespace_id" => [ "1.21", "1.22" ]
    pub owners: DashMap<u32, Vec<String>>,
    //                "1.21"  [ "org.freedesktop.systemd1.Manager.Reboot" ]
    pub requests: DashMap<String, Vec<DbusMsg>>,
}



impl Default for Memory {
    fn default() -> Self {
        Memory {
            cancel: Arc::new(AtomicBool::new(false)),
            credentials_requests: DashMap::new(),
            messages: Mutex::new(Vec::new()),
            owners: DashMap::new(),
            requests: DashMap::new(),
        }
    }
}

fn msg_type_to_string<S>(msg_type: &MessageType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{:?}", msg_type))
}

fn msg_type_from_string<'de, D>(deserializer: D) -> Result<MessageType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.as_str() {
        "MethodCall" => Ok(MessageType::MethodCall),
        "MethodReturn" => Ok(MessageType::MethodReturn),
        "Error" => Ok(MessageType::Error),
        "Signal" => Ok(MessageType::Signal),
        _ => Err(serde::de::Error::custom(format!("Unknown message type: {}", s))),
    }
}

// This programs implements the equivalent of running the "dbus-monitor" tool
pub(crate) fn run_dbus_monitor(
    d_data: Arc<Memory>,
) -> Result<HashMap<u32,Vec<DbusMsg>>, Error> {
    // First open up a connection to the desired bus.
    let conn = Connection::new_system().expect("D-Bus connection failed");

    // Second create a rule to match messages we want to receive; in this example we add no
    // further requirements, so all messages will match
    let rule = MatchRule::new();

    // Try matching using new scheme
    let proxy = conn.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_millis(5000),
    );
    let result: Result<(), dbus::Error> = proxy.method_call(
        "org.freedesktop.DBus.Monitoring",
        "BecomeMonitor",
        (vec![rule.match_str()], 0u32),
    );
    match result {
        // BecomeMonitor was successful, start listening for messages
        Ok(_) => {
            let data = d_data.clone();
            conn.start_receive(
                rule,
                Box::new(move |msg, _| {
                    handle_message(data.clone(), &msg);
                    true
                }),
            );
        }
        // BecomeMonitor failed, fallback to using the old scheme
        Err(e) => {
            eprintln!(
                "Failed to BecomeMonitor: '{}', falling back to eavesdrop",
                e
            );

            // First, we'll try "eavesdrop", which as the name implies lets us receive
            // *all* messages, not just ours.
            let rule_with_eavesdrop = {
                let mut rule = rule.clone();
                rule.eavesdrop = true;
                rule
            };
            let data = d_data.clone();
            let result = conn.add_match(rule_with_eavesdrop, move |_: (), _, msg| {
                handle_message(data.clone(), &msg);
                true
            });
            let data = d_data.clone();
            match result {
                Ok(_) => {
                    // success, we're now listening
                }
                // This can sometimes fail, for example when listening to the system bus as a non-root user.
                // So, just like `dbus-monitor`, we attempt to fallback without `eavesdrop=true`:
                Err(e) => {
                    eprintln!("Failed to eavesdrop: '{}', trying without it", e);
                    conn.add_match(rule, move |_: (), _, msg| {
                        handle_message(data.clone(), &msg);
                        true
                    })
                    .expect("add_match failed");
                }
            }
        }
    }

    // Loop and print out all messages received (using handle_message()) as they come.
    // Some can be quite large, e.g. if they contain embedded images..
    while d_data.cancel.load(std::sync::atomic::Ordering::Relaxed) == false {
        conn.process(Duration::from_millis(1000)).unwrap();
    }

    // join d_data.owners and d_data.requests
    let mut nsid_to_requests = HashMap::new();
    d_data.owners.iter().for_each(|x| {
        let nsid = x.key();
        let owners = x.value();
        for owner in owners {
            if let Some(requests) = d_data.requests.get(owner) {
                debug!("extend requests: {:?}", requests.value());
                if !nsid_to_requests.contains_key(nsid) {
                    nsid_to_requests.insert(*nsid, Vec::new());
                }
                nsid_to_requests.get_mut(nsid).unwrap().extend(requests.value().clone());
            }
        }
    });
    debug!("nsid_to_requests: {:?}", nsid_to_requests);
    Ok(nsid_to_requests)
}

pub fn get_dbus_methods<P:AsRef<Path>>(path : P, nsid : Rc<RefCell<u32>>) -> Result<Vec<String>, Error> {
    let path = path.as_ref();
    let nsid = nsid.borrow();
    //read json file
    let content = read_to_string(path).expect("failed to read file");
    let content: HashMap<u32,Vec<DbusMsg>> = serde_json::from_str(&content).unwrap();
    let requests = content.get(&nsid).unwrap();
    let mut methods = Vec::new();
    for request in requests {
        if request.msg_type == MessageType::MethodCall {
            methods.push(format!("{}.{}", request.interface.as_ref().unwrap(), request.method.as_ref().unwrap()));
        }
    }
    Ok(methods)
}

fn handle_message(
    data: Arc<Memory>,
    msg: &Message,
) {
    let sender = msg.sender().map(|x| x.to_string());
    let dest = msg.destination().map(|x| x.to_string());
    let dbus_msg = DbusMsg {
        msg_type: msg.msg_type(),
        sender: sender.clone(),
        destination: dest.clone(),
        serial: if msg.msg_type() == MessageType::MethodReturn {
            msg.get_reply_serial()
        } else {
            msg.get_serial()
        },
        interface: msg.interface().map(|x| x.to_string().trim_matches('"').to_string()),
        method: msg.member().map(|x| x.to_string()),
        path: msg.path().map(|x| x.to_string()),
        arguments: if msg.iter_init().count() > 0 {
            Some(
                msg.iter_init()
                    .map(|arg| format!("{:?}", arg).trim_matches('"').to_string())
                    .collect(),
            )
        } else {
            None
        },
    };

    let key = dest.map(|dest| {
        MsgKey {
            sender: dest,
            serial: dbus_msg.serial.unwrap(),
        }
    });
    
    if dbus_msg.msg_type == MessageType::MethodCall
        && dbus_msg.method
            .as_ref().is_some_and(|x| x == "GetConnectionCredentials")
    {
        let key = MsgKey {
            sender: sender.clone().unwrap(),
            serial: dbus_msg.serial.unwrap(),
        };
        data.credentials_requests.insert(
            key,
            msg.get1().unwrap(),
        );
    } else if dbus_msg.msg_type == MessageType::MethodReturn
        && key.as_ref().is_some_and( |key| data.credentials_requests.contains_key(&key) )
    {
        let map : HashMap<String,Variant<Box<dyn RefArg>>> = msg.get1().unwrap();
        let process_id = map.get("ProcessID").unwrap().0.as_u64().unwrap() as i32;
        // read /proc/<pid>/name to get the path of the socket
        let nspid =
                    metadata(format!("/proc/{}/ns/pid", process_id)).expect("failed to open pid ns").ino() as u32;
        let dbus_id = data.credentials_requests.get(&key.unwrap()).unwrap().to_string();
        let array = data.owners.get_mut(&nspid);
        match array {
            Some(mut array) => {
                if !array.contains(&dbus_id) {
                    debug!("We know that ProcessID: {} is DbusID: {}, which is under {} namespace", process_id, dbus_id, nspid);
                    array.push(dbus_id);
                }
            }
            None => {
                debug!("We know that ProcessID: {} is DbusID: {}, which is under {} namespace", process_id, dbus_id, nspid);
                data.owners.insert(nspid, vec![dbus_id]);
            }
        }
    } else if dbus_msg.msg_type == MessageType::MethodCall {
        data.requests.entry(sender.unwrap()).or_insert(Vec::new()).push(dbus_msg.clone());
    }
    data.messages.lock().unwrap().push(dbus_msg);
}
