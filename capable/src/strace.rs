use std::{collections::HashMap, fmt::Display, fs, path::Path};

use pest::Parser;
use pest_derive::Parser;
use tracing::{debug, warn};

pub struct Syscall {
    pub syscall: String,
    pub args: Vec<Parameter>,
    pub return_code: ReturnCode,
}

#[derive(Clone)]
pub enum Parameter {
    String(String),
    Array(Vec<String>),
    Constant(String),
    Comment(String),
    Dict(HashMap<String, String>),
}

impl Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Parameter::String(s) => write!(f, "{}", s),
            Parameter::Array(a) => write!(f, "{:?}", a),
            Parameter::Constant(c) => write!(f, "{}", c),
            Parameter::Comment(c) => write!(f, "{}", c),
            Parameter::Dict(d) => write!(f, "{:?}", d),
        }
    }
}

pub struct ReturnCode {
    pub code: i32,
    pub constant: Option<String>,
    pub message: Option<String>,
}

#[derive(Parser)]
#[grammar = "strace.pest"]
struct StraceParser;

pub fn read_strace<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Syscall>> {
    debug!("Reading strace file: {:?}", path.as_ref());
    let binding = fs::read_to_string(path)?;
    debug!("Parsing strace file");
    let pairs = StraceParser::parse(Rule::file, &binding).unwrap_or_else(|e| panic!("{}", e));
    let mut syscalls = Vec::new();
    for pair in pairs {
        match pair.as_rule() {
            Rule::syscall_call => {
                parse_syscall(pair, &mut syscalls);
            }
            Rule::EOI | Rule::exit => (),
            _ => warn!("Unexpected rule: {:?}", pair.as_rule()),
        }
    }
    Ok(syscalls)
}

fn parse_syscall(pair: pest::iterators::Pair<'_, Rule>, syscalls: &mut Vec<Syscall>) {
    let mut syscall = Syscall {
        syscall: String::new(),
        args: Vec::new(),
        return_code: ReturnCode {
            code: 0,
            constant: None,
            message: None,
        },
    };
    for pair in pair.into_inner() {
        match pair.as_rule() {
            Rule::syscall => {
                if !syscall.syscall.is_empty() {
                    syscalls.push(syscall);
                    syscall = Syscall {
                        syscall: String::new(),
                        args: Vec::new(),
                        return_code: ReturnCode {
                            code: 0,
                            constant: None,
                            message: None,
                        },
                    };
                }
                syscall.syscall = pair.as_str().to_string();
                warn!("Syscall: {:?}", syscall.syscall);
            },
            Rule::array => {
                syscall.args.push(Parameter::Array(
                    pair.into_inner().map(|x| x.as_str().to_string()).collect(),
                ));
            }
            Rule::string => {
                syscall
                    .args
                    .push(Parameter::String(pair.as_str().to_string()));
            }
            Rule::constant => {
                syscall
                    .args
                    .push(Parameter::Constant(pair.as_str().to_string()));
            }
            Rule::comment => {
                syscall
                    .args
                    .push(Parameter::Comment(pair.as_str().to_string()));
            }
            Rule::structure => {
                let mut map = HashMap::new();
                let mut inner = pair.into_inner();
                while let Some(inner_pair) = inner.next() {
                    match inner_pair.as_rule() {
                        Rule::key => {
                            let key = inner_pair.as_str().to_string();
                            let value = inner.next().unwrap().as_str().to_string();
                            map.insert(key, value);
                        }
                        _ => {
                            warn!("Unexpected rule: {:?}", inner_pair.as_rule());
                        }
                    }
                }
                syscall.args.push(Parameter::Dict(map));
            }
            Rule::return_code => {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::return_value => {
                            syscall.return_code.code = inner_pair.as_str().trim().parse().unwrap()
                        }
                        Rule::constant => {
                            syscall.return_code.constant = Some(inner_pair.as_str().to_string())
                        }
                        Rule::message => {
                            syscall.return_code.message = Some(inner_pair.as_str().to_string())
                        }
                        _ => {
                            warn!("Unexpected rule: {:?}", inner_pair.as_rule());
                        }
                    }
                }
            },
            Rule::signal => {
                warn!("Signal: {:?}", pair.as_str());
            },
            _ => {
                warn!("Unexpected rule: {:?}", pair.as_rule());
            }
        }
    }
    syscalls.push(syscall);
}
