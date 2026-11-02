//! Per-process TCP/UDP endpoints from the IP Helper owner-pid tables, plus a
//! background reverse-DNS resolver for public remote addresses.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use windows::Win32::NetworkManagement::IpHelper::*;

#[derive(Serialize, Clone, Debug)]
pub struct Conn {
    pub proto: &'static str,
    pub pid: u32,
    pub laddr: String,
    pub lport: u16,
    pub raddr: String,
    pub rport: u16,
    pub state: &'static str,
    pub host: String,
    pub first_ms: i64,
    /// remote side is a routable internet address
    pub public: bool,
}

impl Conn {
    pub fn key(&self) -> (u32, &'static str, String, u16, String, u16) {
        (self.pid, self.proto, self.laddr.clone(), self.lport, self.raddr.clone(), self.rport)
    }
    /// An actual conversation with another host (not a listener, not loopback).
    pub fn is_remote(&self) -> bool {
        self.proto.starts_with("tcp")
            && !matches!(self.state, "LISTEN" | "CLOSED" | "DELETE_TCB")
            && self.raddr.parse::<IpAddr>().is_ok_and(|ip| !ip.is_loopback() && !ip.is_unspecified())
    }
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "?",
    }
}

pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64) // CGNAT
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// Calls an IP Helper table function with a growing, 8-byte aligned buffer.
unsafe fn fetch(f: impl Fn(Option<*mut c_void>, *mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size = 0u32;
    f(None, &mut size);
    for _ in 0..4 {
        let mut buf = vec![0u64; size as usize / 8 + 1];
        size = (buf.len() * 8) as u32;
        match f(Some(buf.as_mut_ptr() as *mut c_void), &mut size) {
            0 => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return None,
        }
    }
    None
}

unsafe fn rows<'a, T>(buf: &'a [u64], first: *const T) -> &'a [T] {
    let n = *(buf.as_ptr() as *const u32) as usize;
    std::slice::from_raw_parts(first, n)
}

fn conn(proto: &'static str, pid: u32, l: IpAddr, lport: u16, r: Option<IpAddr>, rport: u16, state: &'static str) -> Conn {
    Conn {
        proto,
        pid,
        laddr: l.to_string(),
        lport,
        raddr: r.map(|x| x.to_string()).unwrap_or_else(|| "*".into()),
        rport,
        state,
        host: String::new(),
        first_ms: 0,
        public: r.is_some_and(|x| is_public(&x)),
    }
}

pub fn snapshot() -> Vec<Conn> {
    let mut out = Vec::new();
    unsafe {
        if let Some(buf) = fetch(|p, s| GetExtendedTcpTable(p, s, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) {
            let t = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            for r in rows(&buf, t.table.as_ptr()) {
                let ra = Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes());
                out.push(conn("tcp", r.dwOwningPid, Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).into(), port(r.dwLocalPort),
                    Some(ra.into()), port(r.dwRemotePort), tcp_state(r.dwState)));
            }
        }
        if let Some(buf) = fetch(|p, s| GetExtendedTcpTable(p, s, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) {
            let t = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            for r in rows(&buf, t.table.as_ptr()) {
                out.push(conn("tcp6", r.dwOwningPid, Ipv6Addr::from(r.ucLocalAddr).into(), port(r.dwLocalPort),
                    Some(Ipv6Addr::from(r.ucRemoteAddr).into()), port(r.dwRemotePort), tcp_state(r.dwState)));
            }
        }
        if let Some(buf) = fetch(|p, s| GetExtendedUdpTable(p, s, false, AF_INET, UDP_TABLE_OWNER_PID, 0)) {
            let t = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            for r in rows(&buf, t.table.as_ptr()) {
                out.push(conn("udp", r.dwOwningPid, Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).into(), port(r.dwLocalPort), None, 0, ""));
            }
        }
        if let Some(buf) = fetch(|p, s| GetExtendedUdpTable(p, s, false, AF_INET6, UDP_TABLE_OWNER_PID, 0)) {
            let t = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            for r in rows(&buf, t.table.as_ptr()) {
                out.push(conn("udp6", r.dwOwningPid, Ipv6Addr::from(r.ucLocalAddr).into(), port(r.dwLocalPort), None, 0, ""));
            }
        }
    }
    out
}

/// Reverse DNS on a single background thread; lookups can take seconds.
pub struct Resolver {
    cache: Mutex<HashMap<IpAddr, String>>,
    pending: Mutex<HashSet<IpAddr>>,
    tx: Mutex<Sender<IpAddr>>,
}

impl Resolver {
    pub fn start() -> Arc<Resolver> {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let r = Arc::new(Resolver { cache: Mutex::default(), pending: Mutex::default(), tx: Mutex::new(tx) });
        let me = r.clone();
        std::thread::spawn(move || {
            for ip in rx {
                let name = dns_lookup::lookup_addr(&ip).ok().filter(|n| *n != ip.to_string()).unwrap_or_default();
                me.cache.lock().unwrap().insert(ip, name);
                me.pending.lock().unwrap().remove(&ip);
            }
        });
        r
    }

    /// Cached host name ("" when the address has none); queues a lookup on a miss.
    pub fn name(&self, ip: IpAddr) -> String {
        if let Some(n) = self.cache.lock().unwrap().get(&ip) {
            return n.clone();
        }
        if self.pending.lock().unwrap().insert(ip) {
            let _ = self.tx.lock().unwrap().send(ip);
        }
        String::new()
    }
}
