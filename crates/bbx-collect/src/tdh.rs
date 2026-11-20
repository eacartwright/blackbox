//! ETW event decoding. TDH supplies each event type's schema (property names,
//! types, lengths) once; after that, events are decoded by reading their
//! bytes directly, which is much cheaper than formatting through TDH.
//!
//! Only flat properties are decoded (no structs or arrays): decoding stops at
//! the first one it can't handle, which is fine because every field BlackBox
//! uses comes before those in the kernel and DNS schemas.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;
use windows_sys::Win32::System::Diagnostics::Etw::{EVENT_PROPERTY_INFO, EVENT_RECORD, TRACE_EVENT_INFO};

#[link(name = "tdh", kind = "raw-dylib")]
extern "system" {
    fn TdhGetEventInformation(event: *const EVENT_RECORD, ctx_count: u32, ctx: *const c_void, buf: *mut c_void, size: *mut u32) -> u32;
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

// Layout checks for the manual parsing below.
const _: () = assert!(std::mem::size_of::<EVENT_PROPERTY_INFO>() == 24);
const _: () = assert!(std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray) == 112);

const PROPERTY_STRUCT: i32 = 0x1;
const PROPERTY_PARAM_LENGTH: i32 = 0x2;
const PROPERTY_PARAM_COUNT: i32 = 0x4;

// TDH_INTYPE_*
const IN_UNICODESTRING: u16 = 1;
const IN_ANSISTRING: u16 = 2;
const IN_INT8: u16 = 3;
const IN_UINT8: u16 = 4;
const IN_INT16: u16 = 5;
const IN_UINT16: u16 = 6;
const IN_INT32: u16 = 7;
const IN_UINT32: u16 = 8;
const IN_INT64: u16 = 9;
const IN_UINT64: u16 = 10;
const IN_BOOLEAN: u16 = 13;
const IN_BINARY: u16 = 14;
const IN_GUID: u16 = 15;
const IN_POINTER: u16 = 16;
const IN_FILETIME: u16 = 17;
const IN_SID: u16 = 19;
const IN_HEXINT32: u16 = 20;
const IN_HEXINT64: u16 = 21;
const IN_SIZET: u16 = 308;
const IN_WBEMSID: u16 = 310;

// TDH_OUTTYPE_*
const OUT_PORT: u16 = 22;
const OUT_IPV4: u16 = 23;
const OUT_IPV6: u16 = 24;

const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x0020;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U(u64),
    I(i64),
    S(String),
    B(Vec<u8>),
}

impl Value {
    pub fn as_u64(&self) -> u64 {
        match self {
            Value::U(v) => *v,
            Value::I(v) => *v as u64,
            Value::S(s) => s.parse().unwrap_or(0),
            Value::B(_) => 0,
        }
    }
    pub fn as_str(&self) -> String {
        match self {
            Value::S(s) => s.clone(),
            Value::U(v) => v.to_string(),
            Value::I(v) => v.to_string(),
            Value::B(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
        }
    }
}

#[derive(Debug)]
struct Prop {
    name: Arc<str>,
    in_type: u16,
    out_type: u16,
    length: u16,
    flags: i32,
    len_index: u16,
}

#[derive(Debug)]
pub struct Schema {
    pub event_name: String,
    props: Vec<Prop>,
}

/// Decoded top-level properties of one event, in schema order.
#[derive(Debug, Default)]
pub struct Decoded {
    pub props: Vec<(Arc<str>, Value)>,
}

impl Decoded {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.props.iter().find(|(n, _)| &**n == name).map(|(_, v)| v)
    }
    pub fn u64(&self, name: &str) -> u64 {
        self.get(name).map(|v| v.as_u64()).unwrap_or(0)
    }
    pub fn str(&self, name: &str) -> String {
        self.get(name).map(|v| v.as_str()).unwrap_or_default()
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct Key {
    guid: u128,
    id: u16,
    opcode: u8,
    version: u8,
}

fn guid128(g: &windows_sys::core::GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | u64::from_be_bytes(g.data4) as u128
}

pub fn event_guid(r: &EVENT_RECORD) -> u128 {
    guid128(&r.EventHeader.ProviderId)
}

/// Schema cache. Not thread-safe; owned by the consumer thread.
#[derive(Default)]
pub struct Decoder {
    cache: HashMap<Key, Option<Arc<Schema>>>,
    pub schema_failures: u64,
}

impl Decoder {
    fn schema(&mut self, r: &EVENT_RECORD) -> Option<Arc<Schema>> {
        let d = &r.EventHeader.EventDescriptor;
        let key = Key { guid: event_guid(r), id: d.Id, opcode: d.Opcode, version: d.Version };
        if let Some(s) = self.cache.get(&key) {
            return s.clone();
        }
        let s = load_schema(r).map(Arc::new);
        if s.is_none() {
            self.schema_failures += 1;
        }
        self.cache.insert(key, s.clone());
        s
    }

    /// Decode properties until all `wanted` names have been seen (or the
    /// schema runs out / hits something non-flat). Empty `wanted` = all.
    pub fn decode(&mut self, r: &EVENT_RECORD, wanted: &[&str]) -> Option<Decoded> {
        let schema = self.schema(r)?;
        let data: &[u8] = if r.UserData.is_null() || r.UserDataLength == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) }
        };
        let ptr_size = if r.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 { 4 } else { 8 };
        Some(decode_with(&schema, data, ptr_size, wanted))
    }
}

fn load_schema(r: &EVENT_RECORD) -> Option<Schema> {
    let mut size = 0u32;
    let rc = unsafe { TdhGetEventInformation(r, 0, std::ptr::null(), std::ptr::null_mut(), &mut size) };
    if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return None;
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let rc = unsafe { TdhGetEventInformation(r, 0, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
    if rc != 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, size as usize) };
    let rd32 = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let rd16 = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());
    let wstr = |off: u32| -> String {
        if off == 0 || off as usize >= bytes.len() {
            return String::new();
        }
        let mut units = Vec::new();
        let mut o = off as usize;
        while o + 1 < bytes.len() {
            let c = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
            if c == 0 {
                break;
            }
            units.push(c);
            o += 2;
        }
        String::from_utf16_lossy(&units)
    };
    let top = rd32(104) as usize;
    let mut props = Vec::with_capacity(top);
    for i in 0..top {
        let o = 112 + i * 24;
        if o + 24 > bytes.len() {
            break;
        }
        props.push(Prop {
            flags: rd32(o) as i32,
            name: Arc::from(wstr(rd32(o + 4)).as_str()),
            in_type: rd16(o + 8),
            out_type: rd16(o + 10),
            length: rd16(o + 18),
            len_index: rd16(o + 18),
        });
        let count = rd16(o + 16);
        let flags = rd32(o) as i32;
        if flags & (PROPERTY_STRUCT | PROPERTY_PARAM_COUNT) != 0 || count > 1 {
            props.last_mut().unwrap().flags |= PROPERTY_STRUCT; // marks "stop here"
        }
    }
    let event_name = wstr(rd32(92));
    Some(Schema { event_name, props })
}

fn sid_string(b: &[u8]) -> Option<(String, usize)> {
    if b.len() < 8 {
        return None;
    }
    let n = b[1] as usize;
    let len = 8 + 4 * n;
    if b.len() < len || n > 15 {
        return None;
    }
    let auth = u64::from_be_bytes([0, 0, b[2], b[3], b[4], b[5], b[6], b[7]]);
    let mut s = format!("S-{}-{}", b[0], auth);
    for i in 0..n {
        let o = 8 + 4 * i;
        s.push_str(&format!("-{}", u32::from_le_bytes(b[o..o + 4].try_into().unwrap())));
    }
    Some((s, len))
}

fn decode_with(schema: &Schema, data: &[u8], ptr: usize, wanted: &[&str]) -> Decoded {
    let mut out = Decoded::default();
    let mut found = 0usize;
    let mut off = 0usize;
    for p in &schema.props {
        if p.flags & PROPERTY_STRUCT != 0 {
            break;
        }
        let rest = &data[off.min(data.len())..];
        let fixed = |n: usize| -> Option<&[u8]> { rest.get(..n) };
        let le = |b: &[u8]| -> u64 {
            let mut a = [0u8; 8];
            a[..b.len()].copy_from_slice(b);
            u64::from_le_bytes(a)
        };
        let (val, used) = match p.in_type {
            IN_INT8 | IN_UINT8 => match fixed(1) { Some(b) => (Value::U(b[0] as u64), 1), None => break },
            IN_INT16 | IN_UINT16 => match fixed(2) {
                Some(b) if p.out_type == OUT_PORT => (Value::U(u16::from_be_bytes([b[0], b[1]]) as u64), 2),
                Some(b) => (Value::U(le(b)), 2),
                None => break,
            },
            IN_INT32 => match fixed(4) { Some(b) => (Value::I(i32::from_le_bytes(b.try_into().unwrap()) as i64), 4), None => break },
            IN_UINT32 | IN_HEXINT32 | IN_BOOLEAN => match fixed(4) {
                Some(b) if p.out_type == OUT_IPV4 => (Value::S(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])), 4),
                Some(b) => (Value::U(le(b)), 4),
                None => break,
            },
            IN_INT64 => match fixed(8) { Some(b) => (Value::I(i64::from_le_bytes(b.try_into().unwrap())), 8), None => break },
            IN_UINT64 | IN_HEXINT64 | IN_FILETIME => match fixed(8) { Some(b) => (Value::U(le(b)), 8), None => break },
            IN_POINTER | IN_SIZET => match fixed(ptr) { Some(b) => (Value::U(le(b)), ptr), None => break },
            IN_GUID => match fixed(16) { Some(b) => (Value::B(b.to_vec()), 16), None => break },
            IN_UNICODESTRING => {
                let mut units = Vec::new();
                let mut i = 0;
                let limit = if p.length > 0 && p.flags & PROPERTY_PARAM_LENGTH == 0 { (p.length as usize * 2).min(rest.len()) } else { rest.len() };
                while i + 1 < limit {
                    let c = u16::from_le_bytes([rest[i], rest[i + 1]]);
                    i += 2;
                    if c == 0 {
                        break;
                    }
                    units.push(c);
                }
                (Value::S(String::from_utf16_lossy(&units)), i)
            }
            IN_ANSISTRING => {
                let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                (Value::S(String::from_utf8_lossy(&rest[..end]).into_owned()), (end + 1).min(rest.len()))
            }
            IN_BINARY => {
                let n = if p.flags & PROPERTY_PARAM_LENGTH != 0 {
                    out.props.get(p.len_index as usize).map(|(_, v)| v.as_u64() as usize).unwrap_or(0)
                } else {
                    p.length as usize
                };
                match fixed(n) {
                    Some(b) if p.out_type == OUT_IPV6 && n == 16 => (Value::S(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string()), 16),
                    Some(b) => (Value::B(b.to_vec()), n),
                    None => break,
                }
            }
            IN_WBEMSID => {
                // TOKEN_USER {PSID, Attributes} (2 pointers) followed by the SID,
                // or a single 0 ULONG when there is no SID.
                if fixed(4).is_some_and(|b| b == [0, 0, 0, 0]) {
                    (Value::S(String::new()), 4)
                } else {
                    match rest.get(2 * ptr..).and_then(sid_string) {
                        Some((s, n)) => (Value::S(s), 2 * ptr + n),
                        None => break,
                    }
                }
            }
            IN_SID => match sid_string(rest) {
                Some((s, n)) => (Value::S(s), n),
                None => break,
            },
            _ => break,
        };
        off += used;
        if wanted.is_empty() || wanted.contains(&&*p.name) {
            found += 1;
            out.props.push((p.name.clone(), val));
            if !wanted.is_empty() && found == wanted.len() {
                break;
            }
        } else {
            // Keep it anyway: later PropertyParamLength references use indexes.
            out.props.push((p.name.clone(), val));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(props: Vec<(&str, u16, u16, u16)>) -> Schema {
        Schema {
            event_name: "T".into(),
            props: props
                .into_iter()
                .map(|(n, i, o, l)| Prop { name: Arc::from(n), in_type: i, out_type: o, length: l, flags: 0, len_index: l })
                .collect(),
        }
    }

    #[test]
    fn decodes_tcp_like_payload() {
        let s = schema(vec![
            ("PID", IN_UINT32, 0, 4),
            ("size", IN_UINT32, 0, 4),
            ("daddr", IN_UINT32, OUT_IPV4, 4),
            ("saddr", IN_UINT32, OUT_IPV4, 4),
            ("dport", IN_UINT16, OUT_PORT, 2),
            ("sport", IN_UINT16, OUT_PORT, 2),
        ]);
        let mut d = Vec::new();
        d.extend_from_slice(&1234u32.to_le_bytes());
        d.extend_from_slice(&1500u32.to_le_bytes());
        d.extend_from_slice(&[93, 184, 216, 34]);
        d.extend_from_slice(&[10, 0, 0, 5]);
        d.extend_from_slice(&443u16.to_be_bytes());
        d.extend_from_slice(&50000u16.to_be_bytes());
        let out = decode_with(&s, &d, 8, &[]);
        assert_eq!(out.u64("PID"), 1234);
        assert_eq!(out.str("daddr"), "93.184.216.34");
        assert_eq!(out.u64("dport"), 443);
        assert_eq!(out.u64("sport"), 50000);
    }

    #[test]
    fn decodes_process_like_payload_with_sid_and_strings() {
        let s = schema(vec![
            ("UniqueProcessKey", IN_POINTER, 0, 0),
            ("ProcessId", IN_UINT32, 0, 4),
            ("UserSID", IN_WBEMSID, 0, 0),
            ("ImageFileName", IN_ANSISTRING, 0, 0),
            ("CommandLine", IN_UNICODESTRING, 0, 0),
        ]);
        let mut d = Vec::new();
        d.extend_from_slice(&0xffff_8000_0000_1000u64.to_le_bytes());
        d.extend_from_slice(&4242u32.to_le_bytes());
        d.extend_from_slice(&[1u8; 16]); // TOKEN_USER (2 pointers)
        d.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // S-1-5-18
        d.extend_from_slice(b"cmd.exe\0");
        for c in "cmd /c echo hi".encode_utf16().chain(Some(0)) {
            d.extend_from_slice(&c.to_le_bytes());
        }
        let out = decode_with(&s, &d, 8, &[]);
        assert_eq!(out.u64("ProcessId"), 4242);
        assert_eq!(out.str("UserSID"), "S-1-5-18");
        assert_eq!(out.str("ImageFileName"), "cmd.exe");
        assert_eq!(out.str("CommandLine"), "cmd /c echo hi");
    }

    #[test]
    fn stops_at_wanted() {
        let s = schema(vec![("A", IN_UINT32, 0, 4), ("B", IN_UINT32, 0, 4), ("C", 9999, 0, 0)]);
        let d = [1, 0, 0, 0, 2, 0, 0, 0];
        let out = decode_with(&s, &d, 8, &["A"]);
        assert_eq!(out.u64("A"), 1);
        assert!(out.get("B").is_none());
        // Unknown types stop decoding without panicking.
        let out = decode_with(&s, &d, 8, &[]);
        assert_eq!(out.props.len(), 2);
    }
}
