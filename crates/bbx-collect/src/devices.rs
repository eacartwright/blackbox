//! Device watcher: diffs the set of present devices and their problem codes
//! every few seconds. Catches USB/dock/disk/GPU devices disappearing and
//! devices entering a problem state (Code 43, Code 10, ...).

use crate::util::{below_normal_priority, from_wide};
use crate::Ctx;
use anyhow::{anyhow, Result};
use bbx_core::records::{Device, DeviceInventory, DeviceRow, RecordType};
use std::collections::HashMap;
use std::time::Duration;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Registry_PropertyW, CM_Get_DevNode_Status, CM_Get_Device_ID_ListW, CM_Get_Device_ID_List_SizeW,
    CM_Locate_DevNodeW,
};

const CR_SUCCESS: u32 = 0;
const CR_BUFFER_SMALL: u32 = 0x1A;
const CM_GETIDLIST_FILTER_PRESENT: u32 = 0x100;
const CM_DRP_DEVICEDESC: u32 = 0x01;
const CM_DRP_CLASS: u32 = 0x08;
const CM_DRP_FRIENDLYNAME: u32 = 0x0D;
const DN_HAS_PROBLEM: u32 = 0x400;

fn present_ids() -> Result<Vec<String>> {
    for _ in 0..4 {
        let mut len = 0u32;
        let rc = unsafe { CM_Get_Device_ID_List_SizeW(&mut len, std::ptr::null(), CM_GETIDLIST_FILTER_PRESENT) };
        if rc != CR_SUCCESS {
            return Err(anyhow!("CM_Get_Device_ID_List_Size failed: {rc}"));
        }
        let mut buf = vec![0u16; len as usize + 1];
        let rc = unsafe { CM_Get_Device_ID_ListW(std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32, CM_GETIDLIST_FILTER_PRESENT) };
        if rc == CR_BUFFER_SMALL {
            continue; // a device arrived between the two calls
        }
        if rc != CR_SUCCESS {
            return Err(anyhow!("CM_Get_Device_ID_List failed: {rc}"));
        }
        return Ok(buf.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect());
    }
    Err(anyhow!("device list kept changing"))
}

fn devnode(id: &str) -> Option<u32> {
    let w: Vec<u16> = id.encode_utf16().chain(Some(0)).collect();
    let mut dn = 0u32;
    (unsafe { CM_Locate_DevNodeW(&mut dn, w.as_ptr(), 0) } == CR_SUCCESS).then_some(dn)
}

fn problem(dn: u32) -> u32 {
    let (mut status, mut prob) = (0u32, 0u32);
    if unsafe { CM_Get_DevNode_Status(&mut status, &mut prob, dn, 0) } != CR_SUCCESS {
        return 0;
    }
    if status & DN_HAS_PROBLEM != 0 { prob } else { 0 }
}

fn prop(dn: u32, which: u32) -> String {
    let mut buf = vec![0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let mut ty = 0u32;
    let rc = unsafe { CM_Get_DevNode_Registry_PropertyW(dn, which, &mut ty, buf.as_mut_ptr().cast(), &mut len, 0) };
    if rc != CR_SUCCESS {
        return String::new();
    }
    from_wide(&buf)
}

fn describe(id: &str, dn: Option<u32>) -> DeviceRow {
    let (name, class, prob) = match dn {
        Some(dn) => {
            let mut n = prop(dn, CM_DRP_FRIENDLYNAME);
            if n.is_empty() {
                n = prop(dn, CM_DRP_DEVICEDESC);
            }
            (n, prop(dn, CM_DRP_CLASS), problem(dn))
        }
        None => Default::default(),
    };
    DeviceRow { id: id.to_string(), name, class, problem: prob }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    below_normal_priority();
    let interval = Duration::from_millis(ctx.cfg.device_poll_ms.max(1000));
    // id -> (name/class row with last problem)
    let mut known: HashMap<String, DeviceRow> = HashMap::new();
    for id in present_ids()? {
        let row = describe(&id, devnode(&id));
        known.insert(id, row);
    }
    let mut inv: Vec<DeviceRow> = known.values().cloned().collect();
    inv.sort_by(|a, b| a.class.cmp(&b.class).then(a.name.cmp(&b.name)));
    ctx.emit(RecordType::DeviceInventory, &DeviceInventory { devices: inv });

    while !ctx.stop.wait(interval) {
        let ids = present_ids()?;
        let mut present: HashMap<String, ()> = HashMap::with_capacity(ids.len());
        for id in ids {
            let dn = devnode(&id);
            match known.get_mut(&id) {
                None => {
                    let row = describe(&id, dn);
                    ctx.emit(RecordType::Device, &Device { action: "added".into(), dev: row.clone(), old_problem: 0 });
                    known.insert(id.clone(), row);
                }
                Some(row) => {
                    let p = dn.map(problem).unwrap_or(0);
                    if p != row.problem {
                        let old = row.problem;
                        row.problem = p;
                        let action = if p == 0 { "recovered" } else { "problem" };
                        ctx.emit(RecordType::Device, &Device { action: action.into(), dev: row.clone(), old_problem: old });
                    }
                }
            }
            present.insert(id, ());
        }
        let removed: Vec<String> = known.keys().filter(|k| !present.contains_key(*k)).cloned().collect();
        for id in removed {
            if let Some(row) = known.remove(&id) {
                ctx.emit(RecordType::Device, &Device { action: "removed".into(), old_problem: row.problem, dev: row });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_devices_with_names() {
        let ids = super::present_ids().unwrap();
        assert!(ids.len() > 20);
        let named = ids.iter().filter(|id| !super::describe(id, super::devnode(id)).name.is_empty()).count();
        assert!(named > ids.len() / 2);
    }
}
