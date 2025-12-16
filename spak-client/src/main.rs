use anyhow::{anyhow, Context, Result};
use aya::programs::{self, tc::SchedClassifierLinkId};
use aya::{include_bytes_aligned, maps::HashMap, Ebpf};
use log::warn;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::rc::Rc;

const IFACE: &str = "lo";

fn ipv4_to_u32(ip_str: &str) -> Option<u32> {
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    Some(ip.to_bits())
}

fn ipv4_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let mut ip_u32 = ipv4_to_u32(ip_str)?;
    let mut bytes: [u8; 16] = [0u8; 16];
    bytes[..4].copy_from_slice(&ip_u32.to_be_bytes());
    Some(bytes)
}

fn ipv6_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    Some(ip.octets())
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Keys {
    key1: u64,
    key2: u64,
}
unsafe impl aya::Pod for Keys {}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TargetKeys {
    keys: Keys,
    key_id: u16,
}
unsafe impl aya::Pod for TargetKeys {}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Destination {
    ip: [u8; 16],
    port: u16,
}
unsafe impl aya::Pod for Destination {}

struct BpfObject {
    value: RefCell<Ebpf>,
}

impl BpfObject {
    fn new(data: &[u8]) -> Result<Self> {
        let bpf: Ebpf = Ebpf::load(data)?;
        Ok(Self {
            value: RefCell::new(bpf),
        })
    }

    fn attach_program(&self, name: &str) -> Result<SchedClassifierLinkId, anyhow::Error> {
        let mut bpf = self.value.borrow_mut();
        let program: &mut programs::SchedClassifier = bpf
            .program_mut(name)
            .context("failed to find program")
            .map_err(|e| anyhow!(e))?
            .try_into()?;
        program.load()?;
        let link_id = program.attach(IFACE, aya::programs::TcAttachType::Egress)?;
        Ok(link_id)
    }

    fn detach_program(&self, link_id: SchedClassifierLinkId) -> Result<(), anyhow::Error> {
        let mut bpf = self.value.borrow_mut();
        let program: &mut programs::SchedClassifier = bpf
            .program_mut("tc_egress")
            .context("failed to find tc_egress program")
            .map_err(|e| anyhow!(e))?
            .try_into()?;
        program.detach(link_id)?;
        Ok(())
    }

    fn insert_secret(&self, key: Destination, secret: TargetKeys) -> Result<(), String> {
        let mut bpf = self.value.borrow_mut();
        let mut secrets =
            HashMap::try_from(bpf.map_mut("secrets").ok_or("Failed to get secrets map")?).unwrap();
        secrets.insert(key, secret, 0).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    ensure_clsact_qdisc(IFACE).context("failed to prepare clsact qdisc")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nReceived Ctrl+C, detaching eBPF program...");
        shutdown_clone.store(true, Ordering::SeqCst);
    })?;
    let data: &[u8] = include_bytes_aligned!("../../kern/.output/spak.client.bpf.o");
    let bpf_object = BpfObject::new(data)?;
    let link_id = bpf_object.attach_program("tc_egress")?;
    let key_id: u16 = 1;
    let secret = TargetKeys {
        keys: Keys {
            key1: 0x1122334455667788,
            key2: 0x99aabbccddeeff00,
        },
        key_id: key_id,
    };
    let target_ip: [u8; 16] = ipv4_to_bytes("127.0.0.1").unwrap();

    let dest = Destination {
        ip: target_ip,
        port: 22,
    };
    bpf_object.insert_secret(dest, secret)?;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("Detaching eBPF program...");
    bpf_object.detach_program(link_id)?;
    if let Err(err) = remove_clsact_qdisc(IFACE) {
        warn!("{err:#}");
    }
    Ok(())
}

fn ensure_clsact_qdisc(iface: &str) -> Result<()> {
    let output = Command::new("tc")
        .args(["qdisc", "add", "dev", iface, "clsact"])
        .output()
        .with_context(|| format!("failed to execute tc for interface {iface}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") {
        return Ok(());
    }
    if stderr.contains("Exclusivity flag on") {
        let replace = Command::new("tc")
            .args(["qdisc", "replace", "dev", iface, "clsact"])
            .output()
            .with_context(|| format!("failed to execute tc replace for interface {iface}"))?;
        if replace.status.success() {
            return Ok(());
        }
        let replace_stderr = String::from_utf8_lossy(&replace.stderr);
        return Err(anyhow!(
            "tc qdisc replace dev {iface} clsact failed: {}",
            replace_stderr.trim()
        ));
    }

    Err(anyhow!(
        "tc qdisc add dev {iface} clsact failed: {}",
        stderr.trim()
    ))
}

fn remove_clsact_qdisc(iface: &str) -> Result<()> {
    let output = Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output()
        .with_context(|| format!("failed to execute tc delete for interface {iface}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file")
        || stderr.contains("Cannot delete qdisc with handle of zero")
        || stderr.contains("RTNETLINK answers: No such file or directory")
    {
        return Ok(());
    }

    Err(anyhow!(
        "tc qdisc del dev {iface} clsact failed: {}",
        stderr.trim()
    ))
}
