use anyhow::{anyhow, Context, Result};
use aya::programs::{self, tc::SchedClassifierLinkId};
use aya::{include_bytes_aligned, maps::HashMap, Ebpf};
use log::warn;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::cell::RefCell;
use std::rc::Rc;

const IFACE: &str = "lo";

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Keys {
    key1: u64,
    key2: u64,
}
unsafe impl aya::Pod for Keys {}

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

    fn insert_secret(&self, key_id: u16, secret: Keys) -> Result<(), String> {
        let mut bpf = self.value.borrow_mut();
        let mut secrets =
            HashMap::try_from(bpf.map_mut("secrets").ok_or("Failed to get secrets map")?).unwrap();
        secrets
            .insert(key_id, secret, 0)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    ensure_clsact_qdisc(IFACE).context("failed to prepare clsact qdisc")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let data: &[u8] = include_bytes_aligned!("../../kern/.output/spak.client.bpf.o");
    let bpf_object = BpfObject::new(data)?;
    let link_id = bpf_object.attach_program("tc_egress")?;
    let key_id: u16 = 1;
    let secret = Keys {
        key1: 0x1122334455667788,
        key2: 0x99aabbccddeeff00,
    };
    bpf_object.insert_secret(key_id, secret)?;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }
    bpf_object.detach_program(link_id)?;
    if let Err(err) = remove_clsact_qdisc(IFACE) {
        warn!("{err:#}");
    }
    Ok(())
}

fn detach_classifier(
    program: &mut programs::SchedClassifier,
    link_id: SchedClassifierLinkId,
) -> Result<()> {
    program
        .detach(link_id)
        .context("failed to detach tc program from interface")
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
