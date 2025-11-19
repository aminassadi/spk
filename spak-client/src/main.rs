use anyhow::{anyhow, Context, Result};
use aya::programs::{self, tc::SchedClassifierLinkId};
use aya::{include_bytes_aligned, Ebpf};
use log::warn;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const IFACE: &str = "lo";

fn main() -> Result<()> {
    env_logger::init();

    ensure_clsact_qdisc(IFACE).context("failed to prepare clsact qdisc")?;

    let data = include_bytes_aligned!("../../kern/.output/spak.client.bpf.o");
    let mut bpf = Ebpf::load(data)?;
    let program: &mut programs::SchedClassifier = bpf
        .program_mut("tc_egress")
        .context("failed to find tc_egress program")?
        .try_into()?;
    program.load()?;
    let link_id = program.attach(IFACE, aya::programs::TcAttachType::Egress)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_flag = shutdown.clone();
    ctrlc::set_handler(move || {
        signal_flag.store(true, Ordering::SeqCst);
    })
    .context("failed to install Ctrl-C handler")?;

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }

    detach_classifier(program, link_id)?;
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
