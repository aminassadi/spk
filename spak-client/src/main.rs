use anyhow::{Context, Result};
use aya::programs::{self};
use aya::{include_bytes_aligned, Ebpf};
use std::process::Command;

fn main() -> Result<()> {
    env_logger::init();

   // ensure_clsact_qdisc("lo").context("failed to prepare clsact qdisc")?;

    let data = include_bytes_aligned!("../../kern/.output/spak.client.bpf.o");
    let mut bpf = Ebpf::load(data)?;
    let program: &mut programs::SchedClassifier = bpf
        .program_mut("tc_egress")
        .context("failed to find tc_egress program")?
        .try_into()?;
    program.load()?;
    program.attach("lo", aya::programs::TcAttachType::Egress)?;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}

// fn ensure_clsact_qdisc(iface: &str) -> Result<()> {
//     let output = Command::new("tc")
//         .args(["qdisc", "add", "dev", iface, "clsact"])
//         .output()
//         .with_context(|| format!("failed to execute tc for interface {iface}"))?;

//     if output.status.success() {
//         return Ok(());
//     }

//     let stderr = String::from_utf8_lossy(&output.stderr);
//     if stderr.contains("File exists") {
//         return Ok(());
//     }
//     if stderr.contains("Exclusivity flag on") {
//         let replace = Command::new("tc")
//             .args(["qdisc", "replace", "dev", iface, "clsact"])
//             .output()
//             .with_context(|| format!("failed to execute tc replace for interface {iface}"))?;
//         if replace.status.success() {
//             return Ok(());
//         }
//         let replace_stderr = String::from_utf8_lossy(&replace.stderr);
//         return Err(anyhow::anyhow!(
//             "tc qdisc replace dev {iface} clsact failed: {}",
//             replace_stderr.trim()
//         ));
//     }

//     Err(anyhow::anyhow!(
//         "tc qdisc add dev {iface} clsact failed: {}",
//         stderr.trim()
//     ))
// }
