mod bpf;

use anyhow::{anyhow, Context, Result};
use aya::include_bytes_aligned;
use bpf::{parse_secret_key, BpfObject, Destination, TargetKeys};
use log::warn;
use std::env;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn ipv4_to_u32(ip_str: &str) -> Option<u32> {
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    Some(ip.to_bits())
}

fn ipv4_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip_u32 = ipv4_to_u32(ip_str)?;
    let mut bytes: [u8; 16] = [0u8; 16];
    bytes[..4].copy_from_slice(&ip_u32.to_be_bytes());
    Some(bytes)
}

fn ipv6_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    Some(ip.octets())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <ip> <port> <key_id> <iface>", args[0]);
        eprintln!("Environment variable SECRET_KEY must be set (32 hex characters, 16 bytes)");
        eprintln!(
            "Example: SECRET_KEY=112233445566778899aabbccddeeff00 {} 127.0.0.1 22 1 lo",
            args[0]
        );
        std::process::exit(1);
    }

    let ip_str = &args[1];
    let port_str = &args[2];
    let key_id_str = &args[3];
    let iface = &args[4];

    let target_ip: [u8; 16] = ipv4_to_bytes(ip_str)
        .or_else(|| ipv6_to_bytes(ip_str))
        .ok_or_else(|| anyhow!("Invalid IP address: {ip_str}"))?;

    let port: u16 = port_str
        .parse()
        .with_context(|| format!("Invalid port number: {port_str}"))?;

    let key_id: u16 = key_id_str
        .parse()
        .with_context(|| format!("Invalid key_id: {key_id_str}"))?;

    let secret_key_hex =
        env::var("SECRET_KEY").context("SECRET_KEY environment variable not set")?;
    let keys = parse_secret_key(&secret_key_hex).context("Failed to parse SECRET_KEY")?;

    ensure_clsact_qdisc(iface).context("failed to prepare clsact qdisc")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nReceived Ctrl+C, detaching eBPF program...");
        shutdown_clone.store(true, Ordering::SeqCst);
    })?;
    let data: &[u8] = include_bytes_aligned!("../../kern/.output/spak.client.bpf.o");
    let bpf_object = BpfObject::new(data)?;
    let link_id = bpf_object.attach_program("tc_egress", iface)?;

    let secret = TargetKeys { keys, key_id };

    let dest = Destination {
        ip: target_ip,
        port,
    };
    bpf_object.insert_secret(dest, secret)?;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("Detaching eBPF program...");
    bpf_object.detach_program(link_id)?;
    if let Err(err) = remove_clsact_qdisc(iface) {
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
