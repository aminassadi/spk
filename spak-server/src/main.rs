mod bpf;

use anyhow::{anyhow, Context, Result};
use aya::include_bytes_aligned;
use bpf::{ipv4_to_bytes, ipv6_to_bytes, parse_secret_key, BpfServer, Destination};
use log::info;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <ip> <port> <key_id> <iface>", args[0]);
        eprintln!("Environment variable SECRET_KEY must be set (32 hex characters, 16 bytes)");
        eprintln!(
            "Example: SECRET_KEY=112233445566778899aabbccddeeff00 {} 127.0.0.1 22 1 ens01",
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
        .parse::<u16>()
        .with_context(|| format!("Invalid port number: {port_str}"))?
        .to_be();

    let key_id: u16 = key_id_str
        .parse()
        .with_context(|| format!("Invalid key_id: {key_id_str}"))?;

    let secret_key_hex =
        env::var("SECRET_KEY").context("SECRET_KEY environment variable not set")?;
    let keys = parse_secret_key(&secret_key_hex).context("Failed to parse SECRET_KEY")?;

    info!("Starting SPAK eBPF program...");

    let data = include_bytes_aligned!("../../kern/.output/spak.server.bpf.o");
    let mut bpf_server = BpfServer::new(data)?;

    bpf_server.attach_xdp(iface)?;
    info!("eBPF program loaded successfully");

    bpf_server.insert_secret(key_id, keys)?;
    info!("Inserted key_id={key_id} into secrets map");

    let dest = Destination {
        ip: target_ip,
        port,
    };
    bpf_server.insert_protected_destination(dest)?;
    info!("Protected destination {ip_str}:{port_str}");

    bpf_server.insert_destination_secret(dest, key_id, keys)?;
    info!("Inserted ({ip_str}:{port_str}, key_id={key_id}) into destination_secrets");

    info!("All maps populated. Server running...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
