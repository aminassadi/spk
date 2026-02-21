use aya::maps::HashMap;
use aya::programs::Xdp;
use aya::programs::XdpFlags;
use aya::{include_bytes_aligned, Ebpf};
use log::info;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

// Must match `struct destination` in kern/common.h  (16-byte IP + 2-byte port = 18 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct Destination {
    ip: [u8; 16],
    port: u16,
}
unsafe impl aya::Pod for Destination {}

// Must match `struct dest_key_id` in kern/common.h  (Destination + key_id = 20 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct DestKeyId {
    dest: Destination,
    key_id: u16,
}
unsafe impl aya::Pod for DestKeyId {}

// Must match `struct keys` in kern/common.h  (two u64 = 16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Keys {
    key1: u64,
    key2: u64,
}
unsafe impl aya::Pod for Keys {}

fn ipv4_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    Some(bytes)
}

#[allow(dead_code)]
fn ipv6_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    Some(ip.octets())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Starting SPAK eBPF program...");

    let data = include_bytes_aligned!("../../kern/.output/spak.server.bpf.o");
    let mut bpf = Ebpf::load(data)?;

    // Load and attach XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach("lo", XdpFlags::default())?;

    info!("eBPF program loaded successfully");

    // ── 1. Populate the global `secrets` map (key_id -> keys) ───────────────
    let mut secrets: HashMap<_, u16, Keys> =
        HashMap::try_from(bpf.map_mut("secrets").ok_or("Failed to get secrets map")?)?;

    secrets.insert(
        1,
        Keys {
            key1: 0x1122334455667788,
            key2: 0x99aabbccddeeff00,
        },
        0,
    )?;
    info!("Inserted key_id=1 into secrets map");

    // ── 2. Populate `protected_destinations` (destination -> 1u8) ───────────
    let mut protected: HashMap<_, Destination, u8> = HashMap::try_from(
        bpf.map_mut("protected_destinations")
            .ok_or("Failed to get protected_destinations map")?,
    )?;

    // Protect 127.0.0.1:22
    let dest_lo_22 = Destination {
        ip: ipv4_to_bytes("127.0.0.1").unwrap(),
        port: 22u16.to_be(), // network byte order
    };
    protected.insert(dest_lo_22, 1u8, 0)?;
    info!("Protected destination 127.0.0.1:22");

    // ── 3. Populate `destination_secrets` ((destination, key_id) -> keys) ───
    let mut destination_secrets: HashMap<_, DestKeyId, Keys> = HashMap::try_from(
        bpf.map_mut("destination_secrets")
            .ok_or("Failed to get destination_secrets map")?,
    )?;

    let composite_key = DestKeyId {
        dest: dest_lo_22,
        key_id: 1, // same key_id as in secrets map
    };
    destination_secrets.insert(
        composite_key,
        Keys {
            key1: 0x1122334455667788,
            key2: 0x99aabbccddeeff00,
        },
        0,
    )?;
    info!("Inserted (127.0.0.1:22, key_id=1) into destination_secrets");

    info!("All maps populated. Server running...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
