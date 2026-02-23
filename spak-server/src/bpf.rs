use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap;
use aya::programs::Xdp;
use aya::programs::XdpFlags;
use aya::Ebpf;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

// Must match `struct destination` in kern/common.h  (16-byte IP + 2-byte port = 18 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Destination {
    pub ip: [u8; 16],
    pub port: u16,
}
unsafe impl aya::Pod for Destination {}

// Must match `struct dest_key_id` in kern/common.h  (Destination + key_id = 20 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DestKeyId {
    pub dest: Destination,
    pub key_id: u16,
}
unsafe impl aya::Pod for DestKeyId {}

// Must match `struct keys` in kern/common.h  (two u64 = 16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Keys {
    pub key1: u64,
    pub key2: u64,
}
unsafe impl aya::Pod for Keys {}

pub fn ipv4_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    Some(bytes)
}

#[allow(dead_code)]
pub fn ipv6_to_bytes(ip_str: &str) -> Option<[u8; 16]> {
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    Some(ip.octets())
}

pub fn parse_secret_key(hex_str: &str) -> Result<Keys> {
    // Remove any '0x' prefix or spaces
    let hex_str = hex_str.trim_start_matches("0x").trim().replace(" ", "");

    if hex_str.len() != 32 {
        return Err(anyhow!(
            "Secret key must be 32 hex characters (16 bytes), got {} characters",
            hex_str.len()
        ));
    }

    // Parse as two u64 values (16 bytes = 128 bits)
    let key1_str = &hex_str[0..16];
    let key2_str = &hex_str[16..32];

    let key1 =
        u64::from_str_radix(key1_str, 16).context("Failed to parse first 8 bytes of secret key")?;
    let key2 = u64::from_str_radix(key2_str, 16)
        .context("Failed to parse second 8 bytes of secret key")?;

    Ok(Keys { key1, key2 })
}

pub struct BpfServer {
    bpf: Ebpf,
}

impl BpfServer {
    pub fn new(data: &[u8]) -> Result<Self> {
        let bpf = Ebpf::load(data)?;
        Ok(Self { bpf })
    }

    pub fn attach_xdp(&mut self, iface: &str) -> Result<()> {
        let program: &mut Xdp = self
            .bpf
            .program_mut("xdp_ingress")
            .ok_or_else(|| anyhow!("Failed to find xdp_ingress program"))?
            .try_into()?;
        program.load()?;
        program.attach(iface, XdpFlags::default())?;
        Ok(())
    }

    pub fn insert_secret(&mut self, key_id: u16, keys: Keys) -> Result<()> {
        let mut secrets: HashMap<_, u16, Keys> = HashMap::try_from(
            self.bpf
                .map_mut("secrets")
                .ok_or_else(|| anyhow!("Failed to get secrets map"))?,
        )?;
        secrets.insert(key_id, keys, 0)?;
        Ok(())
    }

    pub fn insert_protected_destination(&mut self, dest: Destination) -> Result<()> {
        let mut protected: HashMap<_, Destination, u8> = HashMap::try_from(
            self.bpf
                .map_mut("protected_destinations")
                .ok_or_else(|| anyhow!("Failed to get protected_destinations map"))?,
        )?;
        protected.insert(dest, 1u8, 0)?;
        Ok(())
    }

    pub fn insert_destination_secret(
        &mut self,
        dest: Destination,
        key_id: u16,
        keys: Keys,
    ) -> Result<()> {
        let mut destination_secrets: HashMap<_, DestKeyId, Keys> = HashMap::try_from(
            self.bpf
                .map_mut("destination_secrets")
                .ok_or_else(|| anyhow!("Failed to get destination_secrets map"))?,
        )?;

        let composite_key = DestKeyId { dest, key_id };
        destination_secrets.insert(composite_key, keys, 0)?;
        Ok(())
    }
}
