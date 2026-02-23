use anyhow::{anyhow, Context, Result};
use aya::programs::{self, tc::SchedClassifierLinkId};
use aya::{maps::HashMap, Ebpf};
use std::cell::RefCell;

const IFACE: &str = "lo";

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Keys {
    pub key1: u64,
    pub key2: u64,
}
unsafe impl aya::Pod for Keys {}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TargetKeys {
    pub keys: Keys,
    pub key_id: u16,
}
unsafe impl aya::Pod for TargetKeys {}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Destination {
    pub ip: [u8; 16],
    pub port: u16,
}
unsafe impl aya::Pod for Destination {}

pub struct BpfObject {
    value: RefCell<Ebpf>,
}

impl BpfObject {
    pub fn new(data: &[u8]) -> Result<Self> {
        let bpf: Ebpf = Ebpf::load(data)?;
        Ok(Self {
            value: RefCell::new(bpf),
        })
    }

    pub fn attach_program(&self, name: &str) -> Result<SchedClassifierLinkId, anyhow::Error> {
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

    pub fn detach_program(&self, link_id: SchedClassifierLinkId) -> Result<(), anyhow::Error> {
        let mut bpf = self.value.borrow_mut();
        let program: &mut programs::SchedClassifier = bpf
            .program_mut("tc_egress")
            .context("failed to find tc_egress program")
            .map_err(|e| anyhow!(e))?
            .try_into()?;
        program.detach(link_id)?;
        Ok(())
    }

    pub fn insert_secret(&self, key: Destination, secret: TargetKeys) -> Result<(), String> {
        let mut bpf = self.value.borrow_mut();
        let mut secrets =
            HashMap::try_from(bpf.map_mut("secrets").ok_or("Failed to get secrets map")?).unwrap();
        secrets.insert(key, secret, 0).map_err(|e| e.to_string())?;
        Ok(())
    }
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
