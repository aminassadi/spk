use aya::programs::Xdp;
use aya::programs::XdpFlags;
use aya::{include_bytes_aligned, Ebpf};
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Starting SPAK eBPF program...");

    // Load the eBPF object file
    let data = include_bytes_aligned!("../kern/.output/spak.bpf.o");
    let mut bpf = Ebpf::load(data)?;

    // Get the XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach("lo", XdpFlags::default())?;

    info!("eBPF program loaded successfully");
    // Hardcode secret keys into the "secrets" map at startup
    use aya::maps::HashMap;

    // The struct must match the BPF 'keys' layout: two u64 integers (key1, key2)
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    struct Keys {
        key1: u64,
        key2: u64,
    }

    unsafe impl aya::Pod for Keys {}

    // Put a test key_id and secrets
    let mut secrets =
        HashMap::try_from(bpf.map_mut("secrets").ok_or("Failed to get secrets map")?).unwrap();

    let key_id: u16 = 1;
    let secret = Keys {
        key1: 0x1122334455667788,
        key2: 0x99aabbccddeeff00,
    };
    secrets.insert(key_id, secret, 0)?;

    info!("Hardcoded secret keys inserted into 'secrets' map");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}
