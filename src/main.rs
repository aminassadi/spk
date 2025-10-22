use aya::{Ebpf, include_bytes_aligned};
use aya::programs::Xdp;
use aya::programs::XdpFlags;
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
    program.attach("ens33", XdpFlags::default())?;
    
    info!("eBPF program loaded successfully");
    
    // Keep the program running
    info!("Press Ctrl+C to stop the program");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}