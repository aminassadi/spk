mod build_common {
    include!("../build_common.rs");
}

fn main() {
    use build_common::*;
    
    let workspace_root = get_workspace_root();
    
    // Initialize git submodules
    if let Err(e) = init_submodules(&workspace_root) {
        eprintln!("Error initializing submodules: {}", e);
        std::process::exit(1);
    }
    
    // Setup rerun-if-changed
    setup_rerun_if_changed();
    
    // Build server eBPF program
    let kern_dir = workspace_root.join("kern").join("server");
    if let Err(e) = build_ebpf_program(&kern_dir, "spak.server") {
        if kern_dir.exists() {
            eprintln!("Error building server eBPF: {}", e);
            std::process::exit(1);
        } else {
            println!("cargo:warning=Server eBPF directory not found, skipping");
        }
    }
}
