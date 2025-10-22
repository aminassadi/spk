use std::env;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize and update git submodules
    println!("cargo:warning=Initializing git submodules...");
    
    let output = Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to initialize submodules: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Git submodule initialization failed".into());
    }
    
    println!("cargo:warning=Git submodules initialized successfully");
    
    // Tell Cargo to rebuild if these files change
    println!("cargo:rerun-if-changed=kern/spak.bpf.c");
    println!("cargo:rerun-if-changed=kern/Makefile");
    println!("cargo:rerun-if-changed=libbpf/");
    println!("cargo:rerun-if-changed=.gitmodules");
    
    // Get the current directory
    let current_dir = env::current_dir()?;
    let kern_dir = current_dir.join("kern");
    
    // Check if we're building for eBPF
    let target = env::var("TARGET")?;
    if target.contains("bpf") {
        println!("cargo:warning=Building for eBPF target, skipping userspace build");
        return Ok(());
    }
    
    // Build the eBPF program
    println!("cargo:warning=Building eBPF program...");
    
    let output = Command::new("make")
        .arg("-C")
        .arg(&kern_dir)
        .arg("clean")
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to clean eBPF build: {}", String::from_utf8_lossy(&output.stderr));
        return Err("eBPF clean failed".into());
    }
    
    let output = Command::new("make")
        .arg("-C")
        .arg(&kern_dir)
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to build eBPF program: {}", String::from_utf8_lossy(&output.stderr));
        return Err("eBPF build failed".into());
    }
    
    // Tell Cargo where to find the built eBPF object
    let ebpf_object = kern_dir.join(".output").join("spak.bpf.o");
    if ebpf_object.exists() {
        println!("cargo:rustc-link-search=native={}", kern_dir.join(".output").display());
        println!("cargo:rustc-link-lib=static=bpf");
    }
    
    // Set environment variables for the runtime
    println!("cargo:rustc-env=EBPF_OBJECT_PATH={}", ebpf_object.display());
    
    println!("cargo:warning=eBPF program built successfully!");
    Ok(())
}
