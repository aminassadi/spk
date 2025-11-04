use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn init_submodules(workspace_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:warning=Initializing git submodules...");
    
    let output = Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .current_dir(workspace_root)
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to initialize submodules: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Git submodule initialization failed".into());
    }
    
    println!("cargo:warning=Git submodules initialized successfully");
    Ok(())
}

pub fn build_ebpf_program(
    kern_dir: &Path,
    program_name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    
    if !kern_dir.exists() {
        return Err(format!("eBPF directory not found: {}", kern_dir.display()).into());
    }
    
    println!("cargo:warning=Building eBPF program: {}...", program_name);
    
    // Clean 
    let output = Command::new("make")
        .arg("-C")
        .arg(kern_dir)
        .arg("clean")
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such file or directory") && !stderr.contains("No rule to make target") {
            eprintln!("Warning: Clean had issues: {}", stderr);
        }
    }
    
    // Build
    let output = Command::new("make")
        .arg("-C")
        .arg(kern_dir)
        .output()?;
    
    if !output.status.success() {
        eprintln!("Failed to build eBPF program: {}", String::from_utf8_lossy(&output.stderr));
        return Err("eBPF build failed".into());
    }
    
    let output_dir = kern_dir.parent()
        .expect("kern_dir should have parent")
        .join(".output");
    let ebpf_object = output_dir.join(format!("{}.bpf.o", program_name));
    
    if !ebpf_object.exists() {
        return Err(format!("eBPF object not found: {}", ebpf_object.display()).into());
    }
    
    println!("cargo:warning=eBPF program {} built successfully!", program_name);
    Ok(ebpf_object)
}

pub fn setup_rerun_if_changed() {
    println!("cargo:rerun-if-changed=../kern/");
    println!("cargo:rerun-if-changed=../libbpf/");
    println!("cargo:rerun-if-changed=../.gitmodules");
    println!("cargo:rerun-if-changed=../build_common.rs");
}

pub fn get_workspace_root() -> PathBuf {
    // build.rs runs in the package directory, so go up one level to workspace root
    let current_dir = env::current_dir().expect("Failed to get current directory");
    current_dir.parent()
        .expect("Failed to get parent directory (should be workspace root)")
        .to_path_buf()
}
