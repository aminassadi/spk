use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("package directory should have a parent")
        .to_path_buf();

    emit_rerun_directives();

    if let Err(e) = build_ebpf_artifacts(&workspace_root) {
        eprintln!("Error building eBPF programs: {}", e);
        std::process::exit(1);
    }
}

fn emit_rerun_directives() {
    println!("cargo:rerun-if-changed=../kern");
    println!("cargo:rerun-if-changed=../libbpf");
    println!("cargo:rerun-if-changed=../.gitmodules");
    println!("cargo:rerun-if-changed=../build.rs");
}

fn init_submodules(workspace_root: &Path) -> Result<(), String> {
    let status = Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .current_dir(workspace_root)
        .status()
        .map_err(|e| format!("failed to execute git: {}", e))?;

    if !status.success() {
        return Err("git submodule update failed".into());
    }

    Ok(())
}

fn build_ebpf_artifacts(workspace_root: &Path) -> Result<(), String> {
    let kern_dir = workspace_root.join("kern");
    if !kern_dir.exists() {
        return Err(format!("kern directory not found: {}", kern_dir.display()));
    }

    let output_dir = kern_dir.join(".output");
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir)
            .map_err(|e| format!("failed to create {}: {}", output_dir.display(), e))?;
    }

    let lock_path = output_dir.join("build.lock");
    let _lock = BuildLock::acquire(&lock_path)?;

    init_submodules(workspace_root)?;

    let make_output = Command::new("make")
        .arg("-C")
        .arg(&kern_dir)
        .output()
        .map_err(|e| format!("failed to run make: {}", e))?;

    if !make_output.status.success() {
        let stderr = String::from_utf8_lossy(&make_output.stderr);
        let stdout = String::from_utf8_lossy(&make_output.stdout);
        let mut msg = format!("make failed: {}", stderr.trim());
        if !stdout.trim().is_empty() {
            msg.push_str(&format!("; stdout: {}", stdout.trim()));
        }
        return Err(msg);
    }

    ensure_object_exists(&output_dir, "spak.client.bpf.o")?;
    ensure_object_exists(&output_dir, "spak.server.bpf.o")?;

    Ok(())
}

fn ensure_object_exists(output_dir: &Path, name: &str) -> Result<(), String> {
    let path = output_dir.join(name);
    if !path.exists() {
        return Err(format!("expected eBPF object missing: {}", path.display()));
    }
    Ok(())
}

struct BuildLock {
    path: PathBuf,
}

impl BuildLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let pid = process::id();
        loop {
            match fs::create_dir(path) {
                Ok(_) => {
                    let pid_path = path.join("pid");
                    if let Err(e) = fs::write(&pid_path, format!("{}", pid)) {
                        let _ = fs::remove_dir_all(path);
                        return Err(format!(
                            "failed to record lock owner {}: {}",
                            pid_path.display(),
                            e
                        ));
                    }
                    return Ok(BuildLock {
                        path: path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if BuildLock::is_stale(path)? {
                        fs::remove_dir_all(path)
                            .map_err(|err| format!("failed to clear stale lock: {}", err))?;
                        continue;
                    }
                    sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(format!(
                        "failed to create lock dir {}: {}",
                        path.display(),
                        e
                    ))
                }
            }
        }
    }

    fn is_stale(path: &Path) -> Result<bool, String> {
        let pid_path = path.join("pid");
        match fs::read_to_string(&pid_path) {
            Ok(contents) => {
                let contents = contents.trim();
                match contents.parse::<u32>() {
                    Ok(owner_pid) => {
                        if owner_pid == process::id() {
                            return Ok(true);
                        }
                        let proc_path = Path::new("/proc").join(owner_pid.to_string());
                        Ok(!proc_path.exists())
                    }
                    Err(_) => Ok(true),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(format!(
                "failed to inspect lock owner {}: {}",
                pid_path.display(),
                e
            )),
        }
    }
}

impl Drop for BuildLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
