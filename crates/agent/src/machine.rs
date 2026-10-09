//! What the agent reports about its machine at connect: cgroup memory and CPU limits, `/dev/shm` and the install type.
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::settings::{Env, env_value};

fn read(file: &Path) -> Option<String> {
    std::fs::read_to_string(file).ok().map(|text| text.trim().to_string())
}

fn memory_limit(cgroup: &Path, total: u64) -> Option<u64> {
    let value = read(&cgroup.join("memory.max")).or_else(|| read(&cgroup.join("memory").join("memory.limit_in_bytes")))?;
    let bytes: f64 = value.parse().ok()?;
    // cgroup v1 reports "no limit" as a number near 2^63.
    (bytes > 0.0 && bytes < total as f64).then_some(bytes as u64)
}

fn cpu_quota(cgroup: &Path) -> Option<u64> {
    let (quota, period): (f64, f64) = match read(&cgroup.join("cpu.max")) {
        Some(v2) => {
            let mut parts = v2.split_whitespace();
            (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?)
        }
        None => {
            let dir = ["cpu", "cpu,cpuacct"].iter().map(|dir| cgroup.join(dir)).find(|dir| read(&dir.join("cpu.cfs_quota_us")).is_some())?;
            (read(&dir.join("cpu.cfs_quota_us"))?.parse().ok()?, read(&dir.join("cpu.cfs_period_us"))?.parse().ok()?)
        }
    };
    (quota > 0.0 && period > 0.0).then(|| (quota / period).ceil() as u64)
}

fn shm_size(root: &Path) -> Option<u64> {
    let path = std::ffi::CString::new(root.join("dev").join("shm").to_string_lossy().as_bytes()).ok()?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs fills the struct it is given.
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return None;
    }
    Some(stats.f_blocks as u64 * stats.f_frsize as u64)
}

pub fn total_memory() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let (pages, size) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    (pages.max(0) as u64) * (size.max(0) as u64)
}

pub fn parallelism() -> u64 {
    std::thread::available_parallelism().map(|count| count.get() as u64).unwrap_or(1)
}

/// STATUSTICK_INSTALL when set; otherwise helm inside Kubernetes, docker inside a Docker container, else other.
pub fn install_type(install: Option<&str>, root: &Path, env: &Env) -> String {
    if let Some(install) = install {
        return install.to_string();
    }
    if !env_value(env, "KUBERNETES_SERVICE_HOST").unwrap_or("").trim().is_empty() {
        return "helm".to_string();
    }
    if root.join(".dockerenv").exists() {
        return "docker".to_string();
    }
    "other".to_string()
}

pub struct Probe {
    pub root: PathBuf,
    pub total_memory: u64,
    pub parallelism: u64,
    pub started_at: String,
}

/// The machine fields of the connect call.
pub fn read_machine(install: Option<&str>, env: &Env, probe: &Probe) -> Value {
    let cgroup = probe.root.join("sys").join("fs").join("cgroup");
    let limit = memory_limit(&cgroup, probe.total_memory);
    json!({
        "startedAt": probe.started_at,
        "installType": install_type(install, &probe.root, env),
        "memoryLimitBytes": limit.unwrap_or(probe.total_memory),
        "memoryLimited": limit.is_some(),
        "shmBytes": shm_size(&probe.root),
        "cpuCount": cpu_quota(&cgroup).unwrap_or(probe.parallelism),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cgroup_v2_limits_and_the_install_type() {
        let root = std::env::temp_dir().join(format!("agent-machine-{}", std::process::id()));
        let cgroup = root.join("sys/fs/cgroup");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("memory.max"), "536870912\n").unwrap();
        std::fs::write(cgroup.join("cpu.max"), "150000 100000\n").unwrap();
        std::fs::write(root.join(".dockerenv"), "").unwrap();
        let probe = Probe { root: root.clone(), total_memory: 8 << 30, parallelism: 8, started_at: "2026-10-03T08:00:00.000Z".into() };
        let machine = read_machine(None, &Vec::new(), &probe);
        assert_eq!(machine["memoryLimitBytes"], 536870912);
        assert_eq!(machine["memoryLimited"], true);
        assert_eq!(machine["cpuCount"], 2);
        assert_eq!(machine["installType"], "docker");
        std::fs::write(cgroup.join("memory.max"), "max\n").unwrap();
        std::fs::remove_file(cgroup.join("cpu.max")).unwrap();
        let env = vec![("KUBERNETES_SERVICE_HOST".to_string(), "10.0.0.1".to_string())];
        let machine = read_machine(None, &env, &probe);
        assert_eq!(machine["memoryLimitBytes"], 8u64 << 30);
        assert_eq!(machine["memoryLimited"], false);
        assert_eq!(machine["cpuCount"], 8);
        assert_eq!(machine["installType"], "helm");
        std::fs::remove_dir_all(root).unwrap();
    }
}
