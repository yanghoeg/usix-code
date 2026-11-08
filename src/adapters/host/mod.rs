pub mod linux;
pub mod termux;

use crate::ports::{Backend, BundledSkill, Host};
use anyhow::{ensure, Context, Result};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Only this composition boundary selects an operating-system adapter.
pub fn current() -> Result<Box<dyn Host>> {
    if cfg!(target_os = "android") {
        Ok(Box::new(termux::Termux))
    } else if cfg!(target_os = "linux") {
        Ok(Box::new(linux::Linux))
    } else {
        anyhow::bail!("this OS needs a Host adapter; supported hosts are Linux and Android Termux")
    }
}

pub fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into())).join(".usix")
}

/// Total physical memory from the kernel; both Linux and Android expose /proc/meminfo.
pub fn total_memory() -> Option<u64> {
    parse_mem_total(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

fn parse_mem_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

pub fn has_cmd(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", "command -v \"$1\" >/dev/null 2>&1", "usix-code", name])
        .status()
        .is_ok_and(|s| s.success())
}

pub fn install(script: &str, backend: Backend) -> Result<()> {
    let mut child = Command::new("sh")
        .args(["-s", "--", backend.name()])
        .arg(state_dir().join("backends"))
        .stdin(Stdio::piped())
        .spawn()
        .context("start backend installer")?;
    child
        .stdin
        .take()
        .context("installer stdin")?
        .write_all(script.as_bytes())?;
    ensure!(
        child.wait()?.success(),
        "{} installation failed; see the installer output above",
        backend.name()
    );
    Ok(())
}

pub const LOCAL_SKILL: BundledSkill = BundledSkill {
    filename: "local_work.md",
    text: include_str!("../../../skills/local_work.md"),
    legacy: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ApprovalClass;

    #[test]
    fn host_capabilities_are_separate_and_mutations_remain_gated() {
        let workspace = std::env::current_dir().unwrap();
        let local = linux::Linux.tools(&workspace);
        let phone = termux::Termux.tools(&workspace);
        for name in [
            "read_file",
            "list_dir",
            "shell",
            "write_file",
            "task_create",
            "task_list",
            "task_cancel",
        ] {
            assert!(local.iter().any(|t| t.name() == name));
            assert!(phone.iter().any(|t| t.name() == name));
        }
        for name in [
            "sms_list",
            "sms_send",
            "battery",
            "ui_dump",
            "email_open",
            "notif_list",
        ] {
            assert!(
                !local.iter().any(|t| t.name() == name),
                "Linux exposed {name}"
            );
            assert!(
                phone.iter().any(|t| t.name() == name),
                "Termux missing {name}"
            );
        }
        for tools in [&local, &phone] {
            for name in ["shell", "write_file", "task_create", "task_cancel"] {
                assert!(
                    tools.iter().find(|t| t.name() == name).unwrap().approval()
                        == ApprovalClass::Mutating
                );
            }
        }
    }

    #[test]
    fn parses_mem_total_in_bytes() {
        let meminfo = "MemTotal:       11381260 kB\nMemFree:          253724 kB\n";
        assert_eq!(parse_mem_total(meminfo), Some(11381260 * 1024));
        assert_eq!(parse_mem_total("MemFree: 1 kB\n"), None);
        assert_eq!(parse_mem_total("MemTotal: lots kB\n"), None);
    }

    #[test]
    fn both_host_catalogs_fit_the_default_prompt_budget() {
        let workspace = std::path::Path::new("/project");
        for host in [&linux::Linux as &dyn Host, &termux::Termux as &dyn Host] {
            let registry = crate::domain::registry::Registry::new(host.tools(workspace));
            let limit = crate::domain::context::Budget::default().prompt_tokens();
            let cost = |guidance: String| {
                crate::domain::context::prompt_cost(
                    &[
                        serde_json::json!({"role":"system","content":format!("{}{guidance}", crate::domain::agent::SYSTEM_PROMPT)}),
                        serde_json::json!({"role":"user","content":"Read README.md"}),
                    ],
                    &registry.schemas(),
                )
            };
            // The real policy must leave room for tool results.
            let base = cost(String::new());
            assert!(base + 1500 < limit,
                "{} catalog costs {base} estimated tokens; no room for instructions and tool results", host.name());
            // Any single bundled skill must still fit; context::fit shortens long tool results.
            for source in host.bundled_skills() {
                let skill = crate::domain::skills::parse(source.text).unwrap();
                let with_skill = cost(crate::domain::skills::guidance(&[&skill]));
                assert!(
                    with_skill + 768 < limit,
                    "{} with skill {} costs {with_skill} estimated tokens",
                    host.name(),
                    skill.name
                );
            }
        }
    }
}
