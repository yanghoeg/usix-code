// ADAPTER — termux-api 명령 실행 헬퍼.
use anyhow::{anyhow, Result};
use std::io::Write;
use std::process::{Command, Output, Stdio};

// Termux:API 브리지가 무응답이면 termux-* 가 무한 hang → `timeout` 으로 상한을 둔다.
const TIMEOUT_SECS: &str = "8";

/// termux-* 바이너리를 실행하고 stdout(trim)을 돌려준다.
pub fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new("timeout")
        .arg(TIMEOUT_SECS)
        .arg(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow!("{cmd} failed to run (termux-api installed?): {e}"))?;
    finish(cmd, out)
}

/// 텍스트를 인자 대신 stdin 으로 넘긴다 — termux-* 셸 래퍼의 getopts·echo 해석을 거치지 않게.
pub fn run_with_stdin(cmd: &str, args: &[&str], input: &str) -> Result<String> {
    let mut child = Command::new("timeout")
        .arg(TIMEOUT_SECS)
        .arg(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("{cmd} failed to run (termux-api installed?): {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    finish(cmd, out)
}

fn finish(cmd: &str, out: Output) -> Result<String> {
    if out.status.code() == Some(124) {
        return Err(anyhow!(
            "{cmd} no response (>{TIMEOUT_SECS}s) — check the Termux:API app is installed, running, and permitted."
        ));
    }
    if !out.status.success() {
        return Err(anyhow!(
            "{cmd} error: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
