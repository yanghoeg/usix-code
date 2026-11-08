// TOOLS — 셸/파일. usix `usix-tools`(bash/file_ops)를 폰 규모로 축약.
// shell·write_file·edit_file 은 Mutating(승인), read_file·list_dir 은 ReadOnly(자동).
use crate::ports::{ApprovalClass, Tool};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("필수 인자 누락: {key}"))
}

// 긴 명령이 hang 하지 않도록 상한(초). termux.rs 처럼 `timeout` 바이너리로 감싼다.
const SHELL_TIMEOUT_SECS: &str = "120";
// 모델 컨텍스트 보호 — 각 파이프에서 이 바이트까지만 보관하고 나머지는 버린다.
const MAX_OUTPUT: usize = 8000;
// 승인과 무관한 방어선 — 회복 불가 파괴 명령은 승인해도 실행하지 않는다.
// 소문자·공백 정규화 후 부분문자열 비교. 우회는 쉽다(`find / -delete`, `curl x|sh` 등) —
// 이건 흔한 사고를 막는 걸림돌일 뿐 보안 경계가 아니다. 실제 방어선은 승인 프롬프트에 표시되는
// 명령 원문을 사람이 읽고 y/N 하는 것이다.
const BLOCKED: &[&str] = &[
    ":(){:|:&};:",
    ":(){ :|:& };:",
    "rm -rf /",
    "rm -fr /",
    "rm -rf ~",
    "rm -fr ~",
    "rm -rf $home",
    "mkfs.",
    "wipefs",
    "of=/dev/",
    "> /dev/",
];

/// 회복 불가 파괴 명령인가 — 부분문자열 목록 **또는** AST 해석(usix-shellast).
/// AST 는 인용 분할(`r"m" -rf /`)·플래그 분리(`rm -r -f /`) 같은 변형을 잡고, 부분문자열은
/// AST 가 못 보는 경우(`bash -c 'rm -rf /'` 등)를 우연히 잡는다. usix 와 같은 OR 계약.
fn blocked(cmd: &str) -> Option<String> {
    let low = normalize(cmd);
    if let Some(p) = BLOCKED.iter().find(|p| low.contains(**p)) {
        return Some((*p).to_string());
    }
    usix_shellast::scan(cmd)
        .has_catastrophic_recursive_delete()
        .then(|| "recursive delete of / or ~".to_string())
}

/// BLOCKED 대조용 — 소문자 + 연속 공백을 한 칸으로(`rm   -rf   /` 같은 변형 흡수).
fn normalize(cmd: &str) -> String {
    cmd.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_OUTPUT {
        return s.trim_end().to_string();
    }
    let head: String = s.chars().take(MAX_OUTPUT).collect();
    format!("{head}\n…(출력 잘림)")
}

struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

/// 자식 프로세스가 대량 출력으로 파이프를 막지 않도록 읽기는 끝까지 하되 저장량만 제한한다.
fn capture_limited<R: Read>(mut reader: R) -> std::io::Result<Captured> {
    let mut bytes = Vec::with_capacity(MAX_OUTPUT);
    let mut truncated = false;
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let remaining = MAX_OUTPUT.saturating_sub(bytes.len());
        if remaining == 0 {
            truncated = true;
        } else {
            let keep = remaining.min(n);
            bytes.extend_from_slice(&buf[..keep]);
            if keep < n {
                truncated = true;
            }
        }
    }
    Ok(Captured { bytes, truncated })
}

pub struct Shell;
impl Tool for Shell {
    fn name(&self) -> &str {
        "shell"
    }
    fn description(&self) -> &str {
        "Run a bash command; returns output and exit code. No stdin. Background processes are killed when it ends (use setsid cmd >log 2>&1 & to keep one)."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "Bash command" },
                "cwd": { "type": "string", "description": "Working directory (default workspace)" }
            },
            "required": ["command"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn approval_arguments(&self, args: &Value) -> Value {
        let mut shown = args.clone();
        let opaque = args
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| usix_shellast::scan(cmd).uncertain);
        if let (true, Some(object)) = (opaque, shown.as_object_mut()) {
            object.insert(
                "warning".into(),
                json!("⚠ 구조 해석 불가(불투명 인자) — 명령 원문을 직접 확인하라"),
            );
        }
        shown
    }
    fn run(&self, args: &Value) -> Result<String> {
        let cmd = required_str(args, "command")?;
        if let Some(p) = blocked(cmd) {
            return Err(anyhow!("차단됨: 파괴적 명령 '{p}' 은 실행하지 않는다."));
        }
        let mut c = Command::new("timeout");
        c.arg(SHELL_TIMEOUT_SECS).arg("bash").arg("-c").arg(cmd);
        if let Some(d) = args.get("cwd").and_then(|v| v.as_str()) {
            c.current_dir(d);
        }
        // 자체 프로세스 그룹: 끝난 뒤 남은 백그라운드 자식이 파이프를 쥐고 reader 를 영구
        // 대기시키지 않도록 그룹째 정리한다. stdin 이 없어 대화형 명령은 즉시 EOF.
        let mut child = c
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("셸 실행 실패: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("셸 stdout 파이프를 열 수 없음"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("셸 stderr 파이프를 열 수 없음"))?;
        let stdout_reader = thread::spawn(move || capture_limited(stdout));
        let stderr_reader = thread::spawn(move || capture_limited(stderr));
        let status = child.wait().map_err(|e| anyhow!("셸 대기 실패: {e}"));
        if let Ok(pgid) = i32::try_from(child.id()) {
            // SAFETY: kill(2) 은 메모리를 건드리지 않는다. 음수 pid = 우리가 만든 그룹.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        let status = status?;
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow!("셸 stdout reader 실패"))?
            .map_err(|e| anyhow!("셸 stdout 읽기 실패: {e}"))?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("셸 stderr reader 실패"))?
            .map_err(|e| anyhow!("셸 stderr 읽기 실패: {e}"))?;
        let code = status.code().unwrap_or(-1);
        if code == 124 {
            return Err(anyhow!("셸 시간 초과 (>{SHELL_TIMEOUT_SECS}s)"));
        }
        let mut s = String::from_utf8_lossy(&stdout.bytes).into_owned();
        let se = String::from_utf8_lossy(&stderr.bytes);
        if !se.trim().is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&se);
        }
        let s = truncate(&s);
        let s = if (stdout.truncated || stderr.truncated) && !s.ends_with("…(출력 잘림)") {
            format!("{s}\n…(출력 잘림)")
        } else {
            s
        };
        Ok(if s.trim().is_empty() {
            format!("(exit {code})")
        } else if code != 0 {
            format!("(exit {code})\n{s}")
        } else {
            s
        })
    }
}

const MAX_READ_LINES: usize = 1500;
// read_file 은 승인 없이 자동 실행되므로 크기 상한이 필요하다 — 전체를 메모리에 올린 뒤
// 줄을 자르는 구조라, 모델이 거대·바이너리 파일을 찍으면 폰 lmkd 에 죽는다.
const MAX_READ_BYTES: u64 = 2 * 1024 * 1024;

fn render_lines(c: &str, offset: usize, limit: usize) -> String {
    let lines: Vec<&str> = c.lines().collect();
    let total = lines.len();
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let body = lines[start..end].join("\n");
    if start > 0 || end < total {
        format!(
            "[{}-{}/{} 줄 — offset/limit 으로 더 읽기]\n{body}",
            start + 1,
            end,
            total
        )
    } else {
        body
    }
}

/// 일반 파일만, 상한까지만 읽는다 — /dev/zero·FIFO 처럼 len 이 0 인 특수 파일이
/// 메모리를 무한히 잡거나 영구 대기하지 않게 한다. read_file·edit_file·grep 공용.
pub(crate) fn read_text(path: &str) -> Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| anyhow!("{path} 읽기 실패: {e}"))?;
    if !meta.is_file() {
        return Err(anyhow!("{path} 는 일반 파일이 아님"));
    }
    let too_big = || {
        anyhow!(
            "{path} 는 너무 큼 (> {} KiB) — shell 도구로 head/sed/grep 을 써서 필요한 부분만 읽어라.",
            MAX_READ_BYTES / 1024
        )
    };
    if meta.len() > MAX_READ_BYTES {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_READ_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| anyhow!("{path} 읽기 실패: {e}"))?;
    if bytes.len() as u64 > MAX_READ_BYTES {
        return Err(too_big());
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("{path} 는 UTF-8 텍스트가 아님"))
}

pub struct ReadFile;
impl Tool for ReadFile {
    fn name(&self) -> &str {
        "read_file"
    }
    fn description(&self) -> &str {
        "Read a text file. Use offset/limit (lines) for large files."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path" },
                "offset": { "type": "integer", "description": "First line (0-based)" },
                "limit": { "type": "integer", "description": "Lines to read (max 1500)" }
            },
            "required": ["path"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::ReadOnly
    }
    fn run(&self, args: &Value) -> Result<String> {
        let path = required_str(args, "path")?;
        let offset = args
            .get("offset")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(usize::MAX as u64) as usize)
            .unwrap_or(0);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(usize::MAX as u64) as usize)
            .unwrap_or(MAX_READ_LINES)
            .min(MAX_READ_LINES);
        let content = read_text(path)?;
        Ok(render_lines(&content, offset, limit))
    }
}

pub struct WriteFile;
impl Tool for WriteFile {
    fn name(&self) -> &str {
        "write_file"
    }
    fn description(&self) -> &str {
        "Write a whole text file (overwrites). Prefer edit_file for changes."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path" },
                "content": { "type": "string", "description": "File content" }
            },
            "required": ["path", "content"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn run(&self, args: &Value) -> Result<String> {
        let path = required_str(args, "path")?;
        let content = required_str(args, "content")?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(path, content).map_err(|e| anyhow!("{path} 쓰기 실패: {e}"))?;
        Ok(format!("{} 바이트 기록 → {path}", content.len()))
    }
}

pub struct EditFile;
impl Tool for EditFile {
    fn name(&self) -> &str {
        "edit_file"
    }
    fn description(&self) -> &str {
        "Replace old_string with new_string in a file. old_string must match exactly once unless replace_all."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path" },
                "old_string": { "type": "string", "description": "Exact existing text" },
                "new_string": { "type": "string", "description": "Replacement text" },
                "replace_all": { "type": "boolean", "description": "Replace every match" }
            },
            "required": ["path", "old_string", "new_string"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn run(&self, args: &Value) -> Result<String> {
        let path = required_str(args, "path")?;
        let old = required_str(args, "old_string")?;
        let new = required_str(args, "new_string")?;
        let all = args
            .get("replace_all")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if old.is_empty() {
            return Err(anyhow!("old_string 이 비어 있음"));
        }
        let content = read_text(path)?;
        let count = content.matches(old).count();
        if count == 0 {
            return Err(anyhow!(
                "{path} 에서 old_string 을 찾지 못함 — read_file 로 정확한 원문을 확인하라."
            ));
        }
        if count > 1 && !all {
            return Err(anyhow!(
                "{count}곳 일치 — 문맥을 넓혀 한 곳만 맞추거나 replace_all=true 로 호출하라."
            ));
        }
        let updated = if all {
            content.replace(old, new)
        } else {
            content.replacen(old, new, 1)
        };
        // 같은 폴더의 임시 파일에 쓰고 rename — 중간 실패가 원본을 반쯤 덮지 않게.
        let target = std::path::Path::new(path);
        let tmp = target.with_file_name(format!(
            ".{}.usix-edit.{}",
            target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            std::process::id()
        ));
        let result = std::fs::write(&tmp, &updated)
            .and_then(|_| std::fs::set_permissions(&tmp, std::fs::metadata(target)?.permissions()))
            .and_then(|_| std::fs::rename(&tmp, target));
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!("{path} 쓰기 실패: {e}"));
        }
        let preview = |prefix: char, text: &str| {
            text.lines()
                .take(5)
                .map(|l| format!("{prefix} {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(format!(
            "{count}곳 수정 → {path}\n{}\n{}",
            preview('-', old),
            preview('+', new)
        ))
    }
}

pub struct ListDir;
const MAX_DIR_ENTRIES: usize = 500;
const MAX_DIR_OUTPUT_BYTES: usize = 16 * 1024;

impl Tool for ListDir {
    fn name(&self) -> &str {
        "list_dir"
    }
    fn description(&self) -> &str {
        "List a directory (folders end with /)."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Directory (default workspace)" }
            }
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::ReadOnly
    }
    fn run(&self, args: &Value) -> Result<String> {
        let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let mut entries = BTreeSet::new();
        let mut total = 0usize;
        for e in std::fs::read_dir(path).map_err(|e| anyhow!("{path} 나열 실패: {e}"))? {
            let e = e?;
            total = total.saturating_add(1);
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            entries.insert(if is_dir { format!("{name}/") } else { name });
            if entries.len() > MAX_DIR_ENTRIES {
                let last = entries.iter().next_back().cloned();
                if let Some(last) = last {
                    entries.remove(&last);
                }
            }
        }
        if total == 0 {
            return Ok("(빈 디렉토리)".into());
        }

        let mut out = String::new();
        let mut shown = 0;
        for name in entries {
            let separator = if out.is_empty() { 0 } else { 1 };
            if out.len() + separator + name.len() > MAX_DIR_OUTPUT_BYTES {
                break;
            }
            if separator != 0 {
                out.push('\n');
            }
            out.push_str(&name);
            shown += 1;
        }
        if shown < total {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!(
                "…(총 {total}개 중 {shown}개만 표시 — 더 좁은 경로를 지정하세요)"
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_blocks_destructive() {
        for bad in [
            ":(){:|:&};:",
            "rm -rf /",
            "sudo rm -fr ~",
            "RM  -rf   /*",
            "rm\t-rf\t/",
            "r\"m\" -rf /",
            "rm -r -f /",
            "r\\m -rf ~",
            "rm --recursive --force /etc",
        ] {
            let r = Shell.run(&json!({ "command": bad }));
            assert!(r.is_err(), "파괴 명령이 통과됨: {bad}");
        }
    }

    #[test]
    fn read_rejects_oversized() {
        let dir = std::env::temp_dir().join(format!("usix_shell_big_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.txt");
        std::fs::write(&path, vec![b'x'; (MAX_READ_BYTES + 1) as usize]).unwrap();
        let e = ReadFile
            .run(&json!({ "path": path.to_string_lossy() }))
            .unwrap_err()
            .to_string();
        assert!(e.contains("너무 큼"), "크기 상한이 안 걸림: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_returns_despite_background_children_and_has_no_stdin() {
        let start = std::time::Instant::now();
        let out = Shell
            .run(&json!({ "command": "sleep 30 & read x; echo eof=$?" }))
            .unwrap();
        assert!(out.contains("eof=1"), "stdin 이 닫혀 있지 않음: {out}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "백그라운드 자식 때문에 대기함"
        );
    }

    #[test]
    fn read_rejects_special_files() {
        let e = ReadFile
            .run(&json!({ "path": "/dev/zero" }))
            .unwrap_err()
            .to_string();
        assert!(e.contains("일반 파일이 아님"), "{e}");
    }

    #[test]
    fn edit_requires_unique_match_unless_replace_all() {
        let dir = std::env::temp_dir().join(format!("usix_edit_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.txt");
        let p = path.to_string_lossy().to_string();
        std::fs::write(&path, "a x\nb x\n").unwrap();
        let e = EditFile
            .run(&json!({ "path": p, "old_string": "x", "new_string": "y" }))
            .unwrap_err()
            .to_string();
        assert!(e.contains("2곳 일치"), "{e}");
        assert!(EditFile
            .run(&json!({ "path": p, "old_string": "zz", "new_string": "y" }))
            .is_err());
        EditFile
            .run(&json!({ "path": p, "old_string": "b x", "new_string": "b y" }))
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a x\nb y\n");
        EditFile
            .run(&json!({ "path": p, "old_string": "a", "new_string": "c", "replace_all": true }))
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "c x\nb y\n");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "임시 파일이 남음"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_runs_echo() {
        let out = Shell.run(&json!({ "command": "echo hi_shell" })).unwrap();
        assert!(out.contains("hi_shell"), "echo 출력 누락: {out}");
    }

    #[test]
    fn shell_output_is_bounded() {
        let out = Shell
            .run(&json!({ "command": "printf '%20000s' x" }))
            .unwrap();
        assert!(out.contains("출력 잘림"), "출력 잘림 표시 누락");
        assert!(out.chars().count() < MAX_OUTPUT + 32, "출력이 너무 큼");
    }

    #[test]
    fn read_partial_shows_header() {
        let body = "a\nb\nc\nd\ne";
        let r = render_lines(body, 1, 2);
        assert!(r.starts_with("[2-3/5 줄"), "부분 읽기 헤더 누락: {r}");
        assert!(r.contains("b\nc"), "본문 범위 오류: {r}");
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = std::env::temp_dir().join(format!("usix_shell_test_{}", std::process::id()));
        let path = dir.join("nested").join("f.txt");
        let p = path.to_string_lossy().to_string();
        WriteFile
            .run(&json!({ "path": p, "content": "hello\nworld" }))
            .unwrap();
        let out = ReadFile.run(&json!({ "path": p })).unwrap();
        assert_eq!(out, "hello\nworld");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_dir_bounds_entries_and_memory() {
        let dir = std::env::temp_dir().join(format!("usix_list_dir_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..=MAX_DIR_ENTRIES {
            std::fs::write(dir.join(format!("entry_{i:03}")), b"").unwrap();
        }
        let out = ListDir
            .run(&json!({ "path": dir.to_string_lossy() }))
            .unwrap();
        assert!(
            out.contains("총 501개 중 500개만"),
            "항목 상한 표시 누락: {out}"
        );
        assert!(out.contains("entry_000"), "정렬된 앞 항목 누락");
        assert!(!out.contains("entry_500"), "상한 밖 항목이 노출됨");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
