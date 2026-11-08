// TOOLS — 코드 검색(ReadOnly). grep(정규식 내용 검색)·glob(경로 패턴). 셸 승인 없이
// 저장소를 훑게 해 소형 모델이 shell 로 grep/find 를 조립하다 틀리는 일을 줄인다.
use crate::ports::{ApprovalClass, Tool};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

// 빌드 산출물·의존성·VCS 는 검색 가치가 낮고 크다.
const SKIP_DIRS: &[&str] = &["target", "node_modules", "__pycache__"];
// 거대 저장소에서 한 번의 호출이 폰을 오래 붙잡지 않도록 방문 파일 수 상한.
const MAX_FILES_VISITED: usize = 20_000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_MATCHES: usize = 200;
const MAX_GLOB_RESULTS: usize = 500;
const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_LINE_CHARS: usize = 300;

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("필수 인자 누락: {key}"))
}

/// root 아래 일반 파일을 정렬 순서로 모은다. 숨김·SKIP_DIRS 는 건너뛰고 심볼릭 링크는
/// 따라가지 않는다. root 가 파일이면 그 하나만.
fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let meta = std::fs::symlink_metadata(root)
        .map_err(|e| anyhow!("{} 읽기 실패: {e}", root.display()))?;
    if meta.is_file() {
        return Ok(vec![root.to_owned()]);
    }
    let mut files = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        // 스택이라 역순으로 넣어야 정렬 순서로 방문한다.
        for entry in entries.into_iter().rev() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
        if files.len() >= MAX_FILES_VISITED {
            break;
        }
    }
    files.sort();
    files.truncate(MAX_FILES_VISITED);
    Ok(files)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// 한 경로 조각에 대한 `*`·`?` 매칭.
fn segment_match(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            segment_match(&pattern[1..], text)
                || (!text.is_empty() && segment_match(pattern, &text[1..]))
        }
        (Some('?'), Some(_)) => segment_match(&pattern[1..], &text[1..]),
        (Some(p), Some(t)) if p == t => segment_match(&pattern[1..], &text[1..]),
        _ => false,
    }
}

/// `/` 로 나눈 조각 단위 매칭. `**` 는 0개 이상의 조각과 맞는다.
fn glob_match(pattern: &str, path: &str) -> bool {
    fn parts(pattern: &[&str], path: &[&str]) -> bool {
        match pattern.first() {
            None => path.is_empty(),
            Some(&"**") => {
                parts(&pattern[1..], path) || (!path.is_empty() && parts(pattern, &path[1..]))
            }
            Some(segment) => {
                !path.is_empty()
                    && segment_match(
                        &segment.chars().collect::<Vec<_>>(),
                        &path[0].chars().collect::<Vec<_>>(),
                    )
                    && parts(&pattern[1..], &path[1..])
            }
        }
    }
    let pattern: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts(&pattern, &path)
}

/// `/` 가 없는 패턴은 파일 이름에만 적용한다(`*.rs` 가 하위 폴더에서도 걸리게).
fn path_filter(pattern: &str, rel: &str) -> bool {
    if pattern.contains('/') {
        glob_match(pattern, rel)
    } else {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        glob_match(pattern, name)
    }
}

/// 검색용 텍스트 — 크거나 바이너리(앞 8 KiB 에 NUL)거나 UTF-8 이 아니면 None.
fn searchable(path: &Path) -> Option<String> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub struct Grep;
impl Tool for Grep {
    fn name(&self) -> &str {
        "grep"
    }
    fn description(&self) -> &str {
        "Search file contents by regex; returns path:line: text. Skips .git, target, node_modules."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Regex (Rust syntax)" },
                "path": { "type": "string", "description": "Folder or file (default workspace)" },
                "glob": { "type": "string", "description": "File filter, e.g. *.rs or src/**/*.py" },
                "ignore_case": { "type": "boolean", "description": "Case-insensitive" }
            },
            "required": ["pattern"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::ReadOnly
    }
    fn run(&self, args: &Value) -> Result<String> {
        let pattern = required_str(args, "pattern")?;
        let root = PathBuf::from(args.get("path").and_then(Value::as_str).unwrap_or("."));
        let filter = args.get("glob").and_then(Value::as_str);
        let regex = regex::RegexBuilder::new(pattern)
            .case_insensitive(
                args.get("ignore_case")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )
            .size_limit(1 << 20)
            .build()
            .map_err(|e| anyhow!("잘못된 정규식: {e}"))?;
        let mut out = String::new();
        let mut matches = 0;
        'files: for file in walk(&root)? {
            let rel = relative(&root, &file);
            if filter.is_some_and(|f| !path_filter(f, &rel)) {
                continue;
            }
            let Some(text) = searchable(&file) else {
                continue;
            };
            for (number, line) in text.lines().enumerate() {
                if !regex.is_match(line) {
                    continue;
                }
                let shown: String = line.chars().take(MAX_LINE_CHARS).collect();
                let entry = format!("{rel}:{}: {}\n", number + 1, shown.trim_end());
                if matches >= MAX_MATCHES || out.len() + entry.len() > MAX_OUTPUT_BYTES {
                    out.push_str("…(결과 잘림 — pattern·path·glob 을 좁혀라)");
                    break 'files;
                }
                out.push_str(&entry);
                matches += 1;
            }
        }
        Ok(if out.is_empty() {
            "(일치 없음)".into()
        } else {
            out.trim_end().to_string()
        })
    }
}

pub struct Glob;
impl Tool for Glob {
    fn name(&self) -> &str {
        "glob"
    }
    fn description(&self) -> &str {
        "List files matching a path pattern (*, ?, **). Skips .git, target, node_modules."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Pattern, e.g. **/*.rs" },
                "path": { "type": "string", "description": "Base folder (default workspace)" }
            },
            "required": ["pattern"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::ReadOnly
    }
    fn run(&self, args: &Value) -> Result<String> {
        let pattern = required_str(args, "pattern")?;
        let root = PathBuf::from(args.get("path").and_then(Value::as_str).unwrap_or("."));
        let found: Vec<String> = walk(&root)?
            .iter()
            .map(|f| relative(&root, f))
            .filter(|rel| path_filter(pattern, rel))
            .collect();
        if found.is_empty() {
            return Ok("(일치 없음)".into());
        }
        let total = found.len();
        let mut out = found
            .into_iter()
            .take(MAX_GLOB_RESULTS)
            .collect::<Vec<_>>()
            .join("\n");
        if total > MAX_GLOB_RESULTS {
            out.push_str(&format!(
                "\n…(총 {total}개 중 {MAX_GLOB_RESULTS}개만 표시 — 패턴을 좁혀라)"
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_segments_and_double_star() {
        assert!(glob_match("src/**/*.rs", "src/a/b/c.rs"));
        assert!(glob_match("src/**/*.rs", "src/c.rs"));
        assert!(!glob_match("src/*.rs", "src/a/c.rs"));
        assert!(glob_match("?.md", "a.md"));
        assert!(path_filter("*.rs", "deep/dir/x.rs"));
        assert!(!path_filter("*.rs", "deep/dir/x.rsx"));
    }

    #[test]
    fn grep_and_glob_skip_vcs_build_and_binary_files() {
        let root = std::env::temp_dir().join(format!("usix_search_test_{}", std::process::id()));
        for dir in ["src", ".git", "target"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("src/a.rs"), "fn alpha() {}\nlet NEEDLE = 1;\n").unwrap();
        std::fs::write(root.join(".git/config"), "NEEDLE").unwrap();
        std::fs::write(root.join("target/out.rs"), "NEEDLE").unwrap();
        std::fs::write(root.join("bin.dat"), b"NEEDLE\0\x01").unwrap();
        let path = root.to_string_lossy();

        let out = Grep
            .run(&json!({ "pattern": "needle", "path": path, "ignore_case": true }))
            .unwrap();
        assert_eq!(out, "src/a.rs:2: let NEEDLE = 1;");
        let out = Grep
            .run(&json!({ "pattern": "NEEDLE", "path": path, "glob": "*.md" }))
            .unwrap();
        assert_eq!(out, "(일치 없음)");
        assert!(Grep.run(&json!({ "pattern": "(", "path": path })).is_err());

        let out = Glob
            .run(&json!({ "pattern": "**/*.rs", "path": path }))
            .unwrap();
        assert_eq!(out, "src/a.rs");
        let _ = std::fs::remove_dir_all(&root);
    }
}
