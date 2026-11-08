//! 오염 변수 수집 — 명령치환·`read` 로 채운 변수와 그걸 참조해 만든 변수.
//!
//! [`crate::pipe_flow`] 가 싱크 인자에서 이 변수를 참조하면 로컬 데이터 원천으로 본다. 흐름
//! 무감(flow-insensitive) — 스크립트 어디서든 오염되면 오염으로 본다.

use std::collections::BTreeSet;

use tree_sitter::Node;

use crate::pipe_flow::{collect_refs, Word};
use crate::{argument_literals, literal_of, text};

/// `read`·`mapfile` 의 값-취득 옵션 — 그 다음 워드는 변수 이름이 아니다.
const READ_VALUE_OPTS: &str = "dinNptu";
const MAPFILE_VALUE_OPTS: &str = "dnOsuCc";

/// 명령치환으로 채운 변수(대입·`for … in $(…)`), `read`·`mapfile` 대상, 그리고 그걸 참조해
/// 만든 변수(고정점까지 전파).
pub(crate) fn tainted_vars(root: Node, src: &[u8]) -> BTreeSet<String> {
    let mut taint = BTreeSet::new();
    let mut pending = Vec::new();
    collect_taint(root, src, &mut taint, &mut pending);
    loop {
        let before = taint.len();
        for (name, refs) in &pending {
            if refs.iter().any(|v| taint.contains(v)) {
                taint.insert(name.clone());
            }
        }
        if taint.len() == before {
            return taint;
        }
    }
}

/// `pending` = (이름, 값이 참조하는 변수들) — 참조 대상이 오염되면 이름도 오염된다.
fn collect_taint(
    node: Node,
    src: &[u8],
    taint: &mut BTreeSet<String>,
    pending: &mut Vec<(String, Vec<String>)>,
) {
    let name_field = match node.kind() {
        "variable_assignment" => Some("name"),
        "for_statement" => Some("variable"),
        _ => None,
    };
    if let Some(name) = name_field
        .and_then(|f| node.child_by_field_name(f))
        .and_then(|n| text(n, src))
    {
        let mut c = node.walk();
        for value in node.children_by_field_name("value", &mut c) {
            let mut refs = Word::default();
            collect_refs(value, src, &mut refs);
            if refs.has_subst {
                taint.insert(name.to_string());
            } else if !refs.vars.is_empty() {
                pending.push((name.to_string(), refs.vars));
            }
        }
    }
    if node.kind() == "command" {
        taint_read_targets(node, src, taint);
    }
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        collect_taint(child, src, taint, pending);
    }
}

fn taint_read_targets(node: Node, src: &[u8], taint: &mut BTreeSet<String>) {
    let outer = node
        .child_by_field_name("name")
        .and_then(|n| literal_of(n, src));
    let Some(outer) = outer else {
        return;
    };
    let argv = argument_literals(node, src);
    let Some((verb, args_start)) = read_builtin_argv(&outer, &argv) else {
        return;
    };
    let (value_opts, default_target) = match verb {
        "read" => (READ_VALUE_OPTS, "REPLY"),
        "mapfile" | "readarray" => (MAPFILE_VALUE_OPTS, "MAPFILE"),
        _ => return,
    };
    let mut skip = false;
    let mut found_target = false;
    for word in &argv[args_start..] {
        let Some(lit) = word.as_deref() else {
            skip = false;
            continue;
        };
        if std::mem::take(&mut skip) {
            continue;
        }
        if let Some(flags) = lit.strip_prefix('-') {
            skip = flags.chars().last().is_some_and(|f| value_opts.contains(f));
        } else {
            taint.insert(lit.to_string());
            found_target = true;
        }
    }
    if !found_target && !skip {
        taint.insert(default_target.to_string());
    }
}

/// Resolve only shell builtins that preserve `read`'s mutation of the current shell. External
/// wrappers such as `env` execute a separate process and must not taint the parent shell.
fn read_builtin_argv<'a>(outer: &'a str, argv: &'a [Option<String>]) -> Option<(&'a str, usize)> {
    let mut verb = outer;
    let mut args_start = 0;
    loop {
        match verb {
            "read" | "mapfile" | "readarray" => return Some((verb, args_start)),
            "command" => {
                let mut i = args_start;
                loop {
                    let word = argv.get(i)?.as_deref()?;
                    if word == "--" {
                        i += 1;
                        break;
                    }
                    if word == "-" || !word.starts_with('-') {
                        break;
                    }
                    // `command` only executes its operand through the audited `-p` execution
                    // form. Query modes and invalid/unknown options do not run the following
                    // word as a builtin in the current shell.
                    if !word.chars().skip(1).all(|c| c == 'p') {
                        return None;
                    }
                    i += 1;
                }
                verb = argv.get(i)?.as_deref()?;
                args_start = i + 1;
            }
            "builtin" => {
                let mut i = args_start;
                if argv.get(i).and_then(|word| word.as_deref()) == Some("--") {
                    i += 1;
                }
                verb = argv.get(i)?.as_deref()?;
                if verb.starts_with('-') {
                    return None;
                }
                args_start = i + 1;
            }
            _ => return None,
        }
    }
}
