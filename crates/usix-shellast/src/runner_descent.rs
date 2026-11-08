//! 셸 러너(`sh -c`류) 하강 로직 — `-c` 오퍼랜드뿐 아니라 herestring(`<<<`)·heredoc(`<<`)·
//! 파이프/리다이렉트로 stdin 에 넘어간 스크립트까지 판정한다.
//!
//! Runner descent lives here after executable resolution; general word interpretation and
//! command resolution remain in `lib.rs`.
//!
//! # stdin 하강 결함(2026-09 리뷰 수리)
//!
//! 기존 코드는 `-c` 오퍼랜드만 봤다. `bash <<< 'cargo test'`·`bash <<EOF\ncargo test\nEOF`
//! 처럼 스크립트가 stdin 으로 넘어가는 형태는 전부 무시돼(`uncertain`도 안 세워짐)
//! `compiler_feedback_verb()`가 `None`을 반환하고 `usix-tools::tool_policy`의 substring
//! 폴백도 `uncertain`일 때만 돌기 때문에 그것도 안 돌아 `deny_compiler_feedback`가 우회됐다.
//! 이 모듈은:
//! 1. herestring/heredoc 본문이 **리터럴**이면 재귀 스캔한다(기존 `-c` 경로와 동일 깊이 제한).
//! 2. 본문이 **불투명**(확장 포함)이거나 heredoc 본문 노드를 못 찾으면 `uncertain`.
//! 3. herestring/heredoc 자체가 없는데 스크립트 파일 오퍼랜드가 있거나(`bash script.sh`)
//!    파이프 오른쪽(`… | bash`)이거나 `<` 파일 리다이렉트(`bash < script.sh`)면 — 정적으로
//!    스크립트를 볼 방법이 없으므로 `uncertain`(차단 아님, 호출부가 mode 승급).
//! 4. 러너 단독 호출(`bash`·`bash -l`, 파이프·리다이렉트 없음)은 대화형이라 그대로 둔다.

use tree_sitter::Node;

use crate::pipe_flow::{self, FlowCtx};
use crate::{argument_literals, literal_of, scan_into, text, ResolvedCommand, ShellScan};

/// 중첩 러너(`sh -c "…"`) 하강 깊이 상한. 넘으면 스캔 못 한 스크립트가 남으므로 `uncertain`.
const MAX_RUNNER_DEPTH: u32 = 4;

/// basename 이 이 집합이면 `-c` 오퍼랜드가 **중첩 셸 프로그램**이다.
const SHELL_RUNNERS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash"];

/// 러너 단축옵션 중 **다음 워드를 인자로 먹는** 것. 없으면 `bash -o errexit -c …` 에서
/// `errexit` 을 첫 오퍼랜드로 오독해 하강을 멈춘다.
const SHORT_OPTS_WITH_ARG: &[char] = &['o', 'O'];

/// 러너 롱옵션 중 다음 워드를 먹는 것. 목록 밖 롱옵션은 무인자로 취급 — 최악의 경우
/// 그 인자를 첫 오퍼랜드로 오독해 하강을 **덜** 할 뿐, 과하게 하강하지는 않는다.
const LONG_OPTS_WITH_ARG: &[&str] = &["--rcfile", "--init-file"];

/// verb 가 셸 러너이면 `-c`·herestring·heredoc 중 정적으로 보이는 스크립트를 재귀 스캔하고,
/// 아무것도 안 보이는데 stdin 으로 스크립트가 넘어갔을 수 있으면 `uncertain` 을 세운다.
pub(crate) fn maybe_descend_runner(
    cmd: &ResolvedCommand,
    node: Node,
    src: &[u8],
    depth: u32,
    ctx: &FlowCtx,
    out: &mut ShellScan,
) {
    let argv = argument_literals(node, src);
    maybe_descend_runner_argv(cmd, &argv, node, src, depth, ctx, out);
}

/// Descend a shell runner selected as the final executable of an exec-style wrapper chain.
pub(crate) fn maybe_descend_wrapped_runner(
    cmd: &ResolvedCommand,
    argv: &[Option<String>],
    node: Node,
    src: &[u8],
    depth: u32,
    ctx: &FlowCtx,
    out: &mut ShellScan,
) {
    maybe_descend_runner_argv(cmd, argv, node, src, depth, ctx, out);
}

fn maybe_descend_runner_argv(
    cmd: &ResolvedCommand,
    argv: &[Option<String>],
    node: Node,
    src: &[u8],
    depth: u32,
    ctx: &FlowCtx,
    out: &mut ShellScan,
) {
    let Some(verb) = cmd.verb.as_deref() else {
        return;
    };
    if !SHELL_RUNNERS.contains(&verb) {
        return;
    }
    // `-c` 스크립트만 러너의 stdin(파이프 등)을 데이터로 물려받는다 — stdin 스크립트는 stdin 이
    // 곧 스크립트다.
    let (body, inherited) = match script_operand(verb, argv) {
        ScriptOperand::Literal(script) => (
            script,
            pipe_flow::stdin_source(node, src).or(ctx.inherited_stdin),
        ),
        ScriptOperand::Opaque => {
            out.uncertain = true;
            return;
        }
        ScriptOperand::NoExecute => return,
        ScriptOperand::Absent => match stdin_script_body(node, src) {
            StdinScript::Literal(body) => (body, None),
            StdinScript::Opaque => {
                out.uncertain = true;
                return;
            }
            StdinScript::None => {
                if runner_stdin_is_unseen(cmd, node, src) {
                    out.uncertain = true;
                }
                return;
            }
        },
    };
    if depth + 1 > MAX_RUNNER_DEPTH {
        // 스캔 못 한 스크립트가 남았다 = 판정 불능.
        out.uncertain = true;
        return;
    }
    scan_into(&body, depth + 1, inherited, out);
}

/// 러너 argv 를 POSIX 옵션 의미론으로 훑어 `-c` 의 스크립트 오퍼랜드를 뽑는다.
///
/// `-c` 는 결합 단축그룹 **아무 위치**에서나 성립한다(`-xc`·`-cx`). `--` 이후와 첫
/// 오퍼랜드 이후의 플래그 워드는 러너 옵션이 아니다 — 거기서 하강하면 거짓 양성이다.
enum ScriptOperand {
    Absent,
    Literal(String),
    /// The runner parses input without executing it (`-n`, or Bash `-D`).
    NoExecute,
    /// `-c` was present but its selected body is opaque or missing, or an opaque argv word makes
    /// the option/body boundary unknowable.
    Opaque,
}

fn script_operand(verb: &str, argv: &[Option<String>]) -> ScriptOperand {
    let mut seen_script_flag = false;
    let mut skip_next = false;
    let mut no_execute = false;
    let mut zsh_b_terminates = verb == "zsh";

    for (index, word) in argv.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let Some(lit) = word.as_deref() else {
            return ScriptOperand::Opaque;
        };
        if lit == "--" {
            // 이후는 전부 오퍼랜드 — 스크립트 플래그를 이미 봤다면 다음 워드가 스크립트다.
            return if no_execute {
                ScriptOperand::NoExecute
            } else if seen_script_flag {
                script_at(argv, index + 1)
            } else {
                ScriptOperand::Absent
            };
        }
        if lit == "-" || !lit.starts_with('-') {
            if let Some(flags) = lit.strip_prefix('+') {
                if flags.is_empty() {
                    return if no_execute {
                        ScriptOperand::NoExecute
                    } else {
                        ScriptOperand::Absent
                    };
                }
                let chars: Vec<char> = flags.chars().collect();
                let mut ends_options = false;
                for (i, ch) in chars.iter().enumerate() {
                    if SHORT_OPTS_WITH_ARG.contains(ch) {
                        // `+o`/`+O` disable an option and consume values exactly like their
                        // `-o`/`-O` forms. Other `+` flags, including `+c`, disable rather than
                        // enable the corresponding shell behavior.
                        skip_next = i + 1 == chars.len();
                        break;
                    }
                    if *ch == 'n' {
                        no_execute = false;
                    }
                    if verb == "zsh" && *ch == '-' {
                        ends_options = true;
                        break;
                    }
                    if zsh_b_terminates && *ch == 'b' {
                        ends_options = true;
                    }
                }
                if ends_options {
                    let body_index = index + 1 + if skip_next { 1 } else { 0 };
                    return if no_execute {
                        ScriptOperand::NoExecute
                    } else if seen_script_flag {
                        script_at(argv, body_index)
                    } else {
                        ScriptOperand::Absent
                    };
                }
                continue;
            }
            // 첫 오퍼랜드. 스크립트 플래그를 봤으면 이게 스크립트 본문, 아니면 파일명.
            return if no_execute {
                ScriptOperand::NoExecute
            } else if seen_script_flag {
                ScriptOperand::Literal(lit.to_string())
            } else {
                ScriptOperand::Absent
            };
        }
        if let Some(long) = lit.strip_prefix("--") {
            if verb == "zsh" && lit == "--emulate" {
                let Some(mode) = argv.get(index + 1).and_then(|word| word.as_deref()) else {
                    return ScriptOperand::Opaque;
                };
                zsh_b_terminates = !matches!(mode, "sh" | "ksh");
                skip_next = true;
            } else if LONG_OPTS_WITH_ARG.contains(&lit) && !long.contains('=') {
                skip_next = true;
            }
            continue;
        }
        // 단축 그룹 — `c` 가 어디 있든 성립. 인자 먹는 옵션이 **마지막**이면 다음 워드를 먹는다.
        let chars: Vec<char> = lit.chars().skip(1).collect();
        let mut ends_options = false;
        for (i, ch) in chars.iter().enumerate() {
            if SHORT_OPTS_WITH_ARG.contains(ch) {
                // A suffix is the attached option value; otherwise the next argv word is its value.
                skip_next = i + 1 == chars.len();
                break;
            }
            if *ch == 'n' || verb == "bash" && *ch == 'D' {
                no_execute = true;
            }
            if *ch == 'c' {
                seen_script_flag = true;
            }
            if verb == "zsh" && *ch == '-' {
                ends_options = true;
                break;
            }
            if zsh_b_terminates && *ch == 'b' {
                ends_options = true;
            }
        }
        if ends_options {
            let body_index = index + 1 + if skip_next { 1 } else { 0 };
            return if no_execute {
                ScriptOperand::NoExecute
            } else if seen_script_flag {
                script_at(argv, body_index)
            } else {
                ScriptOperand::Absent
            };
        }
    }
    if no_execute {
        ScriptOperand::NoExecute
    } else if seen_script_flag {
        ScriptOperand::Opaque
    } else {
        ScriptOperand::Absent
    }
}

fn script_at(argv: &[Option<String>], index: usize) -> ScriptOperand {
    match argv.get(index) {
        Some(Some(script)) => ScriptOperand::Literal(script.clone()),
        Some(None) | None => ScriptOperand::Opaque,
    }
}

/// stdin 으로 넘어간 러너 스크립트의 판정 결과.
enum StdinScript {
    /// 리터럴 본문 확보 — 재귀 스캔 대상.
    Literal(String),
    /// herestring/heredoc 은 있는데 본문이 불투명(확장 포함) — 판정 불능.
    Opaque,
    /// herestring/heredoc 자체가 없다 — 다른 stdin 경로(파일 오퍼랜드·파이프·리다이렉트)를
    /// 봐야 한다.
    None,
}

/// `command` 노드에 herestring(`<<<`) 또는 heredoc(`<<`)으로 붙은 스크립트 본문을 찾는다.
///
/// tree-sitter-bash 문법이 둘을 다르게 매단다(`to_sexp` 실측):
/// - herestring: `(command name: (command_name …) redirect: (herestring_redirect (raw_string)))`
///   — `command` 자신의 자식.
/// - heredoc: `(redirected_statement body: (command …) redirect: (heredoc_redirect
///   (heredoc_start) (heredoc_body) (heredoc_end)))` — `command` 를 감싸는 `redirected_statement`
///   부모의 자식이지 `command` 자신의 자식이 아니다.
fn stdin_script_body(node: Node, src: &[u8]) -> StdinScript {
    let mut cursor = node.walk();
    if let Some(herestring) = node
        .named_children(&mut cursor)
        .find(|c| c.kind() == "herestring_redirect")
    {
        let mut hc = herestring.walk();
        return match herestring.named_children(&mut hc).next() {
            Some(body) => literal_or_opaque(body, src),
            None => StdinScript::Opaque,
        };
    }

    let Some(parent) = node.parent() else {
        return StdinScript::None;
    };
    if parent.kind() != "redirected_statement" {
        return StdinScript::None;
    }
    let mut pc = parent.walk();
    let Some(heredoc) = parent
        .named_children(&mut pc)
        .find(|c| c.kind() == "heredoc_redirect")
    else {
        return StdinScript::None;
    };
    heredoc_body_literal(heredoc, src)
}

fn literal_or_opaque(body: Node, src: &[u8]) -> StdinScript {
    match literal_of(body, src) {
        Some(lit) => StdinScript::Literal(lit),
        None => StdinScript::Opaque,
    }
}

/// heredoc 본문 판정 — 확장(`simple_expansion`·`command_substitution` 등) 자식이 하나라도
/// 있으면 불투명. 없으면(보통 자식이 아예 없다 — 인용 구분자 `<<'EOF'` 는 실측상 항상 이
/// 형태다) 노드 원문 전체가 리터럴이다. 빈 heredoc(`<<EOF\nEOF`)은 본문 노드 자체가 없어
/// 빈 리터럴로 취급한다.
fn heredoc_body_literal(heredoc: Node, src: &[u8]) -> StdinScript {
    let mut hc = heredoc.walk();
    let Some(body) = heredoc
        .named_children(&mut hc)
        .find(|c| c.kind() == "heredoc_body")
    else {
        return StdinScript::Literal(String::new());
    };
    let mut bc = body.walk();
    if body
        .named_children(&mut bc)
        .any(|c| c.kind() != "heredoc_content")
    {
        return StdinScript::Opaque;
    }
    match text(body, src) {
        Some(t) => StdinScript::Literal(t.to_string()),
        None => StdinScript::Opaque,
    }
}

/// herestring/heredoc 이 전혀 없는 러너가 그래도 stdin 으로 안 보이는 스크립트를 받을 수
/// 있는가 — 스크립트 파일 오퍼랜드(`bash script.sh`), 파이프 오른쪽(`… | bash`), `<` 파일
/// 리다이렉트(`bash < script.sh`). 셋 다 아니면(`bash`·`bash -l` 단독) 대화형이라 그대로 둔다.
fn runner_stdin_is_unseen(cmd: &ResolvedCommand, node: Node, src: &[u8]) -> bool {
    if !cmd.operands.is_empty() {
        return true; // 스크립트 파일 오퍼랜드 — 정적으로 내용을 못 본다.
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "pipeline" => {
            let mut cursor = parent.walk();
            let is_right_side = parent
                .named_children(&mut cursor)
                .next()
                .is_some_and(|first| first.id() != node.id());
            is_right_side
        }
        "redirected_statement" => {
            let mut cursor = parent.walk();
            let has_stdin_redirect = parent
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "file_redirect")
                .any(|fr| text(fr, src).is_some_and(|t| t.trim_start().starts_with('<')));
            has_stdin_redirect
        }
        _ => false,
    }
}
