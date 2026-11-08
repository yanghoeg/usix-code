//! 파이프·명령치환 **데이터 흐름** 판정 — `usix-tools` SHELL_PIPE 룰의 AST 판정부.
//!
//! "로컬 파일·명령 출력이 외부 네트워크 명령의 입력으로 흘러가는 구조"를 본다.
//! - 원천: 파이프 좌변, 싱크 인자 안의 명령치환(`$(…)`·백틱·`<(…)`), here-string·heredoc·`<`
//!   리다이렉트, 파일 참조 인자(`-d @f`·`-F k=@f`·`-T f`·`--post-file=f`), 명령치환·`read` 로
//!   채운 변수의 참조.
//! - 싱크: `curl`·`wget`·nc 계열(`nc`·`ncat`·`netcat`·Debian 대체 이름) — 중첩 러너(`bash -c`) 안쪽과 래퍼(`sudo`·`xargs`·`timeout` …) 경유 포함.
//! - 목적지([`crate::sink_args`]): 루프백(`localhost`·`127.0.0.0/8`·`::1`)이면 유출이 아니다.
//!   호스트가 불투명(`$URL`)하면 여기서 막지 않고 daemon 승급 축(`command_intent`)에 맡긴다 —
//!   `uncertain` 도 세우지 않는다. `command_intent` 가 curl·wget 을 이미 Network 로 분류하고,
//!   `uncertain` 은 compiler-feedback 폴백과 intent Unknown 판정까지 함께 바꾼다.
//!
//! `piped_rm` tracks an actual `rm` executable behind a pipe or inside command substitution,
//! including supported wrappers. It shares executable resolution with catastrophic-delete
//! checks, while remaining independent of their recursive flags and critical-path conditions.
//!
//! `network_targets` is the destination judgement: one entry per transfer to a literal external
//! host, recorded regardless of whether any local data source is attached to it.
//!
//! # 한계 — 하드 보안 경계가 아니다
//!
//! 사고 방지 계층이다. `write_file` 로 스크립트를 만든 뒤 `bash script.sh` 로 돌리면 AST 는
//! 내용을 못 본다(업계 공통 한계). 확장이 섞인 러너 스크립트(`bash -c "… $T"`)도 하강하지
//! 못해 안 보인다.

use std::collections::BTreeSet;

use tree_sitter::Node;

use crate::{
    exec_resolution, literal_of, posix_basename, sink_args, taint, text, unescape_double_quoted,
};
use crate::{ResolvedCommand, ShellScan};

/// 네트워크 싱크. nc 계열 이름은 Sigma `proc_creation_lnx_netcat_reverse_shell` 목록을 따른다.
const NETWORK_SINKS: &[&str] = &[
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "nc.openbsd",
    "nc.traditional",
    "netcat.openbsd",
    "netcat.traditional",
];

/// 싱크로 흘러간 데이터의 원천.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    /// 파이프 좌변(중첩 러너가 물려받은 파이프 포함).
    Pipe,
    /// `<` 파일·here-string·heredoc 으로 stdin 에 들어감.
    StdinRedirect,
    /// 싱크 인자 안의 명령치환·프로세스 치환.
    CommandSubstitution,
    /// `-d @file` 류 파일 참조 인자.
    FileArgument,
    /// 명령치환·`read` 로 채운 변수를 싱크 인자에서 참조.
    TaintedVariable,
}

/// 로컬 데이터가 외부 호스트로 가는 싱크로 흐르는 구조 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFlow {
    pub sink: String,
    pub source: DataSource,
    pub host: String,
}

/// A transfer to a literal external host, whatever its data source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    pub sink: String,
    pub host: String,
}

/// 파싱 1회분의 흐름 문맥.
pub(crate) struct FlowCtx {
    taint: BTreeSet<String>,
    /// 이 스크립트를 돌리는 러너가 물려받은 stdin 원천.
    pub(crate) inherited_stdin: Option<DataSource>,
}

impl FlowCtx {
    pub(crate) fn new(root: Node, src: &[u8], inherited_stdin: Option<DataSource>) -> Self {
        Self {
            taint: taint::tainted_vars(root, src),
            inherited_stdin,
        }
    }
}

/// 명령 인자 워드 하나. 불투명 조각이 섞여도 **리터럴 접두**는 남긴다 — `"http://h/$(…)"` 의
/// 호스트는 접두만으로 정해진다.
#[derive(Debug, Clone, Default)]
pub(crate) struct Word {
    /// 끝까지 리터럴일 때만 `Some`(이때 `prefix` 와 같다).
    pub(crate) lit: Option<String>,
    pub(crate) prefix: String,
    pub(crate) has_subst: bool,
    pub(crate) vars: Vec<String>,
}

impl Word {
    /// `prefix` 바이트 오프셋 `off` 이후 — `--post-file=F`·`-d@F` 의 값 조각.
    pub(crate) fn tail(&self, off: usize) -> Self {
        Self {
            lit: self.lit.as_ref().map(|l| l[off..].to_string()),
            prefix: self.prefix[off..].to_string(),
            has_subst: self.has_subst,
            vars: self.vars.clone(),
        }
    }
}

/// `command` 노드 하나의 흐름 판정 — 결과를 `out` 에 쌓는다.
pub(crate) fn inspect(
    cmd: &ResolvedCommand,
    node: Node,
    src: &[u8],
    ctx: &FlowCtx,
    out: &mut ShellScan,
) {
    let Some(verb) = cmd.verb.as_deref() else {
        return;
    };
    let mut cursor = node.walk();
    let words: Vec<Word> = node
        .children_by_field_name("argument", &mut cursor)
        .map(|n| read_word(n, src))
        .collect();
    let literals: Vec<Option<&str>> = words.iter().map(|word| word.lit.as_deref()).collect();
    let (target, args, stdin_as_args) = match exec_resolution::actual_exec(verb, &literals) {
        exec_resolution::ActualExec::Outer => (verb.to_string(), &words[..], false),
        exec_resolution::ActualExec::Wrapped {
            verb,
            args_start,
            stdin_as_args,
        } => (
            posix_basename(&verb).to_string(),
            &words[args_start..],
            stdin_as_args,
        ),
        exec_resolution::ActualExec::None | exec_resolution::ActualExec::Opaque => return,
    };
    let stdin = stdin_source(node, src).or(ctx.inherited_stdin);
    if target == "rm" {
        out.piped_rm |= stdin == Some(DataSource::Pipe) || in_command_substitution(node);
        return;
    }
    if !NETWORK_SINKS.contains(&target.as_str()) {
        return;
    }
    let tainted = |w: &Word| w.vars.iter().any(|v| ctx.taint.contains(v));
    let transfers = sink_args::parse(&target, args);
    let transfer_count = transfers.len();
    for transfer in transfers {
        let Some(host) = transfer.external_host else {
            continue;
        };
        out.network_targets.push(NetworkTarget {
            sink: target.clone(),
            host: host.clone(),
        });
        let source = stdin
            // xargs turns stdin into child argv, but this resolver does not retain its optional
            // replacement token. With multiple curl transfers, assigning that source to one
            // group would combine unrelated argv. A single transfer has no such ambiguity.
            .filter(|_| transfer.stdin_ref || stdin_as_args && transfer_count == 1)
            .or(transfer.file_ref.then_some(DataSource::FileArgument))
            .or(transfer
                .flow_args
                .iter()
                .any(|w| w.has_subst)
                .then_some(DataSource::CommandSubstitution))
            .or(transfer
                .flow_args
                .iter()
                .any(tainted)
                .then_some(DataSource::TaintedVariable));
        if let Some(source) = source {
            out.network_flows.push(NetworkFlow {
                sink: target.clone(),
                source,
                host,
            });
        }
    }
}

/// 이 명령의 stdin 에 데이터가 들어오는가 — 파이프 뒷단(조상 어디든)·`<`·here-string·heredoc.
///
/// tree-sitter 는 `a | b < f` 의 리다이렉트를 파이프라인에 매단다(bash 는 마지막 단 `b` 에
/// 붙인다). 뒷단은 이미 파이프로 판정되므로 파이프라인에 매달린 리다이렉트는 건너뛴다.
pub(crate) fn stdin_source(node: Node, src: &[u8]) -> Option<DataSource> {
    if has_stdin_redirect(node, src) {
        return Some(DataSource::StdinRedirect);
    }
    let mut child = node;
    while let Some(parent) = child.parent() {
        match parent.kind() {
            "pipeline" => {
                let mut c = parent.walk();
                if parent
                    .named_children(&mut c)
                    .next()
                    .is_some_and(|first| first.id() != child.id())
                {
                    return Some(DataSource::Pipe);
                }
            }
            "redirected_statement"
                if child.kind() != "pipeline" && has_stdin_redirect(parent, src) =>
            {
                return Some(DataSource::StdinRedirect);
            }
            _ => {}
        }
        child = parent;
    }
    None
}

/// `redirect` 필드에 here-string·heredoc·`<` 파일(`/dev/null` 제외)이 있는가.
fn has_stdin_redirect(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let found = node
        .children_by_field_name("redirect", &mut cursor)
        .any(|r| {
            let stdin = r
                .child_by_field_name("descriptor")
                .and_then(|d| text(d, src))
                .is_none_or(|descriptor| descriptor == "0");
            stdin
                && match r.kind() {
                    "herestring_redirect" | "heredoc_redirect" => true,
                    "file_redirect" => {
                        let mut c = r.walk();
                        let reads = r.children(&mut c).any(|t| t.kind() == "<");
                        let null = r
                            .child_by_field_name("destination")
                            .and_then(|d| text(d, src))
                            .is_some_and(|t| t == "/dev/null");
                        reads && !null
                    }
                    _ => false,
                }
        });
    found
}

fn in_command_substitution(node: Node) -> bool {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "command_substitution" {
            return true;
        }
        cur = n.parent();
    }
    false
}

fn read_word(node: Node, src: &[u8]) -> Word {
    let mut w = Word::default();
    if push_literal(node, src, &mut w.prefix) {
        w.lit = Some(w.prefix.clone());
    }
    collect_refs(node, src, &mut w);
    w
}

/// 리터럴 접두를 `buf` 에 쌓는다. 끝까지 리터럴이면 `true` — 첫 불투명 조각에서 멈춘다.
fn push_literal(node: Node, src: &[u8], buf: &mut String) -> bool {
    match node.kind() {
        "string" | "concatenation" => {
            let mut c = node.walk();
            for child in node.named_children(&mut c) {
                let ok = if child.kind() == "string_content" {
                    text(child, src)
                        .map(|t| buf.push_str(&unescape_double_quoted(t)))
                        .is_some()
                } else {
                    push_literal(child, src, buf)
                };
                if !ok {
                    return false;
                }
            }
            true
        }
        "number" => text(node, src).map(|t| buf.push_str(t)).is_some(),
        _ => literal_of(node, src).map(|l| buf.push_str(&l)).is_some(),
    }
}

pub(crate) fn collect_refs(node: Node, src: &[u8], w: &mut Word) {
    match node.kind() {
        "command_substitution" | "process_substitution" => w.has_subst = true,
        "variable_name" => w.vars.extend(text(node, src).map(str::to_string)),
        _ => {}
    }
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        collect_refs(child, src, w);
    }
}
