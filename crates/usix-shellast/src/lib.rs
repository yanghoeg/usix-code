//! 셸 명령어 **구조** 해석 — 보안 판정용. 순수 함수, I/O 0.
//!
//! # 왜 있나
//!
//! `usix-core` `domain::shell_policy::check_shell_blocked` 는 소문자 변환 후 리터럴
//! substring 매칭이다. 실측(진짜 함수 호출) 결과 우회 코퍼스 23종 중 **19종이 통과**했다 —
//! 인용 분할(`r"m" -rf /`)·백슬래시(`r\m`)·ANSI-C(`$'\x72m'`)·롱플래그·플래그 분리
//! (`rm -r -f /`)·공백/탭 변형·인용된 경로가 전부 뚫린다. 그 레이어는 주석이 "하드 deny
//! (yolo 도 못 뚫음)는 회복불가 파국만 남긴다"고 선언한 최후 방어선이고, 위임 하네스가
//! 자식을 **항상 `--yolo`** 로 스폰하므로(`usix-code` `wave/mod.rs`) 그 위 mode gate 는
//! 상시 열려 있다. 즉 선언한 불변식이 거짓이었다.
//!
//! 참조 설계·회귀 코퍼스 = software-agent-sdk `31f97e4c`(#3944 Phase 2b),
//! `openhands/sdk/security/defense_in_depth/shell_semantics.py`.
//!
//! # 계약
//!
//! - substring 레이어를 **대체하지 않는다**. 호출부가 `substring_hit || ast_hit` 으로 OR 한다
//!   — AST 가 못 보는 걸 substring 이 우연히 잡는 경우가 실재한다(`bash -c 'rm -rf /'`).
//! - 해석 불가는 **차단이 아니라 [`ShellScan::uncertain`]** 이다. 호출부가 mode 승급으로
//!   보낸다. 차단으로 만들면 `rm $OPTS /` 같은 정상 호출이 전부 죽어 가드가 꺼진다.
//! - `uncertain` 은 **탐지가 의존하는 지점에서만** 세운다. 임의 산문이 셸로 파싱 안 된다고
//!   전부 UNKNOWN 이 되면 승급이 무의미해진다(OSS 도 같은 결론).

use std::collections::BTreeSet;

use tree_sitter::{Node, Parser};

mod exec_resolution;
mod pipe_flow;
mod runner_descent;
mod sink_args;
mod taint;

pub use pipe_flow::{DataSource, NetworkFlow, NetworkTarget};

/// 해석된 단일 명령.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedCommand {
    /// de-quote → POSIX basename 을 거친 verb. 불투명(`$(…)`·`` ` ``·`$'…'`·`$VAR`)이면 `None`.
    pub verb: Option<String>,
    /// de-quote 만 거치고 basename 은 안 한 verb 원문(경로 포함) — `./target/debug/deps/x` 처럼
    /// `verb` 가 이미 basename 으로 접혀 잃어버리는 경로 세그먼트를 판정하는 용도(QHR-TOOL-POLICY-001
    /// review fix 2: `target/debug`·`target/release` 직접 실행 탐지). `verb` 와 마찬가지로 불투명이면
    /// `None`.
    pub verb_raw: Option<String>,
    /// De-quoted literal arguments in their original order, excluding the command name.
    ///
    /// This retains distinctions that the flag/operand summaries intentionally erase. Permission
    /// checks for dual-use programs consume this vector so shell quote concatenation
    /// (`-d""elete`) cannot differ from the argv received by the executed program.
    pub arguments: Vec<String>,
    /// 단축 플래그 문자 집합. `-rf`·`-r -f`·`-"r"f` 가 모두 `{'r','f'}` 로 정규화된다.
    pub short_flags: BTreeSet<char>,
    /// 롱 플래그 이름(선두 `--` 제외). `--recursive` → `"recursive"`.
    pub long_flags: BTreeSet<String>,
    /// 옵션이 아닌 워드(경로 등). `--` 이후는 전부 여기로 온다.
    pub operands: Vec<String>,
    /// 이 명령의 워드 중 확장 전에는 값을 알 수 없는 것이 있었다(`$OPTS` 등).
    pub had_opaque_word: bool,
}

impl ResolvedCommand {
    /// verb 가 `name` 인가(이미 basename 화돼 있다).
    #[must_use]
    pub fn verb_is(&self, name: &str) -> bool {
        self.verb.as_deref() == Some(name)
    }

    /// 재귀 + 강제 플래그가 **둘 다** 있는가. 표기(결합·분리·롱)를 동등 취급한다.
    #[must_use]
    pub fn has_recursive_and_force(&self) -> bool {
        let recursive = self.short_flags.contains(&'r')
            || self.short_flags.contains(&'R')
            || self.long_flags.contains("recursive");
        let force = self.short_flags.contains(&'f') || self.long_flags.contains("force");
        recursive && force
    }
}

/// 한 셸 소스에서 해석해낸 전체(중첩 러너 스크립트 포함).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellScan {
    pub commands: Vec<ResolvedCommand>,
    /// Supported wrappers' normalized final executables. Kept separate so one AST command remains
    /// one public `commands` entry for command-chain classification.
    resolved_execs: Vec<ResolvedCommand>,
    /// 탐지가 의존하는 지점을 해석하지 못했다 → 호출부는 **차단이 아니라 mode 승급**.
    pub uncertain: bool,
    /// 로컬 데이터가 **외부** 호스트로 가는 `curl`·`wget`·nc 계열로 흐르는 구조([`pipe_flow`]).
    /// 루프백·불투명 목적지는 담지 않는다.
    pub network_flows: Vec<NetworkFlow>,
    /// Every transfer to a literal external host, whatever its data source. Unlike
    /// [`Self::network_flows`] this is a destination judgement, so a literal payload upload
    /// produces a target and no flow. Loopback and opaque destinations are excluded.
    pub network_targets: Vec<NetworkTarget>,
    /// 파이프 뒷단·명령치환 안에서 (래퍼 경유 포함) 실행되는 `rm`.
    pub piped_rm: bool,
}

impl ShellScan {
    /// Every resolved command: the AST commands followed by the final executables of supported
    /// wrappers (`setsid`, `env`, `nohup`, …), nested runner scripts included.
    pub fn executed_commands(&self) -> impl Iterator<Item = &ResolvedCommand> {
        self.commands.iter().chain(&self.resolved_execs)
    }

    /// **회복불가 파국** 등급의 재귀-강제 삭제가 있는가. 중첩 러너 스크립트 안쪽도 본다.
    ///
    /// 판정 = verb `rm` + 재귀·강제 **동시** + 타깃이 **절대경로 또는 홈**.
    ///
    /// 타깃 축이 있는 이유: `usix-core` 의 기존 하드-deny 테이블이 상대 스코프 삭제
    /// (`rm -rf target/debug`·`rm -rf .`)를 **의도적으로 제외**한다("정상 청소·회복가능 →
    /// 변이로 ask"). 이 해석기는 그 정책을 더 정확히 집행하는 것이지 넓히는 게 아니다 —
    /// 넓히면 일상 명령이 yolo 로도 못 뚫는 하드 deny 에 걸려 가드가 꺼진다.
    /// 기존 substring `"rm -rf /"` 가 `rm -rf /etc` 까지 잡던 것과 동일 범위를 유지한다.
    #[must_use]
    pub fn has_catastrophic_recursive_delete(&self) -> bool {
        self.commands.iter().chain(&self.resolved_execs).any(|c| {
            c.verb_is("rm")
                && c.has_recursive_and_force()
                && c.operands.iter().any(|o| is_root_or_home_target(o))
        })
    }

    /// QHR-TOOL-POLICY-001 — AST 로 정확 해석된 verb 가 컴파일러/테스트 러너인가(중첩 러너
    /// 스크립트 안쪽 포함). 매치된 verb 반환(영수증/UX 용), `None`=무매치.
    ///
    /// `usix-core::domain::shell_policy::check_compiler_feedback_blocked` 는 이 메서드가
    /// `uncertain` 일 때만 도는 **폴백**이다(review fix 1 — AST 가 정확 해석했으면 그 판정만
    /// 쓴다. `has_catastrophic_recursive_delete`처럼 판정 자체를 대체하던 예전 OR 계약과 다름).
    /// verb 가 불투명(`had_opaque_word`로 `verb=None`)이면 이 메서드는 그 명령을 건너뛴다 —
    /// 판정 불능은 `ShellScan::uncertain`의 몫이지 이 메서드가 fail-open 하는 게 아니다.
    ///
    /// review fix 2: `verb_raw`(basename 안 거친 원문)에 `target/debug/`·`target/release/`
    /// 세그먼트가 있으면 빌드 산출물 직접 실행으로 보고 차단하고, `nix develop -c <verb>` 는
    /// `-c` 뒤 오퍼랜드를 감싸인 verb 로 보고 재판정한다(`sh -c`처럼 스크립트 문자열이 아니라
    /// argv 그대로라 `maybe_descend_runner` 재파싱 대상이 아니다 — 여기서 직접 처리).
    ///
    /// residual R1(2026-09-03): `verb == "make"` 이면서 `operands` 가 비어 있으면(값-취득
    /// 플래그의 값은 `resolve_command`가 이미 걸러 operands 에서 제외했다) bare `make` — GNU
    /// make 기본 동작(첫 타깃=보통 빌드)이라 hit.
    #[must_use]
    pub fn compiler_feedback_verb(&self) -> Option<&str> {
        for c in self.commands.iter().chain(&self.resolved_execs) {
            let Some(verb) = c.verb.as_deref() else {
                continue;
            };
            if verb == "make"
                && (c.short_flags.iter().any(|flag| matches!(flag, 'h' | 'v'))
                    || c.long_flags
                        .iter()
                        .any(|flag| matches!(flag.as_str(), "help" | "version")))
            {
                continue;
            }
            if COMPILER_FEEDBACK_VERBS.contains(&verb) {
                return Some(verb);
            }
            if let Some(raw) = c.verb_raw.as_deref() {
                if raw.contains("target/debug/") || raw.contains("target/release/") {
                    return Some(verb);
                }
            }
            if let Some(first) = c.operands.first() {
                if COMPILER_FEEDBACK_SUBCOMMANDS
                    .iter()
                    .any(|&(v, s)| v == verb && s == first.as_str())
                {
                    return Some(verb);
                }
            }
            if verb == "make" && c.operands.is_empty() {
                return Some(verb);
            }
            if verb == "nix" && c.operands.first().map(String::as_str) == Some("develop") {
                if let Some(c_idx) = c.operands.iter().position(|o| o == "-c") {
                    if let Some(wrapped) = c.operands.get(c_idx + 1) {
                        if COMPILER_FEEDBACK_VERBS.contains(&posix_basename(wrapped)) {
                            return Some(verb);
                        }
                    }
                }
            }
        }
        None
    }
}

/// QHR-TOOL-POLICY-001 no-compiler-feedback 정책이 차단하는 verb. 단독으로 차단(빌드시스템
/// 자체가 컴파일러 프런트엔드). `usix-core::domain::shell_policy::COMPILER_FEEDBACK_VERB_TOKENS`
/// ∪ `COMPILER_FEEDBACK_STANDALONE_TOKENS` 와 동일 집합이어야 한다(review fix 4 —
/// `usix-tools`의 드리프트 동일성 테스트가 두 크레이트에서 이 대조를 강제한다) — 이 크레이트는
/// 리프(usix-* 의존 0)라 import 대신 독립 중복 유지(`has_catastrophic_recursive_delete`가
/// `"rm"`을 이미 같은 방식으로 독립 하드코딩). `pub` = 그 드리프트 테스트가 `usix-tools`에서
/// 참조하기 위함(기존 Cargo 의존 방향을 따름 — 새 의존 추가 없음).
pub const COMPILER_FEEDBACK_VERBS: &[&str] = &[
    "cargo", "rustc", "javac", "gcc", "g++", "clang", "clang++", "tsc", "pytest", "rspec",
    "phpunit", "just",
];

/// `make` 값-취득 짧은 옵션(뒤 워드가 값이지 타깃이 아님) — `resolve_command`가 이 목록으로
/// `-C sub`의 `sub`를 operands 에서 제외한다(residual R1, `bare_make`판정 근거).
const MAKE_VALUE_TAKING_SHORT: &[char] = &['C', 'E', 'f', 'I', 'o', 'W'];

/// `make` 값-취득 롱 옵션(이름만, 선두 `--` 제외). 위와 동일 목적.
const MAKE_VALUE_TAKING_LONG: &[&str] = &["directory", "eval", "file", "include", "output-sync"];

/// verb+첫 오퍼랜드(서브커맨드) 조합으로만 차단 — verb 단독은 통과(`go build`류 오탐 방지).
/// `pub` 사유는 [`COMPILER_FEEDBACK_VERBS`]와 동일(드리프트 테스트).
pub const COMPILER_FEEDBACK_SUBCOMMANDS: &[(&str, &str)] = &[
    ("go", "test"),
    ("go", "build"),
    ("go", "vet"),
    ("make", "test"),
    ("make", "check"),
    ("mvn", "test"),
    ("mvn", "compile"),
    ("gradle", "test"),
    ("gradlew", "test"),
    ("npm", "test"),
    ("yarn", "test"),
    ("pnpm", "test"),
    ("dotnet", "test"),
    ("dotnet", "build"),
    ("nix", "run"),
    ("nix", "build"),
];

/// 절대경로(`/…`) 또는 홈(`~`·`~/…`) 타깃인가. 상대경로는 아니다.
fn is_root_or_home_target(operand: &str) -> bool {
    operand.starts_with('/') || operand == "~" || operand.starts_with("~/")
}

/// 셸 소스를 해석한다. 파싱 불가·불투명은 [`ShellScan::uncertain`] 으로 표시하고
/// 해석 가능한 부분은 그대로 담는다(부분 해석이 무해석보다 낫다).
#[must_use]
pub fn scan(src: &str) -> ShellScan {
    let mut out = ShellScan::default();
    scan_into(src, 0, None, &mut out);
    // 불투명 워드를 가진 `rm` 은 `-rf` 를 배제할 수 없다 → 승급 대상.
    if out
        .commands
        .iter()
        .chain(&out.resolved_execs)
        .any(|c| c.had_opaque_word && (c.verb_is("rm") || c.verb.is_none()))
    {
        out.uncertain = true;
    }
    out
}

/// `inherited_stdin` = 이 스크립트를 돌리는 러너가 물려받은 stdin 원천(`… | bash -c '…'`).
pub(crate) fn scan_into(
    src: &str,
    depth: u32,
    inherited_stdin: Option<DataSource>,
    out: &mut ShellScan,
) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        // grammar 적재 실패 = 판정 불능. 조용히 LOW 로 떨어뜨리지 않는다.
        out.uncertain = true;
        return;
    }
    let Some(tree) = parser.parse(src, None) else {
        out.uncertain = true;
        return;
    };
    let ctx = pipe_flow::FlowCtx::new(tree.root_node(), src.as_bytes(), inherited_stdin);
    walk(tree.root_node(), src.as_bytes(), depth, &ctx, out);
}

fn walk(node: Node, src: &[u8], depth: u32, ctx: &pipe_flow::FlowCtx, out: &mut ShellScan) {
    if node.kind() == "command" {
        let cmd = resolve_command(node, src);
        runner_descent::maybe_descend_runner(&cmd, node, src, depth, ctx, out);
        pipe_flow::inspect(&cmd, node, src, ctx, out);
        let argv = argument_literals(node, src);
        let wrapped = resolved_wrapped_command(&cmd, &argv);
        match wrapped {
            WrappedCommand::Known {
                command,
                args_start,
            } => {
                runner_descent::maybe_descend_wrapped_runner(
                    &command,
                    &argv[args_start..],
                    node,
                    src,
                    depth,
                    ctx,
                    out,
                );
                out.resolved_execs.push(command);
            }
            WrappedCommand::Opaque => out.uncertain = true,
            WrappedCommand::None => {}
        }
        out.commands.push(cmd);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, src, depth, ctx, out);
    }
}

enum WrappedCommand {
    Known {
        command: ResolvedCommand,
        args_start: usize,
    },
    None,
    Opaque,
}

/// Normalize the actual executable reached through a supported wrapper chain. Keeping this in
/// `resolved_execs` makes every destructive-command query inspect the same resolved inner command.
fn resolved_wrapped_command(outer: &ResolvedCommand, argv: &[Option<String>]) -> WrappedCommand {
    let Some(verb) = outer.verb.as_deref() else {
        return WrappedCommand::None;
    };
    let refs: Vec<Option<&str>> = argv.iter().map(|word| word.as_deref()).collect();
    match exec_resolution::actual_exec(verb, &refs) {
        exec_resolution::ActualExec::Wrapped {
            verb, args_start, ..
        } => WrappedCommand::Known {
            command: resolve_argv_command(verb, &argv[args_start..]),
            args_start,
        },
        exec_resolution::ActualExec::Opaque => WrappedCommand::Opaque,
        exec_resolution::ActualExec::Outer | exec_resolution::ActualExec::None => {
            WrappedCommand::None
        }
    }
}

pub(crate) fn argument_literals(node: Node, src: &[u8]) -> Vec<Option<String>> {
    let mut cursor = node.walk();
    node.children_by_field_name("argument", &mut cursor)
        .map(|arg| argument_literal(arg, src))
        .collect()
}

fn argument_literal(node: Node, src: &[u8]) -> Option<String> {
    if node.kind() == "number" {
        return text(node, src).map(str::to_string);
    }
    literal_of(node, src)
}

fn resolve_argv_command(verb_raw: String, args: &[Option<String>]) -> ResolvedCommand {
    let mut cmd = ResolvedCommand {
        verb: Some(posix_basename(&verb_raw).to_string()),
        verb_raw: Some(verb_raw),
        ..ResolvedCommand::default()
    };
    let is_make = cmd.verb_is("make");
    let mut skip_next_as_flag_value = false;
    let is_rm = cmd.verb_is("rm");
    let mut options_ended = false;
    for word in args {
        let Some(lit) = word else {
            cmd.had_opaque_word = true;
            continue;
        };
        // Same ordered argv as an AST command, so wrapped executables answer argument checks.
        cmd.arguments.push(lit.clone());
        if skip_next_as_flag_value {
            skip_next_as_flag_value = false;
            continue;
        }
        if options_ended {
            cmd.operands.push(lit.clone());
        } else if lit == "--" {
            options_ended = true;
        } else if lit == "-" || !lit.starts_with('-') {
            // GNU rm accepts options after operands. `--` above remains the explicit boundary.
            options_ended = !is_rm;
            cmd.operands.push(lit.clone());
        } else if let Some(long) = lit.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if is_make && !long.contains('=') && MAKE_VALUE_TAKING_LONG.contains(&name) {
                skip_next_as_flag_value = true;
            }
            cmd.long_flags.insert(name.to_string());
        } else {
            if is_make
                && lit
                    .chars()
                    .last()
                    .is_some_and(|c| MAKE_VALUE_TAKING_SHORT.contains(&c))
            {
                skip_next_as_flag_value = true;
            }
            cmd.short_flags.extend(lit.chars().skip(1));
        }
    }
    cmd
}

/// `command` 노드 하나를 구조로 편다.
fn resolve_command(node: Node, src: &[u8]) -> ResolvedCommand {
    let mut cmd = ResolvedCommand::default();
    let mut cursor = node.walk();

    // 이름(첫 `command_name`) — de-quote 후 basename.
    if let Some(name_node) = node.child_by_field_name("name") {
        match literal_of(name_node, src) {
            Some(lit) => {
                cmd.verb = Some(posix_basename(&lit).to_string());
                cmd.verb_raw = Some(lit);
            }
            None => cmd.had_opaque_word = true, // 불투명 verb
        }
    }
    let is_make = cmd.verb.as_deref() == Some("make");
    let is_rm = cmd.verb.as_deref() == Some("rm");

    // 인자 — POSIX 옵션 의미론.
    let mut options_ended = false;
    // residual R1: make 의 값-취득 옵션(`-C sub`) 다음 워드는 값이지 오퍼랜드(타깃)가 아니다.
    // `is_make` 로만 게이트해 다른 verb 의 기존 동작은 바뀌지 않는다.
    let mut skip_next_as_flag_value = false;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "command_name" {
            continue;
        }
        // 리다이렉트·변수대입은 인자가 아니다.
        if matches!(
            child.kind(),
            "file_redirect"
                | "heredoc_redirect"
                | "herestring_redirect"
                | "variable_assignment"
                | "comment"
        ) {
            continue;
        }
        let Some(lit) = literal_of(child, src) else {
            // 확장 전에는 알 수 없는 워드. 옵션인지 오퍼랜드인지도 모른다.
            cmd.had_opaque_word = true;
            skip_next_as_flag_value = false;
            continue;
        };
        cmd.arguments.push(lit.clone());
        if skip_next_as_flag_value {
            skip_next_as_flag_value = false;
            continue;
        }
        if options_ended {
            cmd.operands.push(lit);
            continue;
        }
        if lit == "--" {
            options_ended = true;
            continue;
        }
        if lit == "-" || !lit.starts_with('-') {
            // GNU rm 은 오퍼랜드 뒤 옵션도 받는다. 다른 명령은 첫 오퍼랜드가 옵션 목록을
            // 끝낸다(러너 하강에서 결정적이다 — `bash script.sh -c '…'`).
            options_ended = !is_rm;
            cmd.operands.push(lit);
            continue;
        }
        if let Some(long) = lit.strip_prefix("--") {
            // `--name=value` 는 이름만 취한다.
            let name = long.split('=').next().unwrap_or(long);
            if is_make && !long.contains('=') && MAKE_VALUE_TAKING_LONG.contains(&name) {
                skip_next_as_flag_value = true;
            }
            cmd.long_flags.insert(name.to_string());
        } else {
            let chars: Vec<char> = lit.chars().skip(1).collect();
            if is_make {
                if let Some(&last) = chars.last() {
                    if MAKE_VALUE_TAKING_SHORT.contains(&last) {
                        skip_next_as_flag_value = true;
                    }
                }
            }
            for ch in chars {
                cmd.short_flags.insert(ch);
            }
        }
    }
    cmd
}

/// 워드의 **확장 후 리터럴**. 확장 전에 알 수 없으면 `None`(= 불투명).
///
/// 인용 분할(`r"m"`)은 `concatenation` 으로 오므로 자식을 이어 붙인다. 명령치환·ANSI-C·
/// 변수확장은 런타임에만 값이 정해지므로 `None` — **추측해서 매치를 날조하지 않는다**.
pub(crate) fn literal_of(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "command_name" => {
            let mut c = node.walk();
            let first = node.named_children(&mut c).next()?;
            literal_of(first, src)
        }
        // 따옴표 밖 워드 — 백슬래시가 다음 문자를 리터럴로 만든다(POSIX 2.2.1).
        "word" => Some(unescape_unquoted(text(node, src)?)),
        // tree-sitter-bash gives an all-digit argv its own node kind. It is still an ordinary
        // literal shell word (`ps -p 123`, `find -maxdepth 1`), not an expansion.
        "number" => Some(text(node, src)?.to_string()),
        // 작은따옴표 — 안쪽은 전부 리터럴, 이스케이프 없음.
        "raw_string" => Some(strip_ends(text(node, src)?, '\'').to_string()),
        // 큰따옴표 — 백슬래시는 `$ ` " \` 개행 앞에서만 이스케이프(POSIX 2.2.3).
        // 과대 제거하면 `"r\m"` 이 `rm` 으로 **날조**된다.
        "string" => {
            let mut c = node.walk();
            let mut buf = String::new();
            for child in node.named_children(&mut c) {
                match child.kind() {
                    "string_content" => buf.push_str(&unescape_double_quoted(text(child, src)?)),
                    // 큰따옴표 안의 확장·치환 = 불투명.
                    _ => return None,
                }
            }
            if buf.is_empty() && node.named_child_count() == 0 {
                // 빈 문자열 `""` — 연결의 일부일 수 있다(`r""m`).
                return Some(String::new());
            }
            Some(buf)
        }
        // `r"m"` · `-"r"f` 처럼 조각이 이어진 워드.
        "concatenation" => {
            let mut c = node.walk();
            let mut buf = String::new();
            for child in node.named_children(&mut c) {
                buf.push_str(&literal_of(child, src)?);
            }
            Some(buf)
        }
        // 런타임에만 값이 정해지는 것들 — 불투명.
        "command_substitution"
        | "process_substitution"
        | "simple_expansion"
        | "expansion"
        | "ansi_c_string"
        | "arithmetic_expansion" => None,
        // 모르는 노드는 보수적으로 불투명 처리.
        _ => None,
    }
}

pub(crate) fn text<'a>(node: Node, src: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&src[node.byte_range()]).ok()
}

fn strip_ends(s: &str, q: char) -> &str {
    s.strip_prefix(q)
        .and_then(|r| r.strip_suffix(q))
        .unwrap_or(s)
}

/// 따옴표 밖: 백슬래시는 **다음 문자 무엇이든** 리터럴로 만든다.
fn unescape_unquoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(ch) = it.next() {
        if ch == '\\' {
            if let Some(next) = it.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// 큰따옴표 안: 백슬래시는 `$`, `` ` ``, `"`, `\`, 개행 **앞에서만** 이스케이프다.
/// 그 외 앞에서는 백슬래시 자체가 리터럴 — `"r\m"` 의 값은 `r\m` 이다.
pub(crate) fn unescape_double_quoted(s: &str) -> String {
    const ESCAPABLE: &[char] = &['$', '`', '"', '\\'];
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == '\\' {
            match it.peek() {
                // A quoted backslash-newline is a line continuation: both characters disappear.
                Some('\n') => {
                    it.next();
                }
                Some(n) if ESCAPABLE.contains(n) => {
                    out.push(*n);
                    it.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// POSIX basename — 마지막 `/` 뒤. 경로 수식(`/bin/rm`)을 verb 로 접는다.
pub(crate) fn posix_basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}
