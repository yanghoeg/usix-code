//! QHR-TOOL-POLICY-001 no-compiler-feedback 정책 — AST verb 해석 코퍼스.
//!
//! `usix-tools::tools::tool_policy`가 이 크레이트의 [`ShellScan::compiler_feedback_verb`]와
//! `usix-core::domain::shell_policy::check_compiler_feedback_blocked`(substring)를
//! `substring_hit || ast_hit`로 OR 해 우회(따옴표·이스케이프·경로수식·중첩 러너)에
//! 견디게 한다. 이 파일은 AST 레이어 단독 계약만 검증한다 — `bypass_corpus.rs`와 동일 스타일.

use usix_shellast::{scan, ShellScan};

/// 컴파일러/테스트 러너 verb 가 잡혔는가.
fn caught(cmd: &str) -> bool {
    let s: ShellScan = scan(cmd);
    s.compiler_feedback_verb().is_some()
}

// ── A군: 반드시 잡아야 한다 ──────────────────────────────────────────────

#[test]
fn named_verbs_are_caught() {
    for cmd in [
        "cargo build",
        "cargo test",
        "cargo test -p usix-core",
        "cargo clippy -- -D warnings",
        "rustc foo.rs",
        "javac Foo.java",
        "pytest",
        "rspec spec/foo_spec.rb",
    ] {
        assert!(caught(cmd), "verb 미포획: {cmd}");
    }
}

#[test]
fn verb_subcommand_pairs_are_caught() {
    for cmd in ["go test ./...", "make test", "npm test", "dotnet test"] {
        assert!(caught(cmd), "verb+subcommand 미포획: {cmd}");
    }
}

#[test]
fn quoted_verb_is_caught() {
    for cmd in [r#""cargo" test"#, r#"c''argo test"#, "'cargo' test"] {
        assert!(caught(cmd), "인용 분할 verb 미포획: {cmd}");
    }
}

#[test]
fn path_qualified_verb_is_caught() {
    for cmd in [
        "/usr/bin/cargo test",
        "/usr/local/bin/cargo build",
        "./cargo test",
    ] {
        assert!(caught(cmd), "경로 수식 verb 미포획: {cmd}");
    }
}

#[test]
fn nested_shell_runner_is_caught() {
    for cmd in [
        r#"bash -c 'cargo test'"#,
        r#"sh -c "cargo build""#,
        r#"bash -c 'rustc foo.rs'"#,
    ] {
        assert!(caught(cmd), "중첩 러너 미포획: {cmd}");
    }
}

#[test]
fn wrapper_resolved_shell_runner_is_caught() {
    for cmd in [
        "sudo bash -c 'cargo test'",
        "sudo -u app env A=1 timeout 5 sh -c 'rustc foo.rs'",
    ] {
        assert!(caught(cmd), "래퍼 안 셸 러너 미포획: {cmd}");
    }
}

#[test]
fn shell_names_in_wrapper_option_values_are_not_descended() {
    for cmd in [
        "sudo -u bash echo -c 'cargo test'",
        "timeout -s bash 5 echo -c 'cargo test'",
        "xargs -I bash echo -c 'cargo test'",
    ] {
        assert!(!caught(cmd), "래퍼 옵션 값을 셸 실행 파일로 오판: {cmd}");
        assert!(
            !scan(cmd).uncertain,
            "확정된 echo 실행을 불투명 오판: {cmd}"
        );
    }
}

#[test]
fn herestring_runner_is_caught() {
    // 리뷰 결함 — 스크립트가 herestring(`<<<`)으로 stdin 에 넘어가면 `-c` 오퍼랜드만 보던
    // 기존 `maybe_descend_runner`가 전혀 하강하지 않아 QHR-TOOL-POLICY-001 이 우회됐다.
    for cmd in [
        r#"bash <<< 'cargo test'"#,
        r#"sh <<< "cargo build""#,
        r#"bash <<< 'cd x && cargo clippy'"#,
    ] {
        assert!(caught(cmd), "herestring 러너 미포획: {cmd}");
    }
}

#[test]
fn heredoc_runner_is_caught() {
    // 리뷰 결함 — heredoc(`<<`)도 동일하게 무시됐다.
    for cmd in ["bash <<EOF\ncargo test\nEOF", "sh <<'EOF'\npytest\nEOF"] {
        assert!(caught(cmd), "heredoc 러너 미포획: {cmd}");
    }
}

#[test]
fn stdin_runner_without_visible_script_is_uncertain() {
    // 정적으로 스크립트 내용을 볼 수 없는 stdin 경로 — 차단이 아니라 uncertain(mode 승급).
    // caught 여부는 무관(잡히면 좋지만 필수 아님).
    for cmd in [
        "echo 'cargo test' | bash",
        "bash script.sh",
        "bash < build.sh",
        "bash <<EOF\n$CMD test\nEOF",
    ] {
        let s: ShellScan = scan(cmd);
        assert!(
            s.uncertain,
            "해석 불가 stdin 러너가 uncertain 이 아님: {cmd}"
        );
    }
}

#[test]
fn interactive_bare_runner_is_not_uncertain() {
    for cmd in ["bash", "bash -l"] {
        assert!(
            !scan(cmd).uncertain,
            "대화형 단독 러너가 uncertain 으로 오판됨: {cmd}"
        );
    }
}

#[test]
fn opaque_or_missing_dash_c_body_is_uncertain() {
    for cmd in [
        r#"bash -c "$CMD""#,
        "sh -c $BODY",
        "bash -c",
        r#"bash -xc "$CMD""#,
        r#"bash -cx "$CMD""#,
        "bash -xc",
        r#"bash -c -- "$CMD""#,
        r#"sudo bash -c "$CMD""#,
        "sudo env A=1 sh -c",
    ] {
        assert!(
            scan(cmd).uncertain,
            "불투명·누락 -c 본문이 uncertain 이 아님: {cmd}"
        );
    }
}

#[test]
fn combined_options_and_dash_dash_preserve_literal_descent_boundaries() {
    for cmd in [
        "bash -xc 'cargo test'",
        "bash -cx 'cargo test'",
        "bash -o errexit -c 'cargo test'",
        "bash -xc -- 'cargo test'",
    ] {
        assert!(caught(cmd), "리터럴 -c 본문 하강 실패: {cmd}");
        assert!(!scan(cmd).uncertain, "리터럴 -c 본문을 불투명 오판: {cmd}");
    }

    let after_dash_dash = "bash -- -c 'cargo test'";
    assert!(
        !caught(after_dash_dash),
        "-- 뒤 -c 를 러너 옵션으로 오판: {after_dash_dash}"
    );
    assert!(
        scan(after_dash_dash).uncertain,
        "정적으로 못 읽는 스크립트 파일 호출은 uncertain 이어야 함"
    );
}

#[test]
fn target_build_dir_direct_exec_is_caught() {
    // review fix 2 — `verb`는 이미 basename 이라 경로를 잃는다. `verb_raw` 로 판정.
    for cmd in [
        "./target/debug/deps/usix_tools-abc123",
        "target/release/usix --help",
        "env RUST_LOG=debug ./target/debug/x",
    ] {
        assert!(
            caught(cmd),
            "target/{{debug,release}} 직접 실행 미포획: {cmd}"
        );
    }
}

#[test]
fn just_and_nix_run_build_are_caught() {
    // review fix 2 — `just` 는 서브커맨드 무관 단독 차단, `nix run`/`nix build` 는 서브커맨드 쌍.
    for cmd in ["just test", "nix run .#test", "nix build .#pkg"] {
        assert!(caught(cmd), "just/nix 미포획: {cmd}");
    }
}

#[test]
fn nix_develop_dash_c_wrapped_verb_is_caught() {
    // review fix 2 — `nix develop -c <verb>` 는 스크립트 문자열이 아니라 argv 그대로라
    // `maybe_descend_runner`(sh/bash -c 재파싱) 대상이 아니다. `compiler_feedback_verb`가 직접 처리.
    assert!(caught("nix develop -c cargo test"));
}

#[test]
fn bare_make_default_target_is_caught() {
    // QHR-TOOL-POLICY-001 residual R1 — 타깃 없는 make 호출은 GNU make 기본 동작(보통
    // 빌드)이라 컴파일러 피드백 hit. `-C sub`는 값-취득 플래그라 값(`sub`)은 타깃이 아니다.
    for cmd in [
        "make",
        "make -j4",
        "make -C sub",
        "make -E 'all:; @true'",
        "make --eval 'all:; @true'",
        "cd x && make",
    ] {
        assert!(caught(cmd), "bare make 미포획: {cmd}");
    }
}

#[test]
fn make_with_explicit_non_test_target_is_not_caught() {
    // R1과 대칭 — 명시 타깃이 있으면(test/check 제외) 여전히 통과.
    for cmd in [
        "make clean",
        "make install",
        "make fmt",
        "make -E 'all:; @true' clean",
        "make --eval 'all:; @true' install",
        "make -h",
        "make -v",
        "make --help test",
        "make --version",
    ] {
        assert!(!caught(cmd), "명시 타깃 make 오탐: {cmd}");
    }
}

// ── B군: 반드시 통과시켜야 한다 (오탐 = 정상 명령 차단) ──────────────────

#[test]
fn bare_verb_without_denied_subcommand_is_not_caught() {
    // `go build`는 컴파일 자체라 COMPILER_FEEDBACK_SUBCOMMANDS 대상 — 여기는 무관 서브커맨드만.
    for cmd in ["go run main.go", "make all", "npm run build"] {
        assert!(!caught(cmd), "무관 서브커맨드 오탐: {cmd}");
    }
}

#[test]
fn ordinary_commands_are_untouched() {
    for cmd in ["ls -la", "git status", "echo hello", "grep -r foo ."] {
        assert!(!caught(cmd), "정상 명령 오탐: {cmd}");
    }
}

#[test]
fn verb_name_in_argument_position_is_not_caught() {
    // review fix 1 — AST 는 애초부터 command-position 만 본다(verb/operands 필드 분리). 회귀 확인용.
    for cmd in [
        "cat Cargo.toml",
        "grep -rn cargo README.md",
        r#"echo "cargo build ok""#,
        "rg rustc docs/",
        "cat Cargo.lock",
        "ls target",
    ] {
        assert!(!caught(cmd), "인자 위치 오탐: {cmd}");
    }
}

#[test]
fn wrapped_feedback_queries_share_exec_resolution() {
    for cmd in [
        r#"sudo env A=1 c"argo" test"#,
        "sudo env A=1 ./target/debug/probe",
        "env make -C sub",
        "env make --eval 'all:; @true'",
    ] {
        assert!(caught(cmd), "{cmd}");
    }
    for cmd in [
        "env -u cargo echo ok",
        "sudo -u cargo echo ok",
        "env make -C sub clean",
        "env make -E 'all:; @true' clean",
        "env make --help test",
    ] {
        assert!(!caught(cmd), "{cmd}");
    }
}
