//! `usix-shellast` 우회 코퍼스 계약 — 스펙 테스트(구현 선행 동결).
//!
//! usix `check_shell_blocked`(usix-core `domain/shell_policy.rs:236`)는 소문자 변환 후
//! 리터럴 13종 substring 매칭이다. probe 크레이트로 **진짜 함수를 호출해 실측**한 결과
//! 23종 중 19종이 통과했다. 이 레이어는 주석이 "하드 deny(yolo 도 못 뚫음)는 회복불가
//! 파국만 남긴다"고 선언한 최후 방어선이고, `wave/mod.rs:103` 이 위임 자식을 **항상
//! `--yolo`** 로 스폰하므로 그 위 mode gate 는 상시 열려 있다 — 선언한 불변식이 거짓이다.
//!
//! 코퍼스 출처 = software-agent-sdk `31f97e4c`(#3944 Phase 2b)
//! `tests/sdk/security/defense_in_depth/test_shell_parser_bypasses.py`(434줄).
//!
//! **B군(오탐 방지)이 A군만큼 중요하다.** 해석기가 정상 명령을 죽이면 가드가 꺼진다.

use usix_shellast::{scan, ShellScan};

/// 재귀+강제 삭제 조합이 잡혔는가.
fn caught(cmd: &str) -> bool {
    let s: ShellScan = scan(cmd);
    s.has_catastrophic_recursive_delete()
}

/// 해석 불가로 표시됐는가(→ 호출부가 mode 승급).
fn uncertain(cmd: &str) -> bool {
    scan(cmd).uncertain
}

// ── A군: 반드시 잡아야 한다 ──────────────────────────────────────────────

#[test]
fn quoted_verb_is_caught() {
    for cmd in [
        r#"r"m" -rf /"#,
        r#"r''m -rf /"#,
        r#"'rm' -rf /"#,
        r#"r"m" --recursive --force /"#,
        r#""r\
m" -rf /"#,
    ] {
        assert!(caught(cmd), "인용 분할 verb 미포획: {cmd}");
    }
}

#[test]
fn escaped_verb_is_caught() {
    for cmd in [
        r#"r\m -rf /"#,
        r#"r\m --recursive --force /"#,
        r#"/bin/r\m -rf /"#,
    ] {
        assert!(caught(cmd), "백슬래시 이스케이프 verb 미포획: {cmd}");
    }
}

#[test]
fn path_qualified_verb_is_caught() {
    for cmd in [
        "/bin/rm -rf /",
        "/usr/bin/rm -rf /",
        r#"/bin/"rm" -rf /"#,
        r#""/bin/rm" -rf /"#,
        "/bin/rm --recursive --force /",
    ] {
        assert!(caught(cmd), "경로 수식 verb 미포획: {cmd}");
    }
}

#[test]
fn flag_spelling_variants_are_equivalent() {
    for cmd in [
        "rm -rf /",
        "rm -fr /",
        "rm -r -f /", // 분리
        "rm  -rf /",  // 공백 2개
        "rm\t-rf /",  // 탭
        "rm --recursive --force /",
        "rm -r --force /", // 혼합
        r#"rm "-rf" /"#,   // 인용 옵션워드
        r#"rm -"r"f /"#,
        r#"rm '-rf' /"#,
        r#"rm "-r" "-f" /"#,
        r#"rm -r\f /"#,
        "rm /etc -rf",
    ] {
        assert!(caught(cmd), "플래그 표기 변형 미포획: {cmd}");
    }
}

#[test]
fn nested_shell_runner_is_caught() {
    for cmd in [
        r#"bash -c 'rm -rf /'"#,
        r#"sh -c 'rm -rf /'"#,
        r#"bash -c "rm -rf /""#,
        r#"bash -c 'r"m" -rf /'"#,
        r#"sh -c 'rm --recursive --force /'"#,
    ] {
        assert!(caught(cmd), "중첩 러너 미포획: {cmd}");
    }
}

#[test]
fn wrapped_shell_runner_is_caught() {
    for cmd in [
        r#"sudo bash -c 'r"m" -rf /etc'"#,
        r#"sudo -u app env A=1 timeout 5 bash -c 'r"m" /etc -rf'"#,
    ] {
        assert!(caught(cmd), "래퍼 안 셸 러너 본문 미포획: {cmd}");
    }
}

#[test]
fn herestring_runner_catastrophic_rm_is_caught() {
    // 리뷰 결함 — herestring 하강이 없어 `has_catastrophic_recursive_delete`도 못 봤다.
    let s: ShellScan = scan("bash <<< 'rm -rf /'");
    assert!(
        s.has_catastrophic_recursive_delete(),
        "herestring 안 rm -rf / 미포획"
    );
}

#[test]
fn runner_option_group_is_parsed_posix() {
    for cmd in [
        r#"bash -xc 'r"m" -rf /'"#,               // 결합 그룹, 플래그 뒤
        r#"bash -cx 'r"m" -rf /'"#,               // 결합 그룹, 플래그 앞
        r#"bash -o pipefail -c 'r"m" -rf /'"#,    // 인자 먹는 옵션 뒤
        r#"bash +x -c 'r"m" -rf /'"#,             // `+` 옵션도 옵션 목록을 끝내지 않음
        r#"bash +o errexit -c 'r"m" -rf /'"#,     // `+o` 역시 다음 워드를 값으로 먹음
        r#"zsh --emulate sh -c 'r"m" -rf /'"#,    // zsh 전용 값-취득 롱옵션
        r#"bash -n +n -c 'r"m" -rf /'"#,          // 뒤의 +n 이 noexec 를 다시 끔
        r#"zsh -bc 'r"m" -rf /'"#,                // -b 뒤 같은 그룹의 -c 는 유효
        r#"zsh --emulate sh -b -c 'r"m" -rf /'"#, // sh emulation 에서 -b 는 종결자가 아님
    ] {
        assert!(caught(cmd), "러너 argv 옵션 의미론 미적용: {cmd}");
    }
}

#[test]
fn ordered_arguments_match_shell_literal_concatenation() {
    let scan = scan(r#"f""ind "." -d""elete"#);
    assert!(!scan.uncertain);
    assert_eq!(scan.commands.len(), 1);
    assert_eq!(scan.commands[0].verb.as_deref(), Some("find"));
    assert_eq!(scan.commands[0].arguments, [".", "-delete"]);
}

#[test]
fn ordered_arguments_include_numeric_literals() {
    let scan = scan("ps -p 123");
    assert!(!scan.uncertain, "{scan:?}");
    assert_eq!(scan.commands.len(), 1, "{scan:?}");
    assert!(!scan.commands[0].had_opaque_word, "{scan:?}");
    assert_eq!(scan.commands[0].arguments, ["-p", "123"]);
}

#[test]
fn wrapped_executables_keep_their_ordered_arguments() {
    let scan = scan("env DISPLAY=:0 nohup setsid chromium --no-sandbox https://example.com &");
    let wrapped: Vec<_> = scan
        .executed_commands()
        .filter(|command| command.verb_is("chromium"))
        .collect();
    assert_eq!(wrapped.len(), 1, "{scan:?}");
    assert_eq!(
        wrapped[0].arguments,
        ["--no-sandbox", "https://example.com"]
    );
}

// ── B군: 반드시 통과시켜야 한다 (오탐 = 가드 무력화) ─────────────────────

#[test]
fn end_of_options_makes_flags_operands() {
    // `--` 뒤 `-c` 는 스크립트 **파일명**이다. 하강하면 거짓 양성.
    assert!(!caught(r#"bash -- -c 'rm -rf /'"#));
    // `--` 뒤 `-rf` 는 파일명. 루트가 강제삭제되지 않는다.
    assert!(!caught("rm -- -rf /"));
    assert!(!caught("rm -- /etc -rf"));
    assert!(!caught(r#"env r"m" -- /etc -rf"#));
}

#[test]
fn first_operand_ends_the_runner_option_list() {
    // 첫 오퍼랜드(script.sh) 이후 플래그는 그 스크립트의 argv 다.
    assert!(!caught(r#"bash script.sh -c 'rm -rf /'"#));
    // `+c` 는 `-c` 를 켜는 옵션이 아니라 이미 켜진 `c` 동작을 끄는 옵션이다.
    assert!(!caught(r#"bash +c 'r"m" -rf /'"#));
    // noexec 러너는 본문을 파싱할 뿐 실행하지 않는다.
    for cmd in [
        r#"bash -n -c 'r"m" -rf /'"#,
        r#"bash -D -c 'r"m" -rf /'"#,
        r#"sh -n -c 'r"m" -rf /'"#,
        r#"sudo bash -n -c 'r"m" -rf /'"#,
        r#"bash +n -n -c 'r"m" -rf /'"#,
    ] {
        assert!(!caught(cmd), "noexec 러너 본문 오탐: {cmd}");
        assert!(!uncertain(cmd), "확정 noexec 를 불투명 오판: {cmd}");
    }
    // zsh의 독자적인 옵션 종결자는 뒤의 별도 -c를 스크립트 파일명으로 만든다.
    for cmd in [
        r#"zsh -b -c 'r"m" -rf /'"#,
        r#"zsh +b -c 'r"m" -rf /'"#,
        r#"zsh -x- -c 'r"m" -rf /'"#,
        r#"zsh +- -c 'r"m" -rf /'"#,
    ] {
        assert!(!caught(cmd), "zsh 옵션 종결 뒤 -c 오탐: {cmd}");
    }
}

#[test]
fn double_quoted_backslash_is_not_over_stripped() {
    // POSIX 2.2.3 — 큰따옴표 안 백슬래시는 $ ` " \ 개행 앞에서만 이스케이프.
    // `"r\m"` 의 verb 는 `r\m` 이지 `rm` 이 아니다. 과대 정규화로 매치를 **날조하면 안 된다**.
    assert!(!caught(r#""r\m" -rf /"#));
    // Bash에서 CRLF는 LF 단독과 달리 line continuation이 아니다. 백슬래시와 CR을 보존한다.
    assert!(!caught("\"r\\\r\nm\" -rf /"));
}

#[test]
fn half_of_the_destructive_pair_is_not_destructive() {
    assert!(!caught("rm -r /"), "재귀만은 파괴 조합이 아니다");
    assert!(!caught("rm -f /"), "강제만은 파괴 조합이 아니다");
}

#[test]
fn ordinary_commands_are_untouched() {
    for cmd in ["ls -la", "cargo test -p usix-core", "git status"] {
        assert!(!caught(cmd), "정상 명령 오탐: {cmd}");
    }
}

#[test]
fn target_axis_matches_the_existing_hard_deny_scope() {
    // 기존 usix-core 테이블은 상대 스코프 삭제를 **의도적으로 제외**한다("정상 청소·
    // 회복가능 → 변이로 ask"). 해석기는 그 정책을 더 정확히 집행할 뿐 넓히지 않는다 —
    // 넓히면 일상 명령이 yolo 로도 못 뚫는 하드 deny 에 걸려 가드가 통째로 꺼진다.
    for cmd in ["rm -rf /", "rm -rf /etc", "rm -rf ~", "rm -fr ~/Documents"] {
        assert!(caught(cmd), "절대경로·홈 타깃은 파국 등급이다: {cmd}");
    }
    for cmd in [
        "rm -rf target/debug",
        "rm -rf .",
        "rm -rf ./build",
        "rm -rf node_modules",
    ] {
        assert!(
            !caught(cmd),
            "상대 스코프 삭제는 하드 deny 대상이 아니다(기존 정책 유지): {cmd}"
        );
    }
}

#[test]
fn exec_wrappers_resolve_quoted_and_escaped_rm() {
    for cmd in [
        r#"sudo r"m" -rf /"#,
        r#"sudo -kn r"m" -rf /etc"#,
        r#"sudo --reset-timestamp r"m" -rf /etc"#,
        r#"sudo -s r"m" -rf /etc"#,
        r#"sudo --login r"m" -rf /etc"#,
        r#"sudo A=1 -u app B=2 r"m" -rf /etc"#,
        r#"env -- A=1 r"m" -rf /etc"#,
        r#"env --env0-from /dev/null r"m" -rf /etc"#,
        r#"xargs --show-limits r"m" -rf /etc"#,
        r#"env A=1 r\m -r -f /etc"#,
        r#"env r"m" /etc -rf"#,
        r#"command -- 'rm' --recursive --force ~"#,
        r#"timeout 5 "r""m" -fr /srv"#,
        r#"nice -n 5 r\m -rf /"#,
        r#"sudo -u app env A=1 timeout --signal TERM 5 nice -n 1 command -- r"m" -rf /etc"#,
    ] {
        assert!(caught(cmd), "래퍼 안 실제 rm 미포획: {cmd}");
    }
}

#[test]
fn wrapper_option_values_and_normal_operands_are_not_rm_commands() {
    for cmd in [
        "sudo -u rm echo -rf /",
        "sudo echo rm -rf /",
        "env -u rm echo -rf /",
        "env RM=rm echo rm -rf /",
        "timeout rm echo -rf /",
        "nice -n rm echo -rf /",
        "command -v rm",
        "sudo -e rm",
        "sudo -l rm",
        "sudo -K rm -rf /",
        "sudo -v rm -rf /",
        "sudo -s echo rm -rf /",
        "sudo -k -u rm echo -rf /",
        "sudo -- A=1 rm -rf /",
        "doas -u rm echo -rf /",
        "env --help rm -rf /",
        "ionice --help rm -rf /",
        r#"setsid -h r"m" -rf /"#,
        r#"setsid -V r"m" -rf /"#,
        r#"ionice -h r"m" -rf /"#,
        r#"ionice -V r"m" -rf /"#,
        r#"sudo setsid -h r"m" -rf /"#,
        r#"env ionice -V r"m" -rf /"#,
        "sudo -u rm env RM=rm echo rm -rf /",
    ] {
        assert!(!caught(cmd), "래퍼 값·일반 인자를 rm 명령으로 오판: {cmd}");
    }
    assert_eq!(
        scan("sudo echo ok").commands.len(),
        1,
        "래퍼 해석이 공개 AST 명령 수를 부풀리면 안 됨"
    );
}

#[test]
fn sudo_interactive_shell_and_shell_dollar_expansion_are_uncertain() {
    for cmd in ["sudo", "sudo -s", "sudo -i", "sudo -s '$CMD' -rf /etc"] {
        assert!(uncertain(cmd), "{cmd}");
    }
    for cmd in ["sudo -k", "sudo --reset-timestamp"] {
        assert!(!uncertain(cmd), "standalone credential invalidation: {cmd}");
    }
}

// ── C군: 해석 불가 = uncertain (차단 아님 → 호출부가 mode 승급) ──────────

#[test]
fn opaque_verb_is_uncertain_not_silently_low() {
    for cmd in [
        "$(echo rm) -rf /",
        "`echo rm` -rf /",
        r#"$'\x72m' -rf /"#,
        r#"$'\162\155' -rf /"#,
    ] {
        assert!(
            uncertain(cmd),
            "불투명 verb 는 uncertain 이어야 한다(조용한 통과 금지): {cmd}"
        );
    }
}

#[test]
fn dynamic_flag_word_is_uncertain_not_blocked() {
    // 확장 후에만 아는 값 = 미지이지 적대가 아니다. 차단하면 모든 $OPTS 호출이 죽는다.
    assert!(
        !caught("rm $OPTS /"),
        "동적 플래그를 차단으로 오판하면 안 된다"
    );
    assert!(
        uncertain("rm $OPTS /"),
        "대신 uncertain 으로 표시해 승급시킨다"
    );
    for cmd in [
        r#"env r"m" "$OPTS" /"#,
        r#"nice r"m" "$OPTS" /etc"#,
        r#"sudo env A=1 r"m" "$OPTS" /etc"#,
    ] {
        assert!(!caught(cmd), "불투명 플래그를 파괴로 단정: {cmd}");
        assert!(uncertain(cmd), "래퍼 안 rm 불투명 플래그 누락: {cmd}");
    }
}

#[test]
fn opaque_timeout_control_word_is_uncertain() {
    let cmd = r#"timeout "$DURATION" r"m" -rf /etc"#;
    assert!(
        !caught(cmd),
        "불투명 timeout 제어 워드 뒤 명령을 단정하면 안 됨"
    );
    assert!(
        uncertain(cmd),
        "불투명 timeout 제어 워드는 uncertain 이어야 함"
    );

    let known = r#"timeout -s "$SIGNAL" 5 r"m" /etc -rf"#;
    assert!(
        caught(known),
        "위치가 확정된 불투명 옵션 값은 실제 명령 해석을 막으면 안 됨"
    );
}

#[test]
fn non_shell_text_does_not_flood_uncertain() {
    // 임의 산문이 파스 실패한다고 전부 UNKNOWN 이 되면 승급이 무의미해진다.
    assert!(
        !uncertain("이것은 셸 명령이 아니라 그냥 한국어 문장이다"),
        "탐지가 의존하지 않는 파스 에러는 uncertain 이 아니다"
    );
}
