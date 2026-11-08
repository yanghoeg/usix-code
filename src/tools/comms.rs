// TOOLS — 변경(Mutating). 실행 전 사람 승인 게이트를 거친다.
use crate::adapters::termux;
use crate::ports::{ApprovalClass, Tool};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::process::{Command, Stdio};

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("필수 인자 누락: {key}"))
}

const MAX_REMINDER_MINUTES: i64 = 365 * 24 * 60;

fn invalid_phone_number(number: &str) -> anyhow::Error {
    anyhow!(
        "'{number}' 은 전화번호가 아니다. 지어내지 말고 contacts 도구로 이름을 조회해 실제 번호를 찾은 뒤 다시 호출하라. 없으면 사용자에게 번호를 물어라."
    )
}

pub struct SmsSend;
impl Tool for SmsSend {
    fn name(&self) -> &str {
        "sms_send"
    }
    fn description(&self) -> &str {
        "Send an SMS to a phone number."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "number": { "type": "string", "description": "Recipient phone number" },
                "text": { "type": "string", "description": "Message text" }
            },
            "required": ["number", "text"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn run(&self, args: &Value) -> Result<String> {
        let number = required_str(args, "number")?.trim();
        let text = required_str(args, "text")?;
        if !is_phone_number(number) {
            return Err(invalid_phone_number(number));
        }
        // termux-sms-send 는 번호를 따옴표 없이 펼치므로 공백·구분자를 걷어내고, 본문은
        // stdin 으로 넘겨 '-' 로 시작하는 본문이 옵션으로 읽히거나 echo 가 해석하지 않게 한다.
        let number = normalize_phone_number(number);
        termux::run_with_stdin("termux-sms-send", &["-n", &number], text)?;
        Ok(format!("문자 발송 완료 → {number}"))
    }
}

/// 전화번호 형식 가드 — 숫자/`+`/구분자(`- () 공백`)만 허용하고 숫자 3자리 이상.
/// 모델이 "부인의 전화번호" 같은 문구를 번호 자리에 넣어 오발송하는 것을 막는다.
fn is_phone_number(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    let mut plus_seen = false;
    let ok_chars = s.chars().enumerate().all(|(i, c)| match c {
        '+' if i == 0 && !plus_seen => {
            plus_seen = true;
            true
        }
        '+' => false,
        c => c.is_ascii_digit() || matches!(c, '-' | '(' | ')' | ' '),
    });
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    digits >= 3 && ok_chars
}

/// 형식 검증을 통과한 번호에서 `+`·숫자만 남긴다.
fn normalize_phone_number(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

pub struct Reminder;
impl Tool for Reminder {
    fn name(&self) -> &str {
        "reminder"
    }
    fn description(&self) -> &str {
        "Show a reminder notification after the given minutes."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_REMINDER_MINUTES,
                    "description": "Minutes from now (max 1 year)"
                },
                "text": { "type": "string", "description": "Reminder text" }
            },
            "required": ["minutes", "text"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn run(&self, args: &Value) -> Result<String> {
        let minutes = args
            .get("minutes")
            .and_then(|v| v.as_i64())
            .filter(|m| (1..=MAX_REMINDER_MINUTES).contains(m))
            .ok_or_else(|| {
                anyhow!("필수 인자 누락/오류: minutes (1~{MAX_REMINDER_MINUTES}, 최대 1년)")
            })?;
        let text = required_str(args, "text")?;
        let secs = minutes
            .checked_mul(60)
            .ok_or_else(|| anyhow!("리마인더 시간이 너무 큼"))?
            .to_string();
        // detached 백그라운드로 sleep 후 알림 — $1/$2 positional 로 넘겨 셸 인젝션 차단.
        let mut child = Command::new("sh")
            .args([
                "-c",
                "sleep \"$1\"; termux-notification --title 리마인더 --content \"$2\"",
                "sh",
                &secs,
                text,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("리마인더 예약 실패: {e}"))?;
        // 오래 켜 둔 TUI 에 좀비가 쌓이지 않게 끝나면 회수한다.
        std::thread::spawn(move || child.wait());
        Ok(format!("{minutes}분 뒤 알림 예약됨: {text}"))
    }
}

pub struct Call;
impl Tool for Call {
    fn name(&self) -> &str {
        "call"
    }
    fn description(&self) -> &str {
        "Place a real phone call. Only when the user explicitly asks to call."
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "number": { "type": "string", "description": "Phone number (digits)" }
            },
            "required": ["number"]
        })
    }
    fn approval(&self) -> ApprovalClass {
        ApprovalClass::Mutating
    }
    fn run(&self, args: &Value) -> Result<String> {
        let number = required_str(args, "number")?.trim();
        if !is_phone_number(number) {
            return Err(invalid_phone_number(number));
        }
        termux::run("termux-telephony-call", &[number])?;
        Ok(format!("전화 발신 → {number}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{is_phone_number, normalize_phone_number, Call, Reminder, MAX_REMINDER_MINUTES};
    use crate::ports::Tool;

    #[test]
    fn rejects_non_numbers_accepts_numbers() {
        assert!(!is_phone_number("부인의 전화번호"));
        assert!(!is_phone_number(""));
        assert!(!is_phone_number("+++123"));
        assert!(!is_phone_number("-01012345678"));
        assert!(is_phone_number("01012345678"));
        assert!(is_phone_number("+82 10-1234-5678"));
    }

    #[test]
    fn normalized_number_is_a_single_shell_word() {
        assert_eq!(normalize_phone_number("+82 10-1234-5678"), "+821012345678");
        assert_eq!(normalize_phone_number("(02) 123-4567"), "021234567");
    }

    #[test]
    fn call_rejects_non_numbers_before_running() {
        assert!(Call.run(&serde_json::json!({ "number": "엄마" })).is_err());
    }

    #[test]
    fn reminder_rejects_overflowing_or_too_long_delays() {
        let args = serde_json::json!({ "minutes": i64::MAX, "text": "later" });
        assert!(Reminder.run(&args).is_err());
        let args = serde_json::json!({
            "minutes": MAX_REMINDER_MINUTES + 1,
            "text": "later"
        });
        assert!(Reminder.run(&args).is_err());
    }
}
