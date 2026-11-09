// TOOLS — usix-companion 브리지(127.0.0.1:8760) 공용 클라이언트.
// 안드로이드는 모든 앱이 같은 loopback 을 공유하므로 포트만으론 호출자를 가릴 수 없다.
// → 앱이 발급한 토큰(~/.usix/companion_token)을 Bearer 헤더로 보내고, 서버가 대조한다.
// 페어링은 `usix-code pair` 1회. 모든 요청에 연결·읽기 타임아웃을 둬 브리지가 멎어도 에이전트가 안 굳는다.
// 앱이 꺼진 사이 다른 앱이 8760 을 차지할 수 있으므로, 토큰을 보내기 전에 매번 상대가
// 토큰을 안다는 증명(HMAC)을 먼저 확인한다 — 토큰 자체는 증명 단계에서 보내지 않는다.
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

pub const PORT: u16 = 8760;

pub fn url(path: &str) -> String {
    format!("http://127.0.0.1:{PORT}{path}")
}

/// 토큰 파일 경로 — ~/.usix/companion_token (skills.rs 와 같은 홈 규약).
pub fn token_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".usix/companion_token")
}

/// 앱이 발급하는 토큰 형식(hex/base64url 계열, 16~128자). 클립보드 잡음을 걸러낸다.
pub fn valid_token(t: &str) -> bool {
    (16..=128).contains(&t.len())
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn load_token() -> Option<String> {
    let raw = std::fs::read_to_string(token_path()).ok()?;
    let t = raw.trim();
    valid_token(t).then(|| t.to_string())
}

/// 토큰 저장 — 소유자만 읽게(0600).
pub fn save_token(t: &str) -> Result<PathBuf> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 쓰기 전에 0600 으로 만든다 — 내용이 umask 권한으로 잠깐이라도 노출되지 않게.
    // 이미 있던 파일은 mode() 가 적용되지 않으므로 권한을 먼저 다시 맞춘다.
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.set_len(0)?;
    file.write_all(format!("{t}\n").as_bytes())?;
    Ok(path)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(20))
        .timeout_write(Duration::from_secs(5))
        .build()
}

const PROOF_PREFIX: &str = "usix-companion-proof-v1:";

/// `/proof` 응답 분류 — 판정은 순수 함수(`check_proof`)가 한다.
enum ProofReply {
    Proof(String),
    /// 증명을 모르는 구버전 앱 — /proof 도 인증 뒤에 라우팅해 401, 또는 404.
    Unsupported,
    Invalid,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn check_proof(token: &str, challenge: &str, reply: ProofReply, legacy: bool) -> Result<()> {
    match reply {
        ProofReply::Proof(proof) => {
            let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
                .map_err(|_| anyhow!("HMAC 키 오류"))?;
            mac.update(format!("{PROOF_PREFIX}{challenge}").as_bytes());
            let ok = hex_decode(&proof).is_some_and(|bytes| mac.verify_slice(&bytes).is_ok());
            ok.then_some(()).ok_or_else(impostor)
        }
        ProofReply::Unsupported if legacy => Ok(()),
        ProofReply::Unsupported => Err(anyhow!(
            "companion 앱이 신원 증명을 지원하지 않는 구버전이라 토큰을 보내지 않았다 — 앱을 업데이트하라. (임시로 USIX_COMPANION_LEGACY_AUTH=1)"
        )),
        ProofReply::Invalid => Err(impostor()),
    }
}

fn impostor() -> anyhow::Error {
    anyhow!("127.0.0.1:{PORT} 의 상대가 페어링된 companion 앱임을 증명하지 못해 토큰을 보내지 않았다 — 다른 앱이 포트를 차지했을 수 있다. companion 앱을 실행하라.")
}

/// 무작위 challenge 를 보내 상대가 토큰을 아는지 확인한다(토큰은 보내지 않는다).
fn verify_companion(token: &str) -> Result<()> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| anyhow!("난수 생성 실패: {e}"))?;
    let challenge: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let reply = match agent()
        .get(&url(&format!("/proof?challenge={challenge}")))
        .call()
    {
        Ok(resp) => resp
            .into_json::<Value>()
            .ok()
            .and_then(|body| body["proof"].as_str().map(str::to_owned))
            .map_or(ProofReply::Invalid, ProofReply::Proof),
        Err(ureq::Error::Status(401 | 404, _)) => ProofReply::Unsupported,
        Err(ureq::Error::Status(..)) => ProofReply::Invalid,
        Err(e) => return Err(bridge_err(e)),
    };
    let legacy = std::env::var("USIX_COMPANION_LEGACY_AUTH").as_deref() == Ok("1");
    check_proof(token, &challenge, reply, legacy)
}

fn with_auth(req: ureq::Request) -> Result<ureq::Request> {
    match load_token() {
        Some(t) => {
            verify_companion(&t)?;
            Ok(req.set("Authorization", &format!("Bearer {t}")))
        }
        None => Ok(req),
    }
}

/// 브리지 오류 → 모델·사용자에게 원인 안내. 401 은 페어링, 503 은 접근성 권한.
pub fn bridge_err(e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(401, _) => anyhow!(
            "companion 토큰 불일치/없음 — 앱에서 '토큰 복사' 후 `usix-code pair` 를 실행하라."
        ),
        ureq::Error::Status(503, _) => anyhow!(
            "접근성 서비스 꺼짐 — usix-companion 앱에서 '접근성(화면 제어)' 권한을 켜라."
        ),
        ureq::Error::Status(404, _) => anyhow!(
            "이 기능을 지원하지 않는 companion 버전 — usix-companion 앱도 함께 업데이트하라."
        ),
        other => anyhow!(
            "companion 브리지 무응답 — usix-companion 앱을 설치·실행하고 필요한 권한(알림 접근/접근성)을 켰는지 확인하라. ({other})"
        ),
    }
}

pub fn get(path: &str) -> Result<Value> {
    let resp = with_auth(agent().get(&url(path)))?
        .call()
        .map_err(bridge_err)?;
    resp.into_json().map_err(|e| anyhow!("응답 파싱 실패: {e}"))
}

pub fn post(path: &str, body: Value) -> Result<Value> {
    let resp = with_auth(agent().post(&url(path)))?
        .send_json(body)
        .map_err(bridge_err)?;
    resp.into_json().map_err(|e| anyhow!("응답 파싱 실패: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format_gate() {
        assert!(valid_token("0123456789abcdef0123456789abcdef"));
        assert!(valid_token("AbC-_0123456789xyz"));
        assert!(!valid_token("short"));
        assert!(!valid_token("has space 0123456789abcdef"));
        assert!(!valid_token("has;semi0123456789abcdef"));
        assert!(!valid_token(&"a".repeat(129)));
    }

    #[test]
    fn proof_check_accepts_only_the_paired_app() {
        let token = "synthetic-test-token";
        let challenge = "0123456789abcdef".repeat(4);
        // Known-answer vector shared with usix-companion's LoopbackBridgeServerTest.
        let good = "498e77767c364bba373090dfff25c93e80bff354d33937691f61003cf61962f8";
        assert!(check_proof(token, &challenge, ProofReply::Proof(good.into()), false).is_ok());
        let forged = good.replacen('4', "5", 1);
        assert!(check_proof(token, &challenge, ProofReply::Proof(forged), true).is_err());
        assert!(check_proof(token, &challenge, ProofReply::Proof("zz".into()), true).is_err());
        assert!(check_proof(token, &challenge, ProofReply::Invalid, true).is_err());
        assert!(check_proof(token, &challenge, ProofReply::Unsupported, true).is_ok());
        let old = check_proof(token, &challenge, ProofReply::Unsupported, false).unwrap_err();
        assert!(old.to_string().contains("USIX_COMPANION_LEGACY_AUTH=1"));
    }
}
