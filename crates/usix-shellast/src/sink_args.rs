//! 네트워크 싱크(`curl`·`wget`·nc 계열) argv 해석 — 목적지 호스트 판정과 파일 참조 인자 탐지.
//!
//! This leaf crate (no usix-* dependencies) parses curl/wget arguments itself: URL authority,
//! IPv6 brackets and userinfo. 옵션 표는 흔한 값-취득
//! 옵션만 담는다. 표에 없는 옵션은 값을 안 먹는다고 보는데, 그 값을 목적지 후보로 오독해도
//! `://` 후보가 있으면 무시되고 없으면 호스트처럼 생긴 워드만 본다.

use crate::pipe_flow::Word;

/// 옵션 값의 역할.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Skip,
    /// A local output path, never sent to the destination.
    LocalOutput,
    /// `@file`(`@-` 제외)이면 파일 참조 — curl `-d`·`-H`.
    Data,
    /// `name@file`·`@file` — curl `--data-urlencode`(`=` 가 먼저면 내용).
    UrlEncode,
    /// `name=@file`·`name=<file` — curl `-F`.
    Form,
    /// 값 자체가 올려 보낼 파일(`-` 제외) — curl `-T`, wget `--post-file`.
    Upload,
    /// 값이 목적지(스킴 생략 가능) — curl `--url`·프록시.
    Dest,
    /// 트래픽이 로컬 소켓으로 간다 — 외부 목적지 없음.
    LocalSocket,
}

/// (역할, 단축 옵션 문자들, 공백으로 가른 롱 옵션 이름들).
type OptTable = &'static [(Role, &'static str, &'static str)];

const CURL: OptTable = &[
    (
        Role::LocalOutput,
        "ocD",
        "output output-dir cookie-jar dump-header",
    ),
    (Role::Data, "dH", "data data-binary data-ascii json header"),
    (Role::UrlEncode, "", "data-urlencode"),
    (Role::Form, "F", "form"),
    (Role::Upload, "T", "upload-file"),
    (Role::Dest, "x", "url proxy preproxy"),
    (Role::LocalSocket, "", "unix-socket abstract-unix-socket"),
    (
        Role::Skip,
        "AbCEeKmPQrtuUwXYyz",
        "data-raw form-string user user-agent referer request cookie \
         config max-time connect-timeout retry retry-delay retry-max-time write-out \
         resolve connect-to cacert cert key oauth2-bearer range limit-rate max-filesize \
         interface proxy-user noproxy proto proto-redir variable",
    ),
];

const WGET: OptTable = &[
    (
        Role::LocalOutput,
        "OoaP",
        "output-document output-file append-output directory-prefix",
    ),
    (Role::Upload, "", "post-file body-file"),
    (
        Role::Skip,
        "UeitTwQBlDARIX",
        "user-agent execute \
         input-file tries timeout wait quota base level domains accept reject header user \
         password post-data body-data method referer load-cookies save-cookies ca-certificate \
         certificate private-key limit-rate",
    ),
];

/// nc 계열 공용 — OpenBSD·traditional nc 와 ncat 의 값-취득 옵션 합집합.
const NC: OptTable = &[
    (Role::Dest, "x", "proxy"),
    (
        Role::Skip,
        "ceGgIiMmOoPpqsTVwWX",
        "sh-exec exec lua-exec proxy-type proxy-auth proxy-dns source source-port wait \
         idle-timeout output hex-dump max-conns allow allowfile deny denyfile ssl-cert ssl-key \
         ssl-trustfile ssl-ciphers ssl-servername ssl-alpn delay",
    ),
];

/// 값 없는 nc 계열 플래그 중 목적지를 로컬로 만드는 것 — 수신 대기·유닉스 소켓
/// (단축 문자, 롱 이름).
const NC_LOCAL_FLAGS: (&str, &str) = ("lU", "listen unixsock");

/// 싱크 argv 해석 결과.
#[derive(Debug, Default)]
pub(crate) struct SinkArgs {
    /// 루프백이 아닌 **리터럴로 확정된** 목적지 호스트. 루프백·불투명·부재면 `None`.
    pub(crate) external_host: Option<String>,
    /// 파일 참조 인자(`-d @f` 등)가 있다.
    pub(crate) file_ref: bool,
    /// This transfer reads its process stdin (`@-`, upload `-`, or an nc-family sink).
    pub(crate) stdin_ref: bool,
    /// Arguments that may carry data to the network; known local output paths are excluded.
    pub(crate) flow_args: Vec<Word>,
}

/// `sink` 는 `curl`·`wget` 이거나 nc 계열, `args` 는 싱크 이름 뒤 워드들. curl의
/// `--next` 전송은 각자 목적지와 데이터 원천을 가진 별도 결과로 반환한다.
pub(crate) fn parse(sink: &str, args: &[Word]) -> Vec<SinkArgs> {
    let (table, (local_short, local_long)) = match sink {
        "curl" => (CURL, ("", "")),
        "wget" => (WGET, ("", "")),
        _ => (NC, NC_LOCAL_FLAGS),
    };
    let mut transfers = Vec::new();
    let mut offset = 0;
    loop {
        let group = &args[offset..];
        let mut out = SinkArgs {
            stdin_ref: !matches!(sink, "curl" | "wget"),
            ..SinkArgs::default()
        };
        let mut dests: Vec<Word> = Vec::new();
        let mut positionals: Vec<&Word> = Vec::new();
        let mut local = false;
        let mut options_ended = false;
        let mut flows = vec![true; group.len()];
        let mut group_end = group.len();
        let mut consumed = group.len();
        let mut i = 0;
        while i < group.len() {
            let start = i;
            let w = &group[i];
            i += 1;
            let p = w.prefix.as_str();
            if sink == "curl" && !options_ended && matches!(w.lit.as_deref(), Some("--next" | "-:"))
            {
                group_end = start;
                consumed = i;
                break;
            }
            if options_ended || !p.starts_with('-') || p == "-" {
                positionals.push(w);
                continue;
            }
            if w.lit.as_deref() == Some("--") {
                options_ended = true;
                continue;
            }
            let (role, value) = if let Some(long) = p.strip_prefix("--") {
                let (name, inline) = match long.find('=') {
                    Some(e) => (&long[..e], Some(w.tail(2 + e + 1))),
                    None => (long, None),
                };
                local |= local_long.split_whitespace().any(|l| l == name);
                let Some(role) = role_of(table, |(_, _, longs)| {
                    longs.split_whitespace().any(|l| l == name)
                }) else {
                    continue;
                };
                (role, inline.or_else(|| next_word(group, &mut i)))
            } else {
                let mut found = None;
                for (k, ch) in p[1..].char_indices() {
                    local |= local_short.contains(ch);
                    if let Some(role) = role_of(table, |(_, shorts, _)| shorts.contains(ch)) {
                        found = Some((role, 1 + k + ch.len_utf8()));
                        break;
                    }
                }
                let Some((role, off)) = found else {
                    continue;
                };
                let value = if off < p.len() || w.lit.is_none() {
                    Some(w.tail(off))
                } else {
                    next_word(group, &mut i)
                };
                (role, value)
            };
            let Some(v) = value else {
                continue;
            };
            match role {
                Role::Skip => {}
                Role::LocalOutput => flows[start..i].fill(false),
                Role::Data => {
                    out.stdin_ref |= stdin_marker(&v.prefix, &v, &['@']);
                    out.file_ref |= file_marker(&v.prefix, &v, &['@']);
                }
                Role::UrlEncode => {
                    let at = v.prefix.find('@');
                    let content_first = v
                        .prefix
                        .find('=')
                        .is_some_and(|e| at.is_some_and(|a| e < a));
                    if !content_first {
                        out.stdin_ref |=
                            at.is_some_and(|a| stdin_marker(&v.prefix[a..], &v, &['@']));
                        out.file_ref |= at.is_some_and(|a| file_marker(&v.prefix[a..], &v, &['@']));
                    }
                }
                Role::Form => {
                    if let Some((_, val)) = v.prefix.split_once('=') {
                        out.stdin_ref |= stdin_marker(val, &v, &['@', '<']);
                        out.file_ref |= file_marker(val, &v, &['@', '<']);
                    }
                }
                Role::Upload => {
                    out.stdin_ref |= v.lit.as_deref() == Some("-");
                    out.file_ref |= v.lit.as_deref() != Some("-");
                }
                Role::Dest => dests.push(v),
                Role::LocalSocket => local = true,
            }
        }
        out.flow_args = group[..group_end]
            .iter()
            .zip(&flows[..group_end])
            .filter_map(|(w, flows)| (*flows).then_some(w.clone()))
            .collect();
        if !local {
            let mut candidates: Vec<Dest> = dests.iter().map(url_dest).collect();
            if !matches!(sink, "curl" | "wget") {
                candidates.extend(positionals.first().map(|w| bare_host_dest(w)));
            } else {
                let schemed: Vec<&Word> = positionals
                    .iter()
                    .copied()
                    .filter(|w| w.prefix.contains("://"))
                    .collect();
                let urls = if schemed.is_empty() {
                    positionals.into_iter().filter(|w| hostish(w)).collect()
                } else {
                    schemed
                };
                candidates.extend(urls.into_iter().map(url_dest));
            }
            out.external_host = candidates.into_iter().find_map(|d| match d {
                Dest::External(host) => Some(host),
                Dest::Loopback | Dest::Opaque => None,
            });
        }
        transfers.push(out);
        if consumed >= group.len() {
            break;
        }
        offset += consumed;
    }
    transfers
}

fn stdin_marker(s: &str, whole: &Word, marks: &[char]) -> bool {
    whole.lit.is_some() && s.len() == 2 && s.starts_with(marks) && s.ends_with('-')
}

fn role_of(table: OptTable, hit: impl Fn(&(Role, &str, &str)) -> bool) -> Option<Role> {
    table.iter().find(|e| hit(e)).map(|e| e.0)
}

fn next_word(args: &[Word], i: &mut usize) -> Option<Word> {
    let w = args.get(*i).cloned();
    if w.is_some() {
        *i += 1;
    }
    w
}

/// `s` 가 파일 표식(`@`·`<`)으로 시작하는가 — 워드가 끝까지 리터럴이고 표식 뒤가 `-`(stdin)면 아님.
fn file_marker(s: &str, whole: &Word, marks: &[char]) -> bool {
    s.starts_with(marks) && !(whole.lit.is_some() && s.len() == 2 && s.ends_with('-'))
}

/// 스킴 없는 위치 인자가 호스트처럼 생겼는가. 불투명 워드는 판정 불가라 후보로 둔다.
fn hostish(w: &Word) -> bool {
    w.lit
        .as_deref()
        .is_none_or(|l| l.contains(['.', ':', '/', '[']) || l.eq_ignore_ascii_case("localhost"))
}

enum Dest {
    Loopback,
    External(String),
    Opaque,
}

/// URL(스킴 생략 가능)의 목적지. authority = `://` 뒤부터 첫 `/`·`?`·`#` 까지, 호스트 = 마지막
/// `@` 뒤. 리터럴 접두만 알 때는 authority 가 닫혔거나 포트 구분자까지 보였어야 호스트가
/// 확정된다 — 단 뒤 불투명 조각에 `@` 가 올 수 있으므로 그 경우 루프백 결론은 내지 않는다.
fn url_dest(w: &Word) -> Dest {
    let s = w.prefix.as_str();
    let rest = s.find("://").map_or(s, |i| &s[i + 3..]);
    let (authority, closed) = match rest.find(['/', '?', '#']) {
        Some(end) => (&rest[..end], true),
        None => (rest, w.lit.is_some()),
    };
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if closed {
        return host_dest(split_port(host_port).unwrap_or(host_port));
    }
    match split_port(host_port).map(host_dest) {
        Some(Dest::Loopback) | None => Dest::Opaque,
        Some(d) => d,
    }
}

/// nc 의 호스트 인자 — 워드 전체가 호스트다(`::1` 도 대괄호 없이 온다).
fn bare_host_dest(w: &Word) -> Dest {
    match w.lit.as_deref() {
        Some(l) => host_dest(l.trim_start_matches('[').trim_end_matches(']')),
        None => Dest::Opaque,
    }
}

/// `[v6]:port` → `v6`, `host:port` → `host`. 구분자가 안 보이면 `None`.
fn split_port(host_port: &str) -> Option<&str> {
    if let Some(v6) = host_port.strip_prefix('[') {
        return v6.find(']').map(|end| &v6[..end]);
    }
    host_port.find(':').map(|i| &host_port[..i])
}

fn host_dest(host: &str) -> Dest {
    if host.is_empty() {
        Dest::Opaque
    } else if is_loopback(host) {
        Dest::Loopback
    } else {
        Dest::External(host.to_string())
    }
}

/// `localhost`·`127.0.0.0/8`·`::1`.
fn is_loopback(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1" {
        return true;
    }
    let octets: Vec<&str> = h.split('.').collect();
    octets.len() == 4 && octets[0] == "127" && octets.iter().all(|o| o.parse::<u8>().is_ok())
}
