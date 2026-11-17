//! ADAPTER — an external Strata server (github.com/Niko1221/Strata).
//! Strata serves llama.cpp-compatible OpenAI endpoints, so inference reuses the
//! llama adapter; this module only identifies the server and its API key.
use serde_json::Value;

/// What `/health` reports. Strata answers it without the API key.
#[derive(Debug, PartialEq, Eq)]
pub struct Health {
    pub model: String,
    pub max_context: Option<usize>,
    pub needs_key: bool,
}

/// None unless the body is a healthy Strata server (`"service": "strata"`).
pub fn parse_health(body: &Value) -> Option<Health> {
    (body["status"] == "ok" && body["service"] == "strata").then(|| Health {
        model: body["model"].as_str().unwrap_or("strata").to_owned(),
        max_context: body["max_context"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok()),
        needs_key: body["api_key"].as_bool().unwrap_or(false),
    })
}

/// The key Strata's own tools read; sent as a bearer token when set.
pub fn api_key() -> Option<String> {
    std::env::var("STRATA_API_KEY")
        .ok()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_healthy_strata_server_is_recognised() {
        let health = parse_health(&json!({"status":"ok","service":"strata","model":"q36",
            "max_context":32768,"api_key":true,"loaded":false}));
        assert_eq!(
            health,
            Some(Health {
                model: "q36".into(),
                max_context: Some(32768),
                needs_key: true
            })
        );
        assert_eq!(parse_health(&json!({"status":"ok"})), None);
        assert_eq!(
            parse_health(&json!({"status":"loading","service":"strata"})),
            None
        );
        let minimal = parse_health(&json!({"status":"ok","service":"strata"})).unwrap();
        assert_eq!((minimal.max_context, minimal.needs_key), (None, false));
    }
}
