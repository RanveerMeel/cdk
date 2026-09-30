//! Model backends (roadmap 3.4): OpenAI-compatible chat-completion servers
//! on the Linux host — vLLM, llama.cpp `llama-server`, Ollama, TensorRT-LLM
//! (via its OpenAI frontend) — or a remote API.
//!
//! CDK sees each backend as a tool named `model:<name>` and never handles
//! credentials: the gateway holds each backend's key and adds it
//! (`Authorization: Bearer`) only to requests for that backend's own URL.
//! Keys are read from a mode-0600 file or an environment variable (which is
//! then removed, so MCP servers started later don't inherit it), are never
//! logged, are scrubbed from any text returned to CDK, and are wiped on
//! drop. Redirects are not followed (a redirect could carry the key to
//! another host), no proxy is used, and a key is refused for plaintext
//! `http://` unless the host is loopback.
//!
//! ```text
//! --model NAME=URL[,model=ID][,max-tokens=N][,key-file=PATH][,key-env=VAR]
//! --model qwen=http://127.0.0.1:11434/v1,model=qwen2.5:3b-instruct,max-tokens=256
//! ```

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::mcp::CallOutcome;

/// How long one completion may take. CDK's own limit for model calls is
/// longer, so a slow backend is reported by the gateway.
pub const TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_MAX_TOKENS: u32 = 256;

/// A credential. Never printed, wiped on drop.
pub struct Secret(Zeroizing<String>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

pub struct Backend {
    pub name: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    key: Option<Secret>,
    agent: ureq::Agent,
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("name", &self.name)
            .field("url", &self.base_url)
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("key", &self.key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// `(scheme, host)` of an `http(s)://` URL.
fn scheme_host(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None; // no userinfo: credentials go in the header only
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    Some((scheme, host))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn read_key_file(path: &str) -> Result<Secret, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("key file {path}: {e}"))?;
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "key file {path} must not be readable by group or others (chmod 600)"
        ));
    }
    let text =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("key file {path}: {e}"))?);
    secret(text.trim())
}

fn secret(s: &str) -> Result<Secret, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("key must be non-empty printable ASCII without spaces".into());
    }
    Ok(Secret(Zeroizing::new(s.to_string())))
}

impl Backend {
    /// Parse `NAME=URL[,opt=value]...` (see the module docs).
    pub fn from_spec(spec: &str) -> Result<Self, String> {
        let (name, rest) = spec.split_once('=').ok_or("expected NAME=URL[,options]")?;
        if name.is_empty()
            || name.len() > 26 // CDK object kinds are `model:` + name, ≤ 32 bytes
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(format!(
                "bad model name {name:?} (letters, digits, . _ -; at most 26)"
            ));
        }
        let mut parts = rest.split(',');
        let base_url = parts.next().unwrap_or("").trim_end_matches('/').to_string();
        let (scheme, host) = scheme_host(&base_url).ok_or(format!("bad URL {base_url:?}"))?;
        if scheme != "http" && scheme != "https" {
            return Err(format!("URL must be http:// or https://, not {scheme}://"));
        }
        let plaintext_remote = scheme == "http" && !is_loopback(host);
        let host = host.to_string();
        let mut b = Backend {
            name: name.to_string(),
            model: name.to_string(),
            max_tokens: DEFAULT_MAX_TOKENS,
            key: None,
            agent: ureq::AgentBuilder::new()
                .timeout(TIMEOUT)
                .redirects(0)
                .build(),
            base_url,
        };
        for opt in parts {
            let (k, v) = opt.split_once('=').ok_or(format!("bad option {opt:?}"))?;
            match k {
                "model" => b.model = v.to_string(),
                "max-tokens" => {
                    b.max_tokens = v
                        .parse()
                        .ok()
                        .filter(|n| (1..=8192).contains(n))
                        .ok_or("max-tokens must be 1..=8192")?
                }
                "key-file" => b.key = Some(read_key_file(v)?),
                "key-env" => {
                    let val = Zeroizing::new(
                        std::env::var(v)
                            .map_err(|_| format!("environment variable {v} is not set"))?,
                    );
                    // Don't let MCP servers (started later) inherit it.
                    std::env::remove_var(v);
                    b.key = Some(secret(&val)?);
                }
                _ => return Err(format!("unknown option {k:?}")),
            }
        }
        if b.key.is_some() && plaintext_remote {
            return Err(format!(
                "refusing to send a credential over plaintext http to {host}; use https"
            ));
        }
        Ok(b)
    }

    /// The name CDK sees.
    pub fn tool_name(&self) -> String {
        format!("{}{}", cdk_link::tool::MODEL_PREFIX, self.name)
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn describe(&self) -> String {
        format!(
            "{} -> {} model={} max-tokens={} key={}",
            self.tool_name(),
            self.base_url,
            self.model,
            self.max_tokens,
            if self.has_key() {
                "yes (injected by gateway)"
            } else {
                "none"
            }
        )
    }

    /// Remove the key from text that is about to leave the gateway.
    fn redact(&self, text: String) -> String {
        match &self.key {
            Some(k) if text.contains(k.0.as_str()) => text.replace(k.0.as_str(), "[redacted]"),
            _ => text,
        }
    }

    /// Run one chat completion. `args` is the agent's JSON:
    /// `{"prompt": "...", "system": "...", "max_tokens": N}` (`prompt`
    /// required; `max_tokens` is capped at the backend's limit).
    pub fn call(&self, args: &[u8]) -> CallOutcome {
        let Ok(Value::Object(a)) = serde_json::from_slice::<Value>(args) else {
            return CallOutcome::ToolError("arguments must be a JSON object".into());
        };
        let Some(prompt) = a.get("prompt").and_then(Value::as_str) else {
            return CallOutcome::ToolError("missing \"prompt\" (string)".into());
        };
        let max_tokens = a
            .get("max_tokens")
            .and_then(Value::as_u64)
            .map_or(self.max_tokens, |n| n.min(self.max_tokens as u64) as u32);
        let mut messages = Vec::new();
        if let Some(system) = a.get("system").and_then(Value::as_str) {
            messages.push(json!({"role": "system", "content": system}));
        }
        messages.push(json!({"role": "user", "content": prompt}));
        let body = json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0,
            "stream": false,
        })
        .to_string();

        let mut req = self
            .agent
            .post(&format!("{}/chat/completions", self.base_url))
            .set("Content-Type", "application/json");
        if let Some(k) = &self.key {
            let header = Zeroizing::new(format!("Bearer {}", k.0.as_str()));
            req = req.set("Authorization", &header);
        }
        let outcome = match req.send_string(&body) {
            Ok(resp) if (200..300).contains(&resp.status()) => match resp.into_string() {
                Ok(text) => parse_completion(&text),
                Err(e) => CallOutcome::Failed(format!("reading response: {e}")),
            },
            Ok(resp) => CallOutcome::Failed(format!(
                "HTTP {} from backend (redirects are not followed)",
                resp.status()
            )),
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                CallOutcome::Failed(format!("HTTP {code}: {}", error_message(&text)))
            }
            Err(e) => CallOutcome::Failed(format!("backend unreachable: {e}")),
        };
        match outcome {
            CallOutcome::Ok(t) => CallOutcome::Ok(self.redact(t)),
            CallOutcome::ToolError(t) => CallOutcome::ToolError(self.redact(t)),
            CallOutcome::Failed(t) => CallOutcome::Failed(self.redact(t)),
        }
    }
}

fn error_message(text: &str) -> String {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let msg = v["error"]["message"]
        .as_str()
        .or_else(|| v["error"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| text.chars().take(200).collect());
    msg.chars().take(300).collect()
}

fn parse_completion(text: &str) -> CallOutcome {
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return CallOutcome::Failed("backend returned invalid JSON".into()),
    };
    match v["choices"][0]["message"]["content"].as_str() {
        Some(c) => CallOutcome::Ok(c.to_string()),
        None => CallOutcome::Failed(format!("unexpected response: {}", error_message(text))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    struct Demo {
        child: Child,
        port: u16,
    }

    impl Drop for Demo {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn demo(key: Option<&str>) -> Demo {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/demo_model_server.py");
        let mut cmd = Command::new("python3");
        cmd.arg(script).stdout(Stdio::piped()).stderr(Stdio::null());
        match key {
            Some(k) => cmd.env("DEMO_MODEL_KEY", k),
            None => cmd.env_remove("DEMO_MODEL_KEY"),
        };
        let mut child = cmd.spawn().expect("start demo model server");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line.trim().strip_prefix("port ").unwrap().parse().unwrap();
        Demo { child, port }
    }

    fn key_file(key: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("cdk-gw-key-{}-{mode:o}", std::process::id()));
        std::fs::write(&p, format!("{key}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn text(o: CallOutcome) -> (&'static str, String) {
        match o {
            CallOutcome::Ok(t) => ("ok", t),
            CallOutcome::ToolError(t) => ("tool-error", t),
            CallOutcome::Failed(t) => ("failed", t),
        }
    }

    #[test]
    fn gateway_injects_the_key_and_caps_tokens() {
        let d = demo(Some("s3cret-key"));
        let kf = key_file("s3cret-key", 0o600);
        let b = Backend::from_spec(&format!(
            "demo=http://127.0.0.1:{}/v1,max-tokens=64,key-file={}",
            d.port,
            kf.display()
        ))
        .unwrap();
        assert!(!format!("{b:?}").contains("s3cret"));
        let (k, t) = text(b.call(br#"{"prompt":"hello","max_tokens":10000}"#));
        assert_eq!((k, t.as_str()), ("ok", "You said: hello [max_tokens=64]"));
        assert_eq!(text(b.call(br#"{"text":"no prompt"}"#)).0, "tool-error");
        let (k, t) = text(b.call(br#"{"prompt":"long answer"}"#));
        assert_eq!(k, "ok");
        assert!(t.len() > 3000);
        std::fs::remove_file(kf).unwrap();
    }

    #[test]
    fn missing_or_wrong_key_fails_and_is_never_echoed() {
        let d = demo(Some("right-key"));
        let b = Backend::from_spec(&format!("demo=http://127.0.0.1:{}/v1", d.port)).unwrap();
        let (k, t) = text(b.call(br#"{"prompt":"hi"}"#));
        assert_eq!(k, "failed");
        assert!(t.contains("HTTP 401"), "{t}");

        // The server echoes the credential it got; the gateway must scrub it.
        std::env::set_var("CDK_TEST_WRONG_KEY", "wrong-key-123");
        let b = Backend::from_spec(&format!(
            "demo=http://127.0.0.1:{}/v1,key-env=CDK_TEST_WRONG_KEY",
            d.port
        ))
        .unwrap();
        assert!(
            std::env::var("CDK_TEST_WRONG_KEY").is_err(),
            "key-env is removed from the environment"
        );
        let (k, t) = text(b.call(br#"{"prompt":"hi"}"#));
        assert_eq!(k, "failed");
        assert!(
            t.contains("HTTP 401") && t.contains("[redacted]") && !t.contains("wrong-key-123"),
            "{t}"
        );
    }

    #[test]
    fn redirects_are_not_followed() {
        let d = demo(Some("k"));
        std::env::set_var("CDK_TEST_REDIR_KEY", "k");
        let b = Backend::from_spec(&format!(
            "demo=http://127.0.0.1:{}/redir/v1,key-env=CDK_TEST_REDIR_KEY",
            d.port
        ))
        .unwrap();
        let (k, t) = text(b.call(br#"{"prompt":"hi"}"#));
        assert_eq!(k, "failed");
        assert!(t.contains("302"), "{t}");
    }

    #[test]
    fn unsafe_specs_are_refused() {
        let kf = key_file("k", 0o644);
        let open_file = format!("m=http://127.0.0.1:1/v1,key-file={}", kf.display());
        std::env::set_var("CDK_TEST_REMOTE_KEY", "k");
        for (spec, why) in [
            (
                "m=http://api.example.com/v1,key-env=CDK_TEST_REMOTE_KEY",
                "plaintext",
            ),
            (open_file.as_str(), "chmod 600"),
            ("m=ftp://127.0.0.1/v1", "http"),
            ("m=http://user:pw@127.0.0.1/v1", "bad URL"),
            ("m=http://127.0.0.1/v1,tempo=1", "unknown option"),
            ("m=http://127.0.0.1/v1,max-tokens=0", "max-tokens"),
            ("bad name=http://127.0.0.1/v1", "bad model name"),
            (
                "m=http://127.0.0.1/v1,key-env=CDK_TEST_UNSET_VAR",
                "not set",
            ),
        ] {
            let e = Backend::from_spec(spec).unwrap_err();
            assert!(e.contains(why), "{spec}: {e}");
        }
        std::fs::remove_file(kf).unwrap();
        // Loopback and https are fine.
        assert!(Backend::from_spec("m=http://[::1]:8000/v1").is_ok());
        assert!(Backend::from_spec("m=https://api.example.com/v1,model=x").is_ok());
    }
}
