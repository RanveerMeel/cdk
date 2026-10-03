//! Minimal MCP client (stdio transport, JSON-RPC 2.0) used by the gateway to
//! reach real tool servers on behalf of CDK agents.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2025-06-18";
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    pub name: String,
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    pub tools: Vec<String>,
}

pub enum CallOutcome {
    Ok(String),
    ToolError(String),
    Failed(String),
}

impl Server {
    /// Spawn `command` (split on whitespace), initialize, and list tools.
    pub fn start(name: &str, command: &str) -> Result<Self, String> {
        let mut parts = command.split_whitespace();
        let prog = parts.next().ok_or("empty MCP command")?;
        let mut child = Command::new(prog)
            .args(parts)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn {command}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut s = Server {
            name: name.to_string(),
            child,
            stdin,
            lines,
            next_id: 1,
            tools: Vec::new(),
        };
        s.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cdk-gateway", "version": env!("CARGO_PKG_VERSION")},
            }),
        )?;
        s.notify("notifications/initialized")?;
        let list = s.request("tools/list", json!({}))?;
        s.tools = list["tools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(s)
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let mut line = msg.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("write to {}: {e}", self.name))
    }

    fn notify(&mut self, method: &str) -> Result<(), String> {
        self.send(&json!({"jsonrpc": "2.0", "method": method}))
    }

    /// Send a request and wait for the response with the same id.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = self
                .lines
                .recv_timeout(TIMEOUT)
                .map_err(|_| format!("{} did not answer {method}", self.name))?;
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if v["id"].as_u64() != Some(id) {
                continue; // notifications or stale replies
            }
            if let Some(err) = v.get("error") {
                return Err(err["message"].as_str().unwrap_or("error").to_string());
            }
            return Ok(v["result"].clone());
        }
    }

    /// `tools/call`; `args` must be a JSON object.
    pub fn call(&mut self, tool: &str, args: &[u8]) -> CallOutcome {
        let arguments: Value = if args.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(args) {
                Ok(v @ Value::Object(_)) => v,
                _ => return CallOutcome::ToolError("arguments must be a JSON object".into()),
            }
        };
        match self.request("tools/call", json!({"name": tool, "arguments": arguments})) {
            Ok(result) => {
                let text = result["content"]
                    .as_array()
                    .map(|parts| {
                        parts
                            .iter()
                            .filter(|p| p["type"] == "text")
                            .filter_map(|p| p["text"].as_str())
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                if result["isError"].as_bool() == Some(true) {
                    CallOutcome::ToolError(text)
                } else {
                    CallOutcome::Ok(text)
                }
            }
            Err(e) if e.contains("did not answer") => CallOutcome::Failed(e),
            Err(e) => CallOutcome::ToolError(e),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// All configured servers, and which one owns each tool name.
#[derive(Default)]
pub struct Registry {
    pub servers: Vec<Server>,
    owner: HashMap<String, usize>,
}

impl Registry {
    pub fn add(&mut self, server: Server) {
        let idx = self.servers.len();
        for t in &server.tools {
            if self.owner.contains_key(t) {
                eprintln!(
                    "gateway: tool {t} from {} shadowed by an earlier server",
                    server.name
                );
            } else {
                self.owner.insert(t.clone(), idx);
            }
        }
        self.servers.push(server);
    }

    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.owner.keys().cloned().collect();
        names.sort();
        names
    }

    /// Name of the server that provides `tool`.
    pub fn server_of(&self, tool: &str) -> Option<&str> {
        self.owner.get(tool).map(|&i| self.servers[i].name.as_str())
    }

    pub fn call(&mut self, tool: &str, args: &[u8]) -> Option<CallOutcome> {
        let idx = *self.owner.get(tool)?;
        Some(self.servers[idx].call(tool, args))
    }
}
