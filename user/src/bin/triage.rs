//! Fraud-triage agent (fraud-prevention demo, `tools/demo_fraud.sh`).
//!
//! Reads transactions from a queue, scores each with an embedded,
//! integer-only model (`models/fraud-demo.cdklm`, synthetic) plus a simple
//! amount rule, looks up the payee for risky ones, optionally asks the local
//! LLM for a one-line rationale, and raises an alert for the responder.
//!
//! It can only do what its handles allow — granted in this order:
//!   h0 recv  on txn-queue           (customer data)
//!   h1 send  on alerts
//!   h2 exec  on tool:lookup_account
//!   h3 exec  on model:<name>         (optional)
//! It holds no money-moving tool, and policy (`separate customer-data
//! money-movement`) means it can never be granted one: whatever a
//! transaction memo says to the model, the agent cannot act on it.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use cdk_user::ml::{text, Model};
use cdk_user::StrBuf;
use cdk_user::{
    ask_model, cap_list, perm, println, recv, send, tool_call, CapInfo, Error, ToolStatus,
};

static MODEL: &[u8] = include_bytes!("../../models/fraud-demo.cdklm");
/// Rule layer: transfers this large to anyone are high risk regardless of
/// the model (real systems combine rules and models).
const LARGE_AMOUNT: u64 = 250_000;

static mut OUT: [u8; 2048] = [0; 2048];

struct Txn<'a> {
    id: &'a str,
    amount: u64,
    from: &'a str,
    to: &'a str,
}

/// `TXN <id> INR <amount> acct <from>-><to> <memo...>`
fn parse(t: &str) -> Option<Txn<'_>> {
    let mut w = t.split_whitespace();
    if w.next()? != "TXN" {
        return None;
    }
    let id = w.next()?;
    if w.next()? != "INR" {
        return None;
    }
    let amount = w.next()?.parse().ok()?;
    if w.next()? != "acct" {
        return None;
    }
    let (from, to) = w.next()?.split_once("->")?;
    let ok =
        |s: &str| !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_alphanumeric());
    (ok(id) && ok(from) && ok(to)).then_some(Txn {
        id,
        amount,
        from,
        to,
    })
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let Ok(model) = Model::parse(MODEL) else {
        println!("triage: bad model");
        return 3;
    };
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0).min(caps.len());
    let caps = &caps[..n];
    let queue = caps
        .iter()
        .find(|c| c.perms & perm::RECV != 0)
        .map(|c| c.handle);
    let alerts = caps
        .iter()
        .find(|c| c.perms & perm::SEND != 0)
        .map(|c| c.handle);
    let mut exec = caps
        .iter()
        .filter(|c| c.perms & perm::EXEC != 0)
        .map(|c| c.handle);
    let (lookup, llm) = (exec.next(), exec.next());
    let (Some(queue), Some(alerts)) = (queue, alerts) else {
        println!("triage: needs recv on the transaction queue and send on alerts");
        return 2;
    };
    println!(
        "triage: model {} features, lookup {}, LLM {}",
        model.n_features(),
        if lookup.is_some() { "yes" } else { "no" },
        if llm.is_some() { "yes" } else { "no" }
    );
    // SAFETY: single-threaded; the only reference.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut buf = [0u8; 64];
    let (mut seen, mut flagged) = (0, 0);
    loop {
        let len = match recv(queue, &mut buf) {
            Ok(n) => n,
            Err(Error::Empty) => break,
            Err(e) => {
                println!("triage: recv failed: {:?}", e);
                return 1;
            }
        };
        let Ok(line) = core::str::from_utf8(&buf[..len]) else {
            continue;
        };
        seen += 1;
        let Some(t) = parse(line) else {
            println!("triage: unparseable transaction skipped");
            continue;
        };
        let mut x = [0u8; 128];
        let x = &mut x[..model.n_features()];
        text::hashed_trigrams(line.as_bytes(), x);
        let c = model.classify(x).unwrap();
        let by_model = model.label(c.class) == "HIGH";
        let by_rule = t.amount >= LARGE_AMOUNT;
        if !(by_model || by_rule) {
            println!(
                "triage: TXN {} INR {} -> LOW (model LOW, margin {})",
                t.id, t.amount, c.margin
            );
            continue;
        }
        flagged += 1;
        println!(
            "triage: TXN {} INR {} -> HIGH ({}{})",
            t.id,
            t.amount,
            if by_model { "model HIGH" } else { "model LOW" },
            if by_rule { ", large-amount rule" } else { "" }
        );
        if let Some(h) = lookup {
            let mut args: StrBuf<64> = StrBuf::new();
            let _ = write!(args, "{{\"account\":\"{}\"}}", t.to);
            match tool_call(h, args.as_bytes(), out) {
                Ok((ToolStatus::Ok, n)) => println!(
                    "triage:   payee {}",
                    core::str::from_utf8(&out[..n]).unwrap_or("?")
                ),
                Ok((st, _)) => println!("triage:   payee lookup: {:?}", st),
                Err(e) => println!("triage:   payee lookup failed: {:?}", e),
            }
        }
        if let Some(h) = llm {
            let mut prompt: StrBuf<256> = StrBuf::new();
            let _ = write!(
                prompt,
                "Transaction: {line}. In one short sentence, why could this be fraud?"
            );
            match ask_model(
                h,
                Some("You are a bank fraud analyst. Answer in one sentence."),
                prompt.as_str(),
                60,
                out,
            ) {
                Ok((_, n)) => {
                    let s = core::str::from_utf8(&out[..n]).unwrap_or("?");
                    println!("triage:   LLM: {}", s.lines().next().unwrap_or(""));
                }
                Err(e) => println!("triage:   LLM unavailable: {:?}", e),
            }
        }
        let mut alert: StrBuf<64> = StrBuf::new();
        let _ = write!(alert, "ALERT {} {} {} {}", t.id, t.to, t.from, t.amount);
        match send(alerts, alert.as_bytes()) {
            Ok(()) => println!("triage:   alert raised: {}", alert),
            Err(e) => println!("triage:   alert failed: {:?}", e),
        }
    }
    println!("triage: {} transaction(s), {} flagged", seen, flagged);
    0
}
