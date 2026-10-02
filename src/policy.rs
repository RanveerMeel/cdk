//! Policy change review (roadmap 2.9).
//!
//! Every change that could widen what an agent can reach is shown as a
//! *reach diff*, checked against the policy's invariants, and applied only
//! after the operator approves it:
//!
//! * **grants** — `grant`, `exec <prog> <obj> <perms>`, or a staged batch
//!   (`policy begin` … `policy commit`);
//! * **policy edits** — rules and labels (`policy rule …`, `policy label …`);
//! * **gateway changes** — a new tool or model, or a changed one (gained a
//!   credential, moved to another host), seen at `tools-sync`; see
//!   [`crate::tools`]. Until approved, calls to it are blocked.
//!
//! `cap_derive` needs no review: it can only attenuate (same object, fewer
//! permissions, the approval constraint kept), so every invariant below that
//! holds before a derivation holds after it.
//!
//! ## Labels and rules
//!
//! Objects carry automatic labels — `tool`, `model`, and from the gateway's
//! listing `credential` (the gateway adds a key) and `remote` (requests leave
//! the machine) — plus labels the operator attaches to an object id or kind
//! (`label obj-2 customer-data`). Rules are invariants over all agents'
//! handles:
//!
//! | rule | violated when |
//! |---|---|
//! | `deny <l>` | any agent holds any handle on an `<l>` object |
//! | `separate <a> <b>` | one agent holds handles reaching both `<a>` and `<b>` |
//! | `approval <l>` | a handle with an effect (`exec`, `send`, `write`, `delete`) on an `<l>` object lacks the approval constraint |
//!
//! A change that would violate a rule is refused outright (it cannot be
//! approved). The boot policy is loaded from `policy.rules` in the ramdisk;
//! if that file is malformed the kernel fails closed and refuses every
//! change. Decisions are audit-logged (`policy-applied` with the first 8
//! bytes of the SHA-256 of the reviewed diff, `policy-refused` with a
//! reason).

extern crate alloc;

use core::fmt::{self, Write as _};

use heapless::{String, Vec};
use sha2::{Digest, Sha256};
use spin::Mutex;

use crate::audit::{self, EventKind};
use crate::capability::Permission;

pub const MAX_LABEL: usize = 24;
pub const MAX_RULES: usize = 16;
pub const MAX_LABELS: usize = 32;

/// Ramdisk file with the boot policy.
pub const POLICY_FILE: &str = "policy.rules";

pub type Label = String<MAX_LABEL>;

/// `detail` codes for [`EventKind::PolicyRefused`].
pub mod refuse_reason {
    /// The operator declined.
    pub const DECLINED: u64 = 1;
    /// The change would violate a rule.
    pub const VIOLATION: u64 = 2;
    /// A call to a tool whose (changed) listing was not approved.
    pub const UNREVIEWED_TOOL: u64 = 3;
    /// The boot policy file is malformed; every change is refused.
    pub const POLICY_BROKEN: u64 = 4;
}

const fn bit(p: Permission) -> u64 {
    1u64 << (match p {
        Permission::Read => 1,
        Permission::Write => 2,
        Permission::Execute => 3,
        Permission::SendMessage => 4,
        Permission::ReceiveMessage => 5,
        Permission::Delete => 6,
        Permission::RequiresApproval => 7,
    })
}

/// Permissions that make something happen (as opposed to observing).
pub const EFFECT_MASK: u64 = bit(Permission::Execute)
    | bit(Permission::SendMessage)
    | bit(Permission::Write)
    | bit(Permission::Delete);
pub const APPROVAL: u64 = bit(Permission::RequiresApproval);

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rule {
    Deny(Label),
    Separate(Label, Label),
    Approval(Label),
}

fn label(s: &str) -> Result<Label, &'static str> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err("labels use letters, digits, - _ . :");
    }
    String::try_from(s).map_err(|_| "label too long (max 24)")
}

impl Rule {
    /// `deny <l>` | `separate <a> <b>` | `approval <l>`.
    pub fn parse(s: &str) -> Result<Rule, &'static str> {
        let mut w = s.split_whitespace();
        let rule = match (w.next(), w.next(), w.next()) {
            (Some("deny"), Some(l), None) => Rule::Deny(label(l)?),
            (Some("approval"), Some(l), None) => Rule::Approval(label(l)?),
            (Some("separate"), Some(a), Some(b)) if a != b => Rule::Separate(label(a)?, label(b)?),
            _ => return Err("rules: deny <label> | separate <a> <b> | approval <label>"),
        };
        if w.next().is_some() {
            return Err("too many words");
        }
        Ok(rule)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Deny(l) => write!(f, "deny {l}"),
            Rule::Separate(a, b) => write!(f, "separate {a} {b}"),
            Rule::Approval(l) => write!(f, "approval {l}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Grants, labels, violations, diffs (pure logic)
// ---------------------------------------------------------------------------

/// A capability an agent holds (or would hold), as policy sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub pid: u32,
    pub object: String<16>,
    pub kind: String<32>,
    /// Gateway flags of the object (`cdk_link::tool::FLAG_*`), 0 otherwise.
    pub flags: u8,
    pub mask: u64,
}

impl Grant {
    pub fn new(pid: u32, object: &str, kind: &str, flags: u8, mask: u64) -> Self {
        let mut o = String::new();
        let _ = o.push_str(&object[..object.len().min(16)]);
        let mut k = String::new();
        let _ = k.push_str(&kind[..kind.len().min(32)]);
        Grant {
            pid,
            object: o,
            kind: k,
            flags,
            mask,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Denied {
        pid: u32,
        object: String<16>,
        label: Label,
    },
    Separated {
        pid: u32,
        a: Label,
        b: Label,
    },
    NeedsApproval {
        pid: u32,
        object: String<16>,
        label: Label,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::Denied { pid, object, label } => {
                write!(f, "pid {pid} would reach {object}, labelled '{label}' (rule: deny {label})")
            }
            Violation::Separated { pid, a, b } => {
                write!(f, "pid {pid} would reach both '{a}' and '{b}' (rule: separate {a} {b})")
            }
            Violation::NeedsApproval { pid, object, label } => write!(
                f,
                "pid {pid} would act on {object} ('{label}') without human approval (rule: approval {label})"
            ),
        }
    }
}

/// One line of a reach diff: what `pid` gains on `object`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub pid: u32,
    pub object: String<16>,
    pub kind: String<32>,
    pub flags: u8,
    /// Permissions gained (bits not held before on this object).
    pub added: u64,
    /// The resulting handle is approval-gated.
    pub gated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub rules: Vec<Rule, MAX_RULES>,
    /// `(object id or kind, label)`.
    pub labels: Vec<(String<32>, Label), MAX_LABELS>,
}

impl Policy {
    pub const fn new() -> Self {
        Policy {
            rules: Vec::new(),
            labels: Vec::new(),
        }
    }

    /// Automatic and operator labels of an object.
    pub fn labels_of(&self, object: &str, kind: &str, flags: u8) -> Vec<Label, 12> {
        let mut out: Vec<Label, 12> = Vec::new();
        let mut add = |l: &str| {
            if !out.iter().any(|x| x == l) {
                if let Ok(l) = String::try_from(l) {
                    let _ = out.push(l);
                }
            }
        };
        if kind.starts_with(crate::tools::KIND_PREFIX) {
            add("tool");
        }
        if kind.starts_with(cdk_link::tool::MODEL_PREFIX) {
            add("model");
        }
        if flags & cdk_link::tool::FLAG_CREDENTIAL != 0 {
            add("credential");
        }
        if flags & cdk_link::tool::FLAG_REMOTE != 0 {
            add("remote");
        }
        for (sel, l) in &self.labels {
            if sel == object || sel == kind {
                add(l);
            }
        }
        out
    }

    fn has(&self, g: &Grant, l: &str) -> bool {
        self.labels_of(&g.object, &g.kind, g.flags)
            .iter()
            .any(|x| x == l)
    }

    /// Every rule violation in `grants` (all agents' handles).
    pub fn violations(&self, grants: &[Grant]) -> alloc::vec::Vec<Violation> {
        let mut out = alloc::vec::Vec::new();
        for rule in &self.rules {
            match rule {
                Rule::Deny(l) => {
                    for g in grants.iter().filter(|g| g.mask != 0 && self.has(g, l)) {
                        out.push(Violation::Denied {
                            pid: g.pid,
                            object: g.object.clone(),
                            label: l.clone(),
                        });
                    }
                }
                Rule::Approval(l) => {
                    for g in grants.iter().filter(|g| {
                        g.mask & EFFECT_MASK != 0 && g.mask & APPROVAL == 0 && self.has(g, l)
                    }) {
                        out.push(Violation::NeedsApproval {
                            pid: g.pid,
                            object: g.object.clone(),
                            label: l.clone(),
                        });
                    }
                }
                Rule::Separate(a, b) => {
                    let mut pids: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
                    for g in grants {
                        if !pids.contains(&g.pid) {
                            pids.push(g.pid);
                        }
                    }
                    for pid in pids {
                        let mine = || grants.iter().filter(move |g| g.pid == pid && g.mask != 0);
                        if mine().any(|g| self.has(g, a)) && mine().any(|g| self.has(g, b)) {
                            out.push(Violation::Separated {
                                pid,
                                a: a.clone(),
                                b: b.clone(),
                            });
                        }
                    }
                }
            }
        }
        out
    }

    /// Parse a policy file: rules and `label <object-or-kind> <label>`
    /// lines; `#` starts a comment. Errors carry the 1-based line number.
    pub fn parse(text: &str) -> Result<Policy, (usize, &'static str)> {
        let mut p = Policy::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let e = |m| (i + 1, m);
            if let Some(rest) = line.strip_prefix("label ") {
                let mut w = rest.split_whitespace();
                let (Some(sel), Some(l), None) = (w.next(), w.next(), w.next()) else {
                    return Err(e("label <object-or-kind> <label>"));
                };
                p.add_label(sel, l).map_err(e)?;
            } else {
                let rule = Rule::parse(line).map_err(e)?;
                p.add_rule(rule).map_err(e)?;
            }
        }
        Ok(p)
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<(), &'static str> {
        if self.rules.contains(&rule) {
            return Err("rule already present");
        }
        self.rules.push(rule).map_err(|_| "too many rules")
    }

    pub fn add_label(&mut self, selector: &str, l: &str) -> Result<(), &'static str> {
        let sel: String<32> = String::try_from(selector).map_err(|_| "object selector too long")?;
        let l = label(l)?;
        if self.labels.iter().any(|(s, x)| *s == sel && *x == l) {
            return Err("label already present");
        }
        self.labels.push((sel, l)).map_err(|_| "too many labels")
    }

    pub fn remove_label(&mut self, selector: &str, l: &str) -> Result<(), &'static str> {
        let pos = self
            .labels
            .iter()
            .position(|(s, x)| s == selector && x == l)
            .ok_or("no such label")?;
        self.labels.remove(pos);
        Ok(())
    }
}

/// What `after` grants beyond `before`, per (pid, object).
pub fn diff(before: &[Grant], after: &[Grant]) -> alloc::vec::Vec<Change> {
    let union = |set: &[Grant], pid: u32, obj: &str| {
        set.iter()
            .filter(|g| g.pid == pid && g.object == obj)
            .fold(0u64, |m, g| m | g.mask)
    };
    let mut out: alloc::vec::Vec<Change> = alloc::vec::Vec::new();
    for g in after {
        if out.iter().any(|c| c.pid == g.pid && c.object == g.object) {
            continue;
        }
        let now = union(after, g.pid, &g.object);
        let added = now & !union(before, g.pid, &g.object) & !APPROVAL;
        // An ungated handle where only gated ones existed is also new reach.
        let ungated_now = after.iter().any(|x| {
            x.pid == g.pid
                && x.object == g.object
                && x.mask & APPROVAL == 0
                && x.mask & EFFECT_MASK != 0
        });
        let ungated_before = before.iter().any(|x| {
            x.pid == g.pid
                && x.object == g.object
                && x.mask & APPROVAL == 0
                && x.mask & EFFECT_MASK != 0
        });
        if added != 0 || (ungated_now && !ungated_before) {
            out.push(Change {
                pid: g.pid,
                object: g.object.clone(),
                kind: g.kind.clone(),
                flags: g.flags,
                added: if added != 0 { added } else { now & EFFECT_MASK },
                gated: !ungated_now,
            });
        }
    }
    out
}

/// First 8 bytes (big-endian) of the SHA-256 of the reviewed text.
pub fn digest(text: &str) -> u64 {
    let d = Sha256::digest(text.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b)
}

// ---------------------------------------------------------------------------
// Kernel state and review flow
// ---------------------------------------------------------------------------

struct State {
    policy: Policy,
    /// Prompt the operator before applying (off = lab mode: rules are still
    /// enforced and changes still audited).
    review: bool,
    /// The boot policy file was malformed: refuse every change.
    broken: bool,
    loaded: bool,
    /// Grants staged by `policy begin` (pid, object ref, perms).
    staged: Option<Vec<(u32, String<32>, String<48>), 16>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    policy: Policy::new(),
    review: true,
    broken: false,
    loaded: false,
    staged: None,
});

/// Load `policy.rules` from the ramdisk (once). A malformed file makes the
/// kernel refuse every policy change until reboot.
pub fn load_boot_policy() {
    let mut st = STATE.lock();
    if st.loaded {
        return;
    }
    st.loaded = true;
    let Some(file) = crate::initrd::find(POLICY_FILE) else {
        return; // no boot policy: no rules, review still on
    };
    let d = Sha256::digest(file.data);
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    let parsed = core::str::from_utf8(file.data)
        .map_err(|_| (0, "not UTF-8"))
        .and_then(Policy::parse);
    match parsed {
        Ok(p) => {
            crate::println!(
                "policy: loaded {} ({} rule(s), {} label(s))",
                POLICY_FILE,
                p.rules.len(),
                p.labels.len()
            );
            st.policy = p;
            drop(st);
            audit::record(
                EventKind::PolicyApplied,
                "boot:policy.rules",
                u64::from_be_bytes(b),
            );
        }
        Err((line, why)) => {
            crate::println!(
                "policy: {} line {}: {} — refusing all policy changes",
                POLICY_FILE,
                line,
                why
            );
            st.broken = true;
            drop(st);
            audit::record(
                EventKind::PolicyRefused,
                "boot:policy.rules",
                refuse_reason::POLICY_BROKEN,
            );
        }
    }
}

pub fn policy() -> Policy {
    load_boot_policy();
    STATE.lock().policy.clone()
}

pub fn review_enabled() -> bool {
    STATE.lock().review
}

pub fn is_broken() -> bool {
    STATE.lock().broken
}

/// Every handle every agent holds now.
pub fn current_grants(kernel: &crate::kernel::Kernel) -> alloc::vec::Vec<Grant> {
    let mut out = alloc::vec::Vec::new();
    crate::agent::for_each_cap(|pid, cap| {
        let kind = kernel
            .for_each_object_find(&cap.object_id)
            .map(|o| o.kind.as_str())
            .unwrap_or("");
        let flags = crate::tools::pinned_flags(kind);
        out.push(Grant::new(
            pid,
            &cap.object_id,
            kind,
            flags,
            cap.permission_mask(),
        ));
    });
    out
}

fn proc_name(pid: u32) -> String<16> {
    let mut s = String::new();
    if let Some(n) = crate::process::name_of(pid) {
        let _ = s.push_str(&n.as_str()[..n.as_str().len().min(16)]);
    }
    s
}

/// Render one change as a line: `+ pid 1 'x' gains exec on ...` (or with
/// another verb, e.g. `holds` for a reach listing, without the `+`).
pub fn render_change(
    c: &Change,
    policy: &Policy,
    verb: &str,
    out: &mut impl fmt::Write,
) -> fmt::Result {
    write!(
        out,
        "{}pid {} '{}' {} {} on {} ({})",
        if verb == "gains" { "+ " } else { "" },
        c.pid,
        proc_name(c.pid),
        verb,
        crate::agent::permission_names(c.added),
        c.object,
        c.kind
    )?;
    let labels = policy.labels_of(&c.object, &c.kind, c.flags);
    if !labels.is_empty() {
        out.write_str(" [")?;
        for (i, l) in labels.iter().enumerate() {
            if i > 0 {
                out.write_str(",")?;
            }
            out.write_str(l)?;
        }
        out.write_str("]")?;
    }
    if let Some(ep) = crate::tools::pinned_endpoint(&c.kind) {
        write!(out, " via {ep}")?;
    }
    out.write_str(if c.added & EFFECT_MASK == 0 {
        ", observe only"
    } else if c.gated {
        ", human-gated"
    } else {
        ", NOT gated"
    })
}

/// Ask the operator (unless review is off). Prints the prompt.
pub fn confirm(question: &str) -> bool {
    if !review_enabled() {
        crate::println!("{} [review off: applied]", question);
        return true;
    }
    crate::print!("{} [y/N] ", question);
    crate::agent::read_decision()
}

/// Review adding `proposed` to the current grants. Prints the diff and any
/// violations, asks the operator, audits the decision. Returns whether the
/// grants may be applied.
pub fn review_grants(kernel: &crate::kernel::Kernel, proposed: &[Grant]) -> bool {
    load_boot_policy();
    if is_broken() {
        crate::println!("policy: refused — the boot policy is malformed");
        audit::record(
            EventKind::PolicyRefused,
            "grant",
            refuse_reason::POLICY_BROKEN,
        );
        return false;
    }
    let policy = policy();
    let before = current_grants(kernel);
    let mut after = before.clone();
    after.extend_from_slice(proposed);
    let changes = diff(&before, &after);
    let mut text = alloc::string::String::new();
    crate::println!("=== POLICY CHANGE REVIEW ===");
    if changes.is_empty() {
        crate::println!("  (no new reach: every permission is already held)");
    }
    for c in &changes {
        let mut line: String<256> = String::new();
        let _ = render_change(c, &policy, "gains", &mut line);
        crate::println!("  {}", line);
        let _ = writeln!(text, "{line}");
    }
    let violations = policy.violations(&after);
    let fresh: alloc::vec::Vec<&Violation> = {
        let old = policy.violations(&before);
        violations.iter().filter(|v| !old.contains(v)).collect()
    };
    let subject = |out: &mut String<48>| {
        let _ = write!(out, "grant:{}-change(s)", changes.len());
    };
    let mut subj: String<48> = String::new();
    subject(&mut subj);
    if !fresh.is_empty() {
        for v in &fresh {
            crate::println!("  ! VIOLATION: {}", v);
        }
        crate::println!("policy: refused (fix the request or the policy)");
        audit::record(EventKind::PolicyRefused, &subj, refuse_reason::VIOLATION);
        return false;
    }
    if !confirm("Apply this policy change?") {
        crate::println!("policy: declined");
        audit::record(EventKind::PolicyRefused, &subj, refuse_reason::DECLINED);
        return false;
    }
    audit::record(EventKind::PolicyApplied, &subj, digest(&text));
    true
}

/// A change to the policy itself.
pub enum Edit<'a> {
    AddRule(Rule),
    RemoveRule(usize),
    AddLabel(&'a str, &'a str),
    RemoveLabel(&'a str, &'a str),
}

/// Review and apply a policy edit. Tightening edits that the current
/// handles already violate are refused (drop or reap those handles first).
pub fn edit(kernel: &crate::kernel::Kernel, e: Edit<'_>) -> Result<(), &'static str> {
    load_boot_policy();
    if is_broken() {
        return Err("the boot policy is malformed");
    }
    let mut candidate = policy();
    let mut text: String<96> = String::new();
    match &e {
        Edit::AddRule(r) => {
            candidate.add_rule(r.clone())?;
            let _ = write!(text, "+ rule: {r}");
        }
        Edit::RemoveRule(i) => {
            if *i >= candidate.rules.len() {
                return Err("no such rule");
            }
            let r = candidate.rules.remove(*i);
            let _ = write!(text, "- rule: {r} (loosens policy)");
        }
        Edit::AddLabel(sel, l) => {
            candidate.add_label(sel, l)?;
            let _ = write!(text, "+ label: {sel} {l}");
        }
        Edit::RemoveLabel(sel, l) => {
            candidate.remove_label(sel, l)?;
            let _ = write!(text, "- label: {sel} {l} (may loosen policy)");
        }
    }
    crate::println!("=== POLICY CHANGE REVIEW ===");
    crate::println!("  {}", text);
    let mut subj: String<48> = String::new();
    let _ = write!(subj, "{}", &text[..text.len().min(48)]);
    let violations = candidate.violations(&current_grants(kernel));
    if !violations.is_empty() {
        for v in &violations {
            crate::println!("  ! VIOLATION (existing handle): {}", v);
        }
        audit::record(EventKind::PolicyRefused, &subj, refuse_reason::VIOLATION);
        return Err("current handles violate the new policy");
    }
    if !confirm("Apply this policy change?") {
        audit::record(EventKind::PolicyRefused, &subj, refuse_reason::DECLINED);
        return Err("declined");
    }
    STATE.lock().policy = candidate;
    audit::record(EventKind::PolicyApplied, &subj, digest(&text));
    crate::println!("policy: applied");
    Ok(())
}

/// Turn the operator prompt on or off (rules stay enforced either way).
pub fn set_review(on: bool) {
    STATE.lock().review = on;
    let what = if on { "review:on" } else { "review:off" };
    audit::record(EventKind::PolicyApplied, what, digest(what));
}

// --- staged batches -------------------------------------------------------

pub fn begin() -> Result<(), &'static str> {
    let mut st = STATE.lock();
    if st.staged.is_some() {
        return Err("a batch is already open (policy commit / policy abort)");
    }
    st.staged = Some(Vec::new());
    Ok(())
}

pub fn is_staging() -> bool {
    STATE.lock().staged.is_some()
}

/// Stage a grant while a batch is open.
pub fn stage(pid: u32, object: &str, perms: &str) -> Result<usize, &'static str> {
    let mut st = STATE.lock();
    let batch = st.staged.as_mut().ok_or("no open batch")?;
    let o = String::try_from(object).map_err(|_| "object reference too long")?;
    let p = String::try_from(perms).map_err(|_| "permissions too long")?;
    batch.push((pid, o, p)).map_err(|_| "batch full (16)")?;
    Ok(batch.len())
}

/// Take the open batch (for commit, diff, or abort).
pub fn take_batch() -> Option<Vec<(u32, String<32>, String<48>), 16>> {
    STATE.lock().staged.take()
}

pub fn peek_batch(mut f: impl FnMut(u32, &str, &str)) {
    if let Some(b) = STATE.lock().staged.as_ref() {
        for (pid, o, p) in b {
            f(*pid, o, p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_link::tool::{FLAG_CREDENTIAL, FLAG_REMOTE};

    const EXEC: u64 = bit(Permission::Execute);
    const RECV: u64 = bit(Permission::ReceiveMessage);
    const SEND: u64 = bit(Permission::SendMessage);

    fn g(pid: u32, obj: &str, kind: &str, flags: u8, mask: u64) -> Grant {
        Grant::new(pid, obj, kind, flags, mask)
    }

    fn policy(text: &str) -> Policy {
        Policy::parse(text).unwrap()
    }

    #[test]
    fn parses_rules_and_labels() {
        let p = policy("# boot policy\napproval credential\n\nseparate customer-data remote # x\nlabel obj-2 customer-data\ndeny model:untrusted\n");
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[1].to_string(), "separate customer-data remote");
        assert_eq!(p.labels.len(), 1);
        for (bad, line) in [
            ("approval\n", 1),
            ("ok\n", 1),
            ("deny a\nseparate x x\n", 2),
            ("deny a b\n", 1),
            ("label obj-2\n", 1),
            ("deny bad label!\n", 1),
            ("deny a\ndeny a\n", 2),
        ] {
            assert_eq!(Policy::parse(bad).unwrap_err().0, line, "{bad:?}");
        }
    }

    #[test]
    fn automatic_and_operator_labels() {
        let p = policy("label obj-2 customer-data\nlabel model:qwen local-llm\n");
        let l = p.labels_of("obj-9", "model:qwen", FLAG_CREDENTIAL | FLAG_REMOTE);
        assert_eq!(l, ["model", "credential", "remote", "local-llm"]);
        assert_eq!(p.labels_of("obj-4", "tool:echo", 0), ["tool"]);
        assert_eq!(p.labels_of("obj-2", "agent-inbox", 0), ["customer-data"]);
    }

    #[test]
    fn rules_find_violations() {
        let p = policy("deny remote\nseparate customer-data tool\napproval credential\nlabel obj-2 customer-data\n");
        let ok = [
            g(1, "obj-2", "inbox", 0, RECV),
            g(2, "obj-4", "tool:echo", 0, EXEC),
            g(3, "obj-8", "model:paid", FLAG_CREDENTIAL, EXEC | APPROVAL),
            g(3, "obj-8", "model:paid", FLAG_CREDENTIAL, RECV), // no effect
        ];
        assert!(p.violations(&ok).is_empty());

        let v = p.violations(&[g(1, "obj-9", "model:far", FLAG_REMOTE, RECV)]);
        assert!(matches!(&v[..], [Violation::Denied { pid: 1, .. }]));

        let v = p.violations(&[
            g(1, "obj-2", "inbox", 0, RECV),
            g(1, "obj-4", "tool:echo", 0, EXEC),
        ]);
        assert!(matches!(&v[..], [Violation::Separated { pid: 1, .. }]));
        // The same two objects held by different agents are fine.
        assert!(p
            .violations(&[
                g(1, "obj-2", "inbox", 0, RECV),
                g(2, "obj-4", "tool:echo", 0, EXEC)
            ])
            .is_empty());

        let v = p.violations(&[g(3, "obj-8", "model:paid", FLAG_CREDENTIAL, EXEC)]);
        assert!(matches!(&v[..], [Violation::NeedsApproval { pid: 3, .. }]));
    }

    #[test]
    fn attenuation_never_creates_violations() {
        // cap_derive keeps the object and approval bit and drops permissions:
        // for every rule, a subset of a compliant grant set is compliant.
        let p = policy("separate customer-data tool\napproval tool\nlabel obj-2 customer-data\n");
        let held = [g(1, "obj-4", "tool:echo", 0, EXEC | SEND | APPROVAL)];
        assert!(p.violations(&held).is_empty());
        for mask in [EXEC | APPROVAL, SEND | APPROVAL, APPROVAL] {
            let mut after = held.to_vec();
            after.push(g(1, "obj-4", "tool:echo", 0, mask));
            assert!(p.violations(&after).is_empty());
        }
    }

    #[test]
    fn diff_shows_only_new_reach() {
        let before = [g(1, "obj-4", "tool:echo", 0, EXEC | APPROVAL)];
        // Same permission again: nothing new.
        assert!(diff(&before, &[before[0].clone(), before[0].clone()]).is_empty());
        // An ungated handle where only a gated one existed is new reach.
        let mut after = before.to_vec();
        after.push(g(1, "obj-4", "tool:echo", 0, EXEC));
        let d = diff(&before, &after);
        assert_eq!(d.len(), 1);
        assert!(!d[0].gated);
        assert_eq!(d[0].added, EXEC);
        // New object, new pid.
        let mut after = before.to_vec();
        after.push(g(2, "obj-8", "model:q", 0, EXEC | RECV | APPROVAL));
        let d = diff(&before, &after);
        assert_eq!(
            (d.len(), d[0].pid, d[0].added, d[0].gated),
            (1, 2, EXEC | RECV, true)
        );
    }

    #[test]
    fn permission_bits_match_capability_tags() {
        for p in [
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::SendMessage,
            Permission::ReceiveMessage,
            Permission::Delete,
            Permission::RequiresApproval,
        ] {
            assert_eq!(bit(p.clone()), 1u64 << p.tag());
        }
    }

    #[test]
    fn default_policy_file_parses() {
        let p = Policy::parse(include_str!("../policy/default.rules")).unwrap();
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn digest_is_stable() {
        assert_eq!(digest("a"), digest("a"));
        assert_ne!(digest("a"), digest("b"));
    }
}
