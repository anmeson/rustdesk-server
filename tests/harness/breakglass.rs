//! Break-glass capabilities, minted by the tools an operator actually uses —
//! TASK.md T5.4.
//!
//! `t35_breakglass.rs` mints in Rust, deliberately: a shared helper would let
//! hbbs and its own test agree with each other while both disagreed with the
//! thing that mints capabilities in production, and the detail most likely to
//! drift is exactly the one such a helper hides — the signature covers the
//! **base64url payload text**, not the decoded JSON.
//!
//! That argument says a re-implementation is the right way to test the
//! *verifier*. It also leaves a gap nothing closes: whether `keygen-breakglass.ts`
//! and `mint-breakglass.ts` — the two scripts a person runs at three in the
//! morning — produce something these servers accept. So this module shells out
//! to the real ones. If the payload shape, the base64 alphabet, or the DER
//! stripping in keygen ever drifts, it fails here, which is the only place it
//! can fail before an outage.
//!
//! One case the real tool cannot produce, and only one: an **already-expired**
//! capability. `mint-breakglass.ts` refuses `--minutes 0` and anything negative,
//! which is correct of it, so [`mint_expired`] signs that one directly — the
//! same code path `t35` uses, kept to the one case that needs it.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use hbb_common::sodiumoxide::crypto::sign;

/// An ed25519 keypair, as `keygen-breakglass.ts` produces it.
pub struct Keys {
    /// The base64 public key, ready for `BREAKGLASS_PUBKEY` and
    /// `--breakglass-pubkey`.
    pub pubkey: String,
    /// The PEM private key on disk — kept offline in production, and never sent
    /// to any server here either.
    pub private_path: PathBuf,
}

fn api_dir() -> PathBuf {
    let crate_root = std::env::current_dir().unwrap();
    crate_root.join("../../apps/api").canonicalize().unwrap()
}

/// Runs the real `keygen-breakglass.ts` and reads back what it printed.
///
/// The filename is unique per call, which is not fussiness: every world arms its
/// servers with *its* public key, so two tests sharing `breakglass.key` means
/// one of them signing with a key the servers it is talking to have never seen.
/// That fails as `Invalid capability signature` — which reads as a broken
/// verifier rather than as a test writing over another test's file.
pub fn keygen(dir: &Path) -> Keys {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let private_path = dir.join(format!(
        "breakglass-{}-{}.key",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let output = Command::new("node")
        .current_dir(api_dir())
        .args([
            "--import",
            "tsx",
            "src/scripts/keygen-breakglass.ts",
            &private_path.display().to_string(),
        ])
        .output()
        .expect("could not run keygen-breakglass.ts");
    assert!(
        output.status.success(),
        "keygen-breakglass.ts failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // It prints `BREAKGLASS_PUBKEY=<base64>` on its own line, which is the line
    // an operator copies into their `.env`.
    let pubkey = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("BREAKGLASS_PUBKEY="))
        .unwrap_or_else(|| panic!("keygen printed no BREAKGLASS_PUBKEY:\n{stdout}"))
        .trim()
        .to_owned();
    assert!(!pubkey.is_empty());
    Keys { pubkey, private_path }
}

/// Runs the real `mint-breakglass.ts`. Returns the `bg.…` capability the
/// operator pastes into `access_token`.
pub fn mint(keys: &Keys, admin: &str, device: &str, minutes: u32) -> String {
    let output = Command::new("node")
        .current_dir(api_dir())
        .args([
            "--import",
            "tsx",
            "src/scripts/mint-breakglass.ts",
            "--key",
            &keys.private_path.display().to_string(),
            "--admin",
            admin,
            "--device",
            device,
            "--minutes",
            &minutes.to_string(),
        ])
        .output()
        .expect("could not run mint-breakglass.ts");
    assert!(
        output.status.success(),
        "mint-breakglass.ts failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capability = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        capability.starts_with("bg."),
        "mint-breakglass.ts printed something unexpected: {capability}"
    );
    capability
}

/// Asks the real tool for something it should refuse, and returns its complaint.
///
/// The bound is part of the design — a capability nobody can remember issuing is
/// the failure decision D1 exists to prevent — and it is enforced in two places
/// that must not disagree: here, and `BREAKGLASS_MAX_TTL_SEC` in hbbs.
pub fn mint_refused(keys: &Keys, admin: &str, device: &str, minutes: u32) -> String {
    let output = Command::new("node")
        .current_dir(api_dir())
        .args([
            "--import",
            "tsx",
            "src/scripts/mint-breakglass.ts",
            "--key",
            &keys.private_path.display().to_string(),
            "--admin",
            admin,
            "--device",
            device,
            "--minutes",
            &minutes.to_string(),
        ])
        .output()
        .expect("could not run mint-breakglass.ts");
    assert!(
        !output.status.success(),
        "mint-breakglass.ts minted a capability it should have refused: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// An already-expired capability, signed with the same private key.
///
/// The one thing the real tool will not produce. The PEM is read and converted
/// rather than a second keypair generated, so this is genuinely the operator's
/// key signing a stale payload — which is the case being tested. A capability
/// signed by *another* key is a different test, and it uses [`keygen`] twice.
pub fn mint_expired(keys: &Keys, admin: &str, device: &str) -> String {
    let secret = secret_key(&keys.private_path);
    let exp = now() - 60;
    let payload = format!(
        r#"{{"admin_id":"{admin}","to_id":"{device}","exp":{exp},"nonce":"expired-{}"}}"#,
        uuid::Uuid::new_v4()
    );
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let signature = sign::sign_detached(payload_b64.as_bytes(), &secret);
    format!(
        "bg.{payload_b64}.{}",
        base64::encode_config(signature.as_ref(), base64::URL_SAFE_NO_PAD)
    )
}

/// Reads the PKCS#8 PEM `keygen-breakglass.ts` wrote and returns the libsodium
/// secret key for it.
///
/// A PKCS#8 ed25519 private key is a fixed 48-byte DER blob whose last 32 bytes
/// are the seed, which is why this can be a slice rather than a DER parser.
/// libsodium's secret key is `seed || public`, which `keypair_from_seed`
/// derives.
fn secret_key(path: &Path) -> sign::SecretKey {
    hbb_common::sodiumoxide::init().ok();
    let pem = std::fs::read_to_string(path).expect("no break-glass private key on disk");
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::decode(body.trim()).expect("the private key is not base64");
    assert_eq!(der.len(), 48, "not a PKCS#8 ed25519 private key: {} bytes", der.len());
    let seed = sign::Seed::from_slice(&der[16..]).expect("bad seed");
    sign::keypair_from_seed(&seed).1
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Every record hbbs has written to its local audit log, as JSON.
///
/// Read straight off disk rather than through any api, because the whole point
/// of the file is that it is the record that exists when nothing else does —
/// during the outage, on the operator's own host, before anybody has been told.
pub fn audit_records(hbbs_dir: &Path) -> Vec<serde_json::Value> {
    let path = hbbs_dir.join("breakglass-audit.log");
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("unparseable audit line {line:?}: {err}"))
        })
        .collect()
}
