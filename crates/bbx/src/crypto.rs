//! Encrypted bundles (age, X25519). A technician runs `bbx keygen` once and
//! puts the public key (`age1...`) in each client's config.json
//! (`export_recipients`) or passes `--recipient`; bundles leave the client
//! machine encrypted and only the technician's key file opens them
//! (`bbx decrypt`, or the standard `age` tool).

use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;

pub fn keygen(out: &Path) -> Result<String> {
    use age::secrecy::ExposeSecret;
    if out.exists() {
        bail!("{} already exists; refusing to overwrite a key", out.display());
    }
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    let body = format!(
        "# BlackBox technician key. Keep this file private.\n# public key: {public}\n{}\n",
        id.to_string().expose_secret()
    );
    std::fs::write(out, body).with_context(|| format!("write {}", out.display()))?;
    Ok(public)
}

pub fn parse_recipients(list: &[String]) -> Result<Vec<age::x25519::Recipient>> {
    list.iter()
        .map(|r| age::x25519::Recipient::from_str(r.trim()).map_err(|e| anyhow!("invalid recipient '{r}': {e}")))
        .collect()
}

pub fn encrypt_file(src: &Path, dst: &Path, recipients: &[age::x25519::Recipient]) -> Result<()> {
    if recipients.is_empty() {
        bail!("no recipients");
    }
    let enc = age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let mut w = enc.wrap_output(BufWriter::new(File::create(dst)?))?;
    std::io::copy(&mut File::open(src)?, &mut w)?;
    w.finish()?.flush()?;
    Ok(())
}

pub fn read_identities(path: &Path) -> Result<Vec<age::x25519::Identity>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ids: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("AGE-SECRET-KEY-"))
        .map(|l| age::x25519::Identity::from_str(l).map_err(|e| anyhow!("bad key in {}: {e}", path.display())))
        .collect::<Result<_>>()?;
    if ids.is_empty() {
        bail!("no AGE-SECRET-KEY found in {}", path.display());
    }
    Ok(ids)
}

pub fn decrypt_file(src: &Path, dst: &Path, ids: &[age::x25519::Identity]) -> Result<()> {
    let dec = age::Decryptor::new(BufReader::new(File::open(src)?)).map_err(|e| anyhow!("{}: {e}", src.display()))?;
    let mut r = dec
        .decrypt(ids.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| anyhow!("cannot decrypt {} with this key: {e}", src.display()))?;
    let mut out = BufWriter::new(File::create(dst)?);
    std::io::copy(&mut r, &mut out)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let key = d.path().join("tech.key");
        let public = keygen(&key).unwrap();
        assert!(public.starts_with("age1"));
        assert!(keygen(&key).is_err(), "never overwrite a key");
        let plain = d.path().join("b.zip");
        std::fs::write(&plain, b"PK\x03\x04 secret bundle").unwrap();
        let enc = d.path().join("b.zip.age");
        encrypt_file(&plain, &enc, &parse_recipients(&[public]).unwrap()).unwrap();
        assert!(!std::fs::read(&enc).unwrap().windows(6).any(|w| w == b"secret"));
        let out = d.path().join("out.zip");
        decrypt_file(&enc, &out, &read_identities(&key).unwrap()).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"PK\x03\x04 secret bundle");

        let other = d.path().join("other.key");
        keygen(&other).unwrap();
        assert!(decrypt_file(&enc, &d.path().join("x"), &read_identities(&other).unwrap()).is_err());
    }
}
