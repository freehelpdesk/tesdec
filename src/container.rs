//! Tesla 2026.20 dashcam container.
//!
//! The layout and page cipher match the unminified `encryptfs` bundle shipped
//! by dashcam.tesla.com. Each file is two 4096-byte header pages followed by
//! AES-CBC payload pages. The per-page IV is
//! `MD5(MD5(file_key) || ascii(page_number) || zeros)` over a 32-byte buffer.
//! Pages are full blocks with no padding; the header's plaintext length trims
//! the tail.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes::Aes128;
use anyhow::{bail, Context, Result};
use cbc::Decryptor;
#[cfg(test)]
use cbc::Encryptor;
use cipher::BlockDecryptMut;
#[cfg(test)]
use cipher::BlockEncryptMut;
use cipher::KeyIvInit;
use md5::{Digest, Md5};

pub const PAGE_SIZE: usize = 4096;
pub const HEADER_SIZE: usize = 8192;
/// `magic1 XOR magic2` from `EcryptfsFile.MAGIC` in Tesla's encryptfs bundle.
pub const MAGIC: u32 = 0x3c81_b7f5;
/// Big-endian uint32 at offset 16. The bundle compares it with 50331650.
pub const VERSION_FLAGS: u32 = 0x0300_0002;
const WRAPPED_KEY_LEN: usize = 44;
const VIN_LEN: usize = 17;
const FULL_PUB_LEN: usize = 65;
const MIN_PUB_LEN: usize = 57;

#[derive(Debug, Clone)]
pub struct ClipHeader {
    pub plaintext_size: u64,
    pub vin: String,
    pub key_id: u32,
    pub timestamp: u64,
    pub wrapped_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug)]
pub enum Probe {
    Encrypted(ClipHeader),
    /// Ordinary MP4 (`ftyp` at offset 4). Firmware before encryption, or a clip
    /// recorded with encryption turned off.
    Plain,
    Invalid(String),
}

pub fn probe(path: &Path) -> Probe {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => return Probe::Invalid(format!("cannot read {}: {err}", path.display())),
    };
    if !meta.is_file() {
        return Probe::Invalid(format!("{} is not a file", path.display()));
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => return Probe::Invalid(format!("cannot open {}: {err}", path.display())),
    };
    let mut prefix = [0u8; 32];
    let n = match file.read(&mut prefix) {
        Ok(n) => n,
        Err(err) => return Probe::Invalid(format!("cannot read {}: {err}", path.display())),
    };
    if n >= 8 && &prefix[4..8] == b"ftyp" && !looks_encrypted(&prefix[..n], meta.len()) {
        return Probe::Plain;
    }
    if !looks_encrypted(&prefix[..n], meta.len()) {
        return Probe::Invalid(format!(
            "{} is not an encrypted TeslaCam clip or a plain MP4",
            path.display()
        ));
    }
    let mut header = vec![0u8; HEADER_SIZE];
    header[..n].copy_from_slice(&prefix[..n]);
    if let Err(err) = file.read_exact(&mut header[n..]) {
        return Probe::Invalid(format!("{} header is short: {err}", path.display()));
    }
    match parse_container(&header, meta.len()) {
        Ok(parsed) => Probe::Encrypted(parsed),
        Err(err) => Probe::Invalid(err.to_string()),
    }
}

fn looks_encrypted(prefix: &[u8], file_len: u64) -> bool {
    if prefix.len() < 26
        || file_len < HEADER_SIZE as u64
        || !file_len.is_multiple_of(PAGE_SIZE as u64)
    {
        return false;
    }
    let magic1 = u32::from_be_bytes(prefix[8..12].try_into().unwrap());
    let magic2 = u32::from_be_bytes(prefix[12..16].try_into().unwrap());
    let version = u32::from_be_bytes(prefix[16..20].try_into().unwrap());
    let data_offset = u32::from_be_bytes(prefix[20..24].try_into().unwrap());
    let extents = u16::from_be_bytes(prefix[24..26].try_into().unwrap());
    magic1 ^ magic2 == MAGIC
        && version == VERSION_FLAGS
        && data_offset == PAGE_SIZE as u32
        && extents == 2
}

pub fn parse_container(header: &[u8], file_len: u64) -> Result<ClipHeader> {
    if header.len() < HEADER_SIZE {
        bail!("encrypted header is shorter than {HEADER_SIZE} bytes");
    }
    if file_len < HEADER_SIZE as u64 || !file_len.is_multiple_of(PAGE_SIZE as u64) {
        bail!("encrypted file length {file_len} is not a multiple of {PAGE_SIZE} past the header");
    }
    if !looks_encrypted(header, file_len) {
        bail!("file does not have a Tesla encrypted-clip header");
    }
    let plaintext_size = u64::from_be_bytes(header[0..8].try_into().unwrap());
    let capacity = file_len - HEADER_SIZE as u64;
    if plaintext_size == 0 || plaintext_size > capacity {
        bail!(
            "plaintext size {plaintext_size} does not fit the encrypted payload ({capacity} bytes)"
        );
    }

    // Port of `EcryptfsFile.extractWrappedKey`. The public key is usually a
    // 65-byte uncompressed point, but the official client allows 57–65 bytes
    // when a NUL sits where the timestamp begins.
    let mut cursor = PAGE_SIZE;
    let key_id = u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let key_start = cursor;
    let expected_vin_start = cursor + FULL_PUB_LEN;
    let ts_start_max = expected_vin_start + VIN_LEN;
    let mut ts_start = expected_vin_start;
    while ts_start <= ts_start_max && header.get(ts_start) != Some(&0) {
        ts_start += 1;
    }
    let mut pub_len = if ts_start <= ts_start_max && header.get(ts_start) == Some(&0) {
        ts_start - VIN_LEN - cursor
    } else {
        FULL_PUB_LEN
    };
    if !(MIN_PUB_LEN..=FULL_PUB_LEN).contains(&pub_len) || header.get(cursor) != Some(&0x04) {
        pub_len = FULL_PUB_LEN;
    }
    let pub_end = key_start + pub_len;
    let wrapped_end = pub_end + VIN_LEN + 8 + WRAPPED_KEY_LEN;
    if wrapped_end > header.len() {
        bail!("wrapped key extends past the header");
    }
    let public_key = header[key_start..pub_end].to_vec();
    if public_key.first() != Some(&0x04) {
        bail!("public key does not start with 0x04");
    }
    let vin_bytes = &header[pub_end..pub_end + VIN_LEN];
    if vin_bytes.contains(&0) || !vin_bytes.is_ascii() {
        bail!("VIN in the encrypted header is not 17 ASCII characters");
    }
    let vin = std::str::from_utf8(vin_bytes)
        .expect("ascii checked")
        .to_string();
    let timestamp = u64::from_be_bytes(
        header[pub_end + VIN_LEN..pub_end + VIN_LEN + 8]
            .try_into()
            .unwrap(),
    );
    let wrapped_key = header[pub_end + VIN_LEN + 8..wrapped_end].to_vec();

    Ok(ClipHeader {
        plaintext_size,
        vin,
        key_id,
        timestamp,
        wrapped_key,
        public_key,
    })
}

pub fn derive_iv(file_key: &[u8], page: u64) -> [u8; 16] {
    let root = Md5::digest(file_key);
    let mut material = [0u8; 32];
    material[..16].copy_from_slice(&root);
    let digits = page.to_string();
    let bytes = digits.as_bytes();
    // Sixteen bytes remain in the 32-byte buffer. A clip would need an absurd
    // page index (10^16 pages) to overflow it.
    let n = bytes.len().min(16);
    material[16..16 + n].copy_from_slice(&bytes[..n]);
    let out = Md5::digest(material);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&out);
    iv
}

fn decrypt_page(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
    if !buf.len().is_multiple_of(16) {
        bail!("ciphertext page is not a multiple of the AES block");
    }
    let err = || anyhow::anyhow!("AES-CBC decrypt failed");
    match key.len() {
        16 => {
            let dec = Decryptor::<Aes128>::new_from_slices(key, iv).map_err(|_| err())?;
            dec.decrypt_padded_mut::<cipher::block_padding::NoPadding>(buf)
                .map(|_| ())
                .map_err(|_| err())?;
        }
        32 => {
            let dec = Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| err())?;
            dec.decrypt_padded_mut::<cipher::block_padding::NoPadding>(buf)
                .map(|_| ())
                .map_err(|_| err())?;
        }
        other => bail!("Tesla returned a {other}-byte key; expected 16 or 32"),
    }
    Ok(())
}

/// Decrypt `src` to `dest`. Writes a sibling temp file and renames it into
/// place, including when `dest` is `src`, so a failure leaves the original clip.
pub fn decrypt_file(src: &Path, dest: &Path, key: &[u8]) -> Result<u64> {
    let file_len = fs::metadata(src)
        .with_context(|| format!("cannot stat {}", src.display()))?
        .len();
    let mut input =
        BufReader::new(File::open(src).with_context(|| format!("cannot open {}", src.display()))?);
    let mut header = vec![0u8; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .with_context(|| format!("cannot read header of {}", src.display()))?;
    let meta = parse_container(&header, file_len)
        .with_context(|| format!("cannot parse {}", src.display()))?;

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    let tmp = temp_path_for(dest);
    let guard = TempGuard(Some(tmp.clone()));
    let mut output = BufWriter::new(
        File::create(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?,
    );

    let mut written = 0u64;
    let mut page_index = 0u64;
    let mut page = vec![0u8; PAGE_SIZE];
    while written < meta.plaintext_size {
        input.read_exact(&mut page).with_context(|| {
            format!(
                "{} ended before plaintext byte {}",
                src.display(),
                meta.plaintext_size
            )
        })?;
        let iv = derive_iv(key, page_index);
        decrypt_page(key, &iv, &mut page)?;
        let remain = (meta.plaintext_size - written) as usize;
        let take = remain.min(PAGE_SIZE);
        if page_index == 0 && (take < 8 || &page[4..8] != b"ftyp") {
            bail!(
                "decrypted {} does not start with an MP4 ftyp box; the key does not match this clip",
                src.display()
            );
        }
        output
            .write_all(&page[..take])
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        written += take as u64;
        page_index += 1;
    }
    output
        .flush()
        .with_context(|| format!("cannot flush {}", tmp.display()))?;
    sync_output(output.get_ref()).with_context(|| format!("cannot sync {}", tmp.display()))?;
    drop(output);

    #[cfg(unix)]
    if let Ok(src_meta) = fs::metadata(src) {
        let _ = fs::set_permissions(&tmp, src_meta.permissions());
    }

    fs::rename(&tmp, dest)
        .with_context(|| format!("cannot replace {} with decrypted output", dest.display()))?;
    guard.disarm();
    Ok(written)
}

/// `File::sync_all` on macOS is `F_FULLFSYNC`. SMB rejects that with ENOTSUP
/// (os error 45) even when `fsync` works, which is what `/Volumes/nas` does.
fn sync_output(file: &File) -> std::io::Result<()> {
    match file.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(err) if sync_unsupported(&err) => fallback_fsync(file),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn sync_unsupported(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == libc::ENOTSUP || code == libc::EOPNOTSUPP || code == libc::ENOSYS
    )
}

#[cfg(unix)]
fn fallback_fsync(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        let rc = unsafe { libc::fsync(file.as_raw_fd()) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if sync_unsupported(&err) {
            note_sync_unavailable();
            return Ok(());
        }
        return Err(err);
    }
}

#[cfg(unix)]
fn note_sync_unavailable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !NOTED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "warning: this filesystem does not support sync; files are written without a durability barrier"
        );
    }
}

pub fn temp_path_for(dest: &Path) -> PathBuf {
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
    dest.with_file_name(format!(".{name}.tesdec-tmp"))
}

struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
fn encrypt_page(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    match key.len() {
        16 => {
            let enc = Encryptor::<Aes128>::new_from_slices(key, iv).unwrap();
            enc.encrypt_padded_mut::<cipher::block_padding::NoPadding>(buf, buf.len())
                .unwrap();
        }
        32 => {
            let enc = Encryptor::<aes::Aes256>::new_from_slices(key, iv).unwrap();
            enc.encrypt_padded_mut::<cipher::block_padding::NoPadding>(buf, buf.len())
                .unwrap();
        }
        _ => panic!("bad key"),
    }
}

#[cfg(test)]
pub(crate) fn seal(
    plaintext: &[u8],
    key: &[u8],
    vin: &str,
    key_id: u32,
    timestamp: u64,
) -> Vec<u8> {
    assert_eq!(vin.len(), VIN_LEN);
    assert!(!plaintext.is_empty());
    let pages = plaintext.len().div_ceil(PAGE_SIZE);
    let mut body = vec![0u8; pages * PAGE_SIZE];
    body[..plaintext.len()].copy_from_slice(plaintext);
    for (index, page) in body.chunks_mut(PAGE_SIZE).enumerate() {
        let iv = derive_iv(key, index as u64);
        encrypt_page(key, &iv, page);
    }

    let mut file = vec![0u8; HEADER_SIZE + body.len()];
    file[..8].copy_from_slice(&(plaintext.len() as u64).to_be_bytes());
    let magic1 = 0x1111_1111u32;
    file[8..12].copy_from_slice(&magic1.to_be_bytes());
    file[12..16].copy_from_slice(&(magic1 ^ MAGIC).to_be_bytes());
    file[16..20].copy_from_slice(&VERSION_FLAGS.to_be_bytes());
    file[20..24].copy_from_slice(&(PAGE_SIZE as u32).to_be_bytes());
    file[24..26].copy_from_slice(&2u16.to_be_bytes());

    let mut cursor = PAGE_SIZE;
    file[cursor..cursor + 4].copy_from_slice(&key_id.to_be_bytes());
    cursor += 4;
    let mut public_key = vec![0x22u8; FULL_PUB_LEN];
    public_key[0] = 0x04;
    file[cursor..cursor + FULL_PUB_LEN].copy_from_slice(&public_key);
    cursor += FULL_PUB_LEN;
    file[cursor..cursor + VIN_LEN].copy_from_slice(vin.as_bytes());
    cursor += VIN_LEN;
    file[cursor..cursor + 8].copy_from_slice(&timestamp.to_be_bytes());
    cursor += 8;
    file[cursor..cursor + WRAPPED_KEY_LEN].fill(0x44);
    file[HEADER_SIZE..].copy_from_slice(&body);
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn page_iv_matches_independent_md5() {
        let key: Vec<u8> = (0..16).collect();
        assert_eq!(
            derive_iv(&key, 0).to_vec(),
            hex("cd096e1db464e9b4c91e51419090606b")
        );
        assert_eq!(
            derive_iv(&key, 10).to_vec(),
            hex("5ce066bcdaf9ef30ca01ce592e8d196e")
        );
    }

    #[test]
    fn round_trip_trims_the_last_page_and_checks_ftyp() {
        let key = [0x11u8; 16];
        let mut plain = vec![0u8; 5000];
        plain[4..8].copy_from_slice(b"ftyp");
        plain[8..12].copy_from_slice(b"isom");
        for (i, byte) in plain.iter_mut().enumerate().skip(12) {
            *byte = (i % 251) as u8;
        }
        let sealed = seal(&plain, &key, "5YJ3E1EA7KF000001", 7, 1_700_000_123);
        let dir = std::env::temp_dir().join(format!("tesdec-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("clip.mp4");
        let dest = dir.join("out.mp4");
        fs::write(&src, &sealed).unwrap();

        let header = parse_container(&sealed[..HEADER_SIZE], sealed.len() as u64).unwrap();
        assert_eq!(header.vin, "5YJ3E1EA7KF000001");
        assert_eq!(header.key_id, 7);
        assert_eq!(header.timestamp, 1_700_000_123);
        assert_eq!(header.public_key.len(), 65);
        assert_eq!(header.wrapped_key.len(), 44);
        assert_eq!(header.plaintext_size, 5000);

        let n = decrypt_file(&src, &dest, &key).unwrap();
        assert_eq!(n, 5000);
        assert_eq!(fs::read(&dest).unwrap(), plain);

        let err = decrypt_file(&src, &dir.join("bad.mp4"), &[0x22u8; 16]).unwrap_err();
        assert!(err.to_string().contains("ftyp"), "{err}");
        assert!(!dir.join("bad.mp4").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shorter_public_key_is_read_the_way_the_viewer_does() {
        let mut header = vec![0u8; HEADER_SIZE];
        let file_len = (HEADER_SIZE + PAGE_SIZE) as u64;
        header[..8].copy_from_slice(&100u64.to_be_bytes());
        let magic1 = 0x2222_2222u32;
        header[8..12].copy_from_slice(&magic1.to_be_bytes());
        header[12..16].copy_from_slice(&(magic1 ^ MAGIC).to_be_bytes());
        header[16..20].copy_from_slice(&VERSION_FLAGS.to_be_bytes());
        header[20..24].copy_from_slice(&(PAGE_SIZE as u32).to_be_bytes());
        header[24..26].copy_from_slice(&2u16.to_be_bytes());

        let mut cursor = PAGE_SIZE;
        header[cursor..cursor + 4].copy_from_slice(&9u32.to_be_bytes());
        cursor += 4;
        let pub_len = 60;
        header[cursor] = 0x04;
        header[cursor + 1..cursor + pub_len].fill(0x33);
        cursor += pub_len;
        header[cursor..cursor + 17].copy_from_slice(b"LRW3E7EK9RC000042");
        cursor += 17;
        // High byte of the timestamp is 0, which is the NUL the viewer scans for.
        header[cursor..cursor + 8].copy_from_slice(&1_720_000_000u64.to_be_bytes());
        cursor += 8;
        header[cursor..cursor + 44].fill(0x55);

        let parsed = parse_container(&header, file_len).unwrap();
        assert_eq!(parsed.public_key.len(), 60);
        assert_eq!(parsed.vin, "LRW3E7EK9RC000042");
        assert_eq!(parsed.key_id, 9);
        assert_eq!(parsed.timestamp, 1_720_000_000);
    }

    #[test]
    fn plain_mp4_and_garbage_are_not_encrypted() {
        let dir = std::env::temp_dir().join(format!("tesdec-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.mp4");
        fs::write(&plain, b"\0\0\0\x18ftypisom").unwrap();
        assert!(matches!(probe(&plain), Probe::Plain));
        let junk = dir.join("nope.mp4");
        fs::write(&junk, b"not a clip").unwrap();
        assert!(matches!(probe(&junk), Probe::Invalid(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn smb_style_fullfsync_rejection_falls_back_to_fsync() {
        let err = std::io::Error::from_raw_os_error(libc::ENOTSUP);
        assert!(sync_unsupported(&err));
        let dir = std::env::temp_dir().join(format!(
            "tesdec-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.mp4");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"\0\0\0\x18ftypisom").unwrap();
        sync_output(&file).unwrap();
        fallback_fsync(&file).unwrap();
        drop(file);
        let _ = fs::remove_dir_all(&dir);
    }
}
