//! C ABI for programs that link `libtesdec`.
//!
//! The layout of every `#[repr(C)]` struct is checked against
//! `include/tesdec.h`. A panic in this module becomes `TESDEC_ERR` and the
//! text `internal error`. It does not unwind into C or C++.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use crate::api::{self, FetchedKeys};
use crate::auth;
use crate::container::{self, ClipHeader, Probe};

pub const TESDEC_OK: i32 = 0;
pub const TESDEC_ERR: i32 = 1;
pub const TESDEC_UNAUTHORIZED: i32 = 2;
pub const TESDEC_PLAIN: i32 = 0;
pub const TESDEC_ENCRYPTED: i32 = 1;

const VIN_LEN: usize = 17;
const PUBKEY_MAX: usize = 65;
const WRAPPED_LEN: usize = 44;

/// Ownership metadata from an encrypted clip header.
///
/// Field offsets are the ABI. Do not reorder them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TesdecHeader {
    pub plaintext_size: u64,
    pub timestamp: u64,
    pub key_id: u32,
    pub reserved: u32,
    pub public_key_len: u64,
    pub wrapped_key_len: u64,
    pub vin: [u8; 18],
    pub public_key: [u8; 65],
    pub wrapped_key: [u8; 44],
}

/// One clip in a key request. Pointers are borrowed for the call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TesdecKeyRequest {
    pub vin: *const c_char,
    pub public_key: *const u8,
    pub wrapped_key: *const u8,
    pub timestamp: u64,
    pub public_key_len: u64,
    pub wrapped_key_len: u64,
    pub key_id: u32,
    pub pad: u32,
}

/// AES key returned for one request, in the same order as the request.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TesdecKeyResult {
    pub key: [u8; 32],
    pub key_len: u64,
    pub error: [u8; 256],
}

const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<TesdecHeader>() == 168);
    assert!(align_of::<TesdecHeader>() == 8);
    assert!(offset_of!(TesdecHeader, plaintext_size) == 0);
    assert!(offset_of!(TesdecHeader, timestamp) == 8);
    assert!(offset_of!(TesdecHeader, key_id) == 16);
    assert!(offset_of!(TesdecHeader, reserved) == 20);
    assert!(offset_of!(TesdecHeader, public_key_len) == 24);
    assert!(offset_of!(TesdecHeader, wrapped_key_len) == 32);
    assert!(offset_of!(TesdecHeader, vin) == 40);
    assert!(offset_of!(TesdecHeader, public_key) == 58);
    assert!(offset_of!(TesdecHeader, wrapped_key) == 123);

    assert!(size_of::<TesdecKeyRequest>() == 56);
    assert!(align_of::<TesdecKeyRequest>() == 8);
    assert!(offset_of!(TesdecKeyRequest, vin) == 0);
    assert!(offset_of!(TesdecKeyRequest, public_key) == 8);
    assert!(offset_of!(TesdecKeyRequest, wrapped_key) == 16);
    assert!(offset_of!(TesdecKeyRequest, timestamp) == 24);
    assert!(offset_of!(TesdecKeyRequest, public_key_len) == 32);
    assert!(offset_of!(TesdecKeyRequest, wrapped_key_len) == 40);
    assert!(offset_of!(TesdecKeyRequest, key_id) == 48);
    assert!(offset_of!(TesdecKeyRequest, pad) == 52);

    assert!(size_of::<TesdecKeyResult>() == 296);
    assert!(align_of::<TesdecKeyResult>() == 8);
    assert!(offset_of!(TesdecKeyResult, key) == 0);
    assert!(offset_of!(TesdecKeyResult, key_len) == 32);
    assert!(offset_of!(TesdecKeyResult, error) == 40);
};

/// Package version. The pointer stays valid for the life of the process.
///
/// # Safety
///
/// The returned pointer is a static NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn tesdec_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Server cap for one `tesdec_fetch_keys` call. Same value as `TESDEC_MAX_BATCH`.
#[no_mangle]
pub extern "C" fn tesdec_max_batch() -> u32 {
    api::MAX_BATCH as u32
}

/// Classify `path` as a plain MP4 or an encrypted TeslaCam clip.
///
/// On success `kind` is `TESDEC_PLAIN` (0) or `TESDEC_ENCRYPTED` (1). An
/// encrypted clip fills `header`. A plain clip leaves `header` untouched when
/// it is null, and zeroes it otherwise. When the clip is encrypted and
/// `header` is null, `kind` is still set and the call returns `TESDEC_ERR`.
///
/// # Safety
///
/// `path` is a NUL-terminated filesystem path. `kind` is non-null. `header`
/// is either null or points at a writable [`TesdecHeader`]. `err` is either
/// null or writable for `err_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn tesdec_probe(
    path: *const c_char,
    kind: *mut i32,
    header: *mut TesdecHeader,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    guard(err, err_len, || {
        probe_inner(path, kind, header, err, err_len)
    })
}

/// Decrypt one clip with a 16- or 32-byte AES key.
///
/// `written` receives the plaintext length and may be null. The destination
/// is replaced only after the decrypted bytes start with an MP4 `ftyp` box.
///
/// # Safety
///
/// `src` and `dest` are NUL-terminated paths. `key` points at `key_len`
/// readable bytes. `written` is either null or writable. `err` is either null
/// or writable for `err_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn tesdec_decrypt_file(
    src: *const c_char,
    dest: *const c_char,
    key: *const u8,
    key_len: u64,
    written: *mut u64,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    guard(err, err_len, || {
        decrypt_inner(src, dest, key, key_len, written, err, err_len)
    })
}

/// Ask dashcam.tesla.com for the AES key of each clip.
///
/// `api_base` null uses `https://dashcam.tesla.com`. `bearer` is an access
/// token. This function does not open a sign-in window. `count` is 1 through
/// [`tesdec_max_batch`]. On success each `out` slot is either a key or a
/// per-clip message in `error`. A rejected token returns `TESDEC_UNAUTHORIZED`
/// and does not write `out`.
///
/// # Safety
///
/// `bearer` is a NUL-terminated UTF-8 string. `api_base` is null or the same.
/// `items` points at `count` requests whose pointers stay valid for the call.
/// `out` points at `count` writable results. `err` is either null or writable
/// for `err_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn tesdec_fetch_keys(
    api_base: *const c_char,
    bearer: *const c_char,
    items: *const TesdecKeyRequest,
    count: u64,
    out: *mut TesdecKeyResult,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    guard(err, err_len, || {
        fetch_inner(api_base, bearer, items, count, out, err, err_len)
    })
}

fn guard(err: *mut c_char, err_len: u64, body: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => {
            write_err(err, err_len, "internal error");
            TESDEC_ERR
        }
    }
}

fn probe_inner(
    path: *const c_char,
    kind: *mut i32,
    header: *mut TesdecHeader,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    if kind.is_null() {
        return fail(err, err_len, "kind is null");
    }
    let path = match c_path(path, "path") {
        Ok(path) => path,
        Err(msg) => return fail(err, err_len, &msg),
    };
    match container::probe(&path) {
        Probe::Plain => {
            unsafe { *kind = TESDEC_PLAIN };
            if !header.is_null() {
                unsafe { header.write(TesdecHeader::zeroed()) };
            }
            clear_err(err, err_len);
            TESDEC_OK
        }
        Probe::Encrypted(parsed) => {
            unsafe { *kind = TESDEC_ENCRYPTED };
            if header.is_null() {
                return fail(err, err_len, "header is required for an encrypted clip");
            }
            match c_header(&parsed) {
                Ok(value) => {
                    unsafe { header.write(value) };
                    clear_err(err, err_len);
                    TESDEC_OK
                }
                Err(msg) => fail(err, err_len, &msg),
            }
        }
        Probe::Invalid(msg) => fail(err, err_len, &msg),
    }
}

fn decrypt_inner(
    src: *const c_char,
    dest: *const c_char,
    key: *const u8,
    key_len: u64,
    written: *mut u64,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    let key = match owned_key(key, key_len) {
        Ok(key) => key,
        Err(msg) => return fail(err, err_len, &msg),
    };
    let src = match c_path(src, "src") {
        Ok(path) => path,
        Err(msg) => return fail(err, err_len, &msg),
    };
    let dest = match c_path(dest, "dest") {
        Ok(path) => path,
        Err(msg) => return fail(err, err_len, &msg),
    };
    match container::decrypt_file(&src, &dest, &key) {
        Ok(n) => {
            if !written.is_null() {
                unsafe { written.write(n) };
            }
            clear_err(err, err_len);
            TESDEC_OK
        }
        Err(cause) => fail(err, err_len, &cause.to_string()),
    }
}

fn fetch_inner(
    api_base: *const c_char,
    bearer: *const c_char,
    items: *const TesdecKeyRequest,
    count: u64,
    out: *mut TesdecKeyResult,
    err: *mut c_char,
    err_len: u64,
) -> i32 {
    if count == 0 || count > api::MAX_BATCH as u64 {
        return fail(
            err,
            err_len,
            &format!("batch of {count} is outside 1 to {}", api::MAX_BATCH),
        );
    }
    if items.is_null() {
        return fail(err, err_len, "items is null");
    }
    if out.is_null() {
        return fail(err, err_len, "out is null");
    }
    let api_base = match optional_text(api_base, "api base") {
        Ok(value) => value.unwrap_or_else(|| auth::API_BASE.to_string()),
        Err(msg) => return fail(err, err_len, &msg),
    };
    if api_base.is_empty() {
        return fail(err, err_len, "api base is empty");
    }
    let bearer = match c_text(bearer, "bearer token") {
        Ok(value) => value,
        Err(msg) => return fail(err, err_len, &msg),
    };
    let bearer = bearer.trim().trim_start_matches("Bearer ").trim();
    if bearer.is_empty() {
        return fail(err, err_len, "bearer token is empty");
    }

    let mut requests = Vec::with_capacity(count as usize);
    let mut ids = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let item = unsafe { &*items.add(index) };
        match request_item(item) {
            Ok(item) => {
                ids.push(item.id.clone());
                requests.push(item);
            }
            Err(msg) => return fail(err, err_len, &format!("item {index}: {msg}")),
        }
    }

    match api::fetch_keys(&api_base, bearer, &requests) {
        Ok(fetched) => {
            let mut pending = vec![TesdecKeyResult::zeroed(); requests.len()];
            for (slot, id) in pending.iter_mut().zip(&ids) {
                fill_result(slot, &fetched, id);
            }
            unsafe {
                std::ptr::copy_nonoverlapping(pending.as_ptr(), out, pending.len());
            }
            clear_err(err, err_len);
            TESDEC_OK
        }
        Err(api::FetchError::Unauthorized) => {
            write_err(err, err_len, "Tesla rejected the access token");
            TESDEC_UNAUTHORIZED
        }
        Err(api::FetchError::Failed(msg)) => fail(err, err_len, &msg),
    }
}

fn request_item(item: &TesdecKeyRequest) -> Result<api::KeyRequestItem, String> {
    let vin = c_text(item.vin, "vin")?;
    if vin.len() != VIN_LEN || !vin.is_ascii() {
        return Err("vin must be 17 ASCII characters".into());
    }
    if item.public_key_len == 0 || item.public_key_len > PUBKEY_MAX as u64 {
        return Err(format!(
            "public key is {} bytes; expected 1 to {PUBKEY_MAX}",
            item.public_key_len
        ));
    }
    if item.wrapped_key_len != WRAPPED_LEN as u64 {
        return Err(format!(
            "wrapped key is {} bytes; expected {WRAPPED_LEN}",
            item.wrapped_key_len
        ));
    }
    if item.public_key.is_null() {
        return Err("public key is null".into());
    }
    if item.wrapped_key.is_null() {
        return Err("wrapped key is null".into());
    }
    let public_key = unsafe {
        std::slice::from_raw_parts(item.public_key, item.public_key_len as usize).to_vec()
    };
    let wrapped_key = unsafe {
        std::slice::from_raw_parts(item.wrapped_key, item.wrapped_key_len as usize).to_vec()
    };
    Ok(api::item_for(&ClipHeader {
        plaintext_size: 0,
        vin,
        key_id: item.key_id,
        timestamp: item.timestamp,
        wrapped_key,
        public_key,
    }))
}

fn fill_result(slot: &mut TesdecKeyResult, fetched: &FetchedKeys, id: &str) {
    if let Some(key) = fetched.keys.get(id) {
        slot.key[..key.len()].copy_from_slice(key);
        slot.key_len = key.len() as u64;
        return;
    }
    let msg = fetched
        .errors
        .iter()
        .find(|(found, _)| found == id)
        .map(|(_, msg)| msg.as_str())
        .unwrap_or("response omitted this clip");
    write_buf(&mut slot.error, msg);
}

fn c_header(header: &ClipHeader) -> Result<TesdecHeader, String> {
    if header.vin.len() != VIN_LEN || !header.vin.is_ascii() {
        return Err("vin must be 17 ASCII characters".into());
    }
    if header.public_key.len() > PUBKEY_MAX || header.wrapped_key.len() > WRAPPED_LEN {
        return Err("header field does not fit the C struct".into());
    }
    let mut out = TesdecHeader::zeroed();
    out.plaintext_size = header.plaintext_size;
    out.timestamp = header.timestamp;
    out.key_id = header.key_id;
    out.vin[..VIN_LEN].copy_from_slice(header.vin.as_bytes());
    out.public_key[..header.public_key.len()].copy_from_slice(&header.public_key);
    out.public_key_len = header.public_key.len() as u64;
    out.wrapped_key[..header.wrapped_key.len()].copy_from_slice(&header.wrapped_key);
    out.wrapped_key_len = header.wrapped_key.len() as u64;
    Ok(out)
}

fn owned_key(key: *const u8, key_len: u64) -> Result<Vec<u8>, String> {
    if key_len != 16 && key_len != 32 {
        return Err(format!("key is {key_len} bytes; expected 16 or 32"));
    }
    if key.is_null() {
        return Err("key is null".into());
    }
    let mut owned = vec![0u8; key_len as usize];
    unsafe {
        std::ptr::copy_nonoverlapping(key, owned.as_mut_ptr(), owned.len());
    }
    Ok(owned)
}

fn c_path(ptr: *const c_char, what: &str) -> Result<PathBuf, String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    // The caller keeps this NUL-terminated path alive for the call.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        let text = std::str::from_utf8(bytes).map_err(|_| "path is not utf-8".to_string())?;
        Ok(PathBuf::from(text))
    }
}

fn c_text(ptr: *const c_char, what: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    // The caller keeps this NUL-terminated UTF-8 string alive for the call.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    std::str::from_utf8(bytes)
        .map(|text| text.to_string())
        .map_err(|_| format!("{what} is not utf-8"))
}

fn optional_text(ptr: *const c_char, what: &str) -> Result<Option<String>, String> {
    if ptr.is_null() {
        Ok(None)
    } else {
        c_text(ptr, what).map(Some)
    }
}

fn fail(err: *mut c_char, err_len: u64, msg: &str) -> i32 {
    write_err(err, err_len, msg);
    TESDEC_ERR
}

fn clear_err(err: *mut c_char, err_len: u64) {
    write_err(err, err_len, "");
}

fn write_err(buf: *mut c_char, len: u64, msg: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let cap = usize::try_from(len).unwrap_or(usize::MAX);
    let mut end = msg.len().min(cap - 1);
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    unsafe {
        if end > 0 {
            std::ptr::copy_nonoverlapping(msg.as_ptr(), buf.cast(), end);
        }
        *buf.add(end) = 0;
    }
}

fn write_buf(dest: &mut [u8], msg: &str) {
    if dest.is_empty() {
        return;
    }
    let mut end = msg.len().min(dest.len() - 1);
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    dest[..end].copy_from_slice(&msg.as_bytes()[..end]);
    dest[end] = 0;
}

impl TesdecHeader {
    const fn zeroed() -> Self {
        Self {
            plaintext_size: 0,
            timestamp: 0,
            key_id: 0,
            reserved: 0,
            public_key_len: 0,
            wrapped_key_len: 0,
            vin: [0; 18],
            public_key: [0; 65],
            wrapped_key: [0; 44],
        }
    }
}

impl TesdecKeyResult {
    const fn zeroed() -> Self {
        Self {
            key: [0; 32],
            key_len: 0,
            error: [0; 256],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("tesdec-ffi-{label}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn plain_mp4() -> Vec<u8> {
        let mut plain = vec![0u8; 5000];
        plain[4..8].copy_from_slice(b"ftyp");
        plain[8..12].copy_from_slice(b"isom");
        plain
    }

    #[test]
    fn version_and_batch_match_the_crate() {
        let version = unsafe { CStr::from_ptr(tesdec_version()) };
        assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
        assert_eq!(tesdec_max_batch(), api::MAX_BATCH as u32);
    }

    #[test]
    fn a_panic_becomes_an_error_code() {
        let mut err = [0u8; 64];
        let code = guard(err.as_mut_ptr().cast(), err.len() as u64, || panic!("boom"));
        assert_eq!(code, TESDEC_ERR);
        assert_eq!(
            CStr::from_bytes_until_nul(&err).unwrap().to_str().unwrap(),
            "internal error"
        );
        let code = guard(std::ptr::null_mut(), 0, || panic!("boom"));
        assert_eq!(code, TESDEC_ERR);
    }

    #[test]
    fn error_text_stops_on_a_utf8_boundary() {
        let mut buf = [0xABu8; 4];
        write_buf(&mut buf, "ééé");
        assert_eq!(&buf, &[0xC3, 0xA9, 0, 0xAB]);
    }

    #[test]
    fn probe_and_decrypt_round_trip_through_the_c_api() {
        let key = [0x11u8; 16];
        let plain = plain_mp4();
        let sealed = container::seal(&plain, &key, "5YJ3E1EA7KF000001", 7, 1_700_000_123);
        let dir = scratch("round");
        let src = dir.join("clip.mp4");
        let dest = dir.join("out.mp4");
        fs::write(&src, &sealed).unwrap();
        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let dest_c = CString::new(dest.to_str().unwrap()).unwrap();

        let mut kind = -1;
        let mut err = [0u8; 256];
        let code = unsafe {
            tesdec_probe(
                src_c.as_ptr(),
                &mut kind,
                std::ptr::null_mut(),
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert_eq!(kind, TESDEC_ENCRYPTED);
        assert!(
            CStr::from_bytes_until_nul(&err)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("header"),
            "{err:?}"
        );

        let mut header = TesdecHeader::zeroed();
        err.fill(0x5A);
        let code = unsafe {
            tesdec_probe(
                src_c.as_ptr(),
                &mut kind,
                &mut header,
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_OK, "{err:?}");
        assert_eq!(kind, TESDEC_ENCRYPTED);
        assert_eq!(header.plaintext_size, 5000);
        assert_eq!(header.key_id, 7);
        assert_eq!(header.timestamp, 1_700_000_123);
        assert_eq!(&header.vin[..17], b"5YJ3E1EA7KF000001");
        assert_eq!(header.vin[17], 0);
        assert_eq!(header.public_key_len, 65);
        assert_eq!(header.public_key[0], 0x04);
        assert_eq!(header.wrapped_key_len, 44);
        assert!(header.wrapped_key.iter().all(|byte| *byte == 0x44));

        let mut written = 0u64;
        let code = unsafe {
            tesdec_decrypt_file(
                src_c.as_ptr(),
                dest_c.as_ptr(),
                key.as_ptr(),
                key.len() as u64,
                &mut written,
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_OK, "{err:?}");
        assert_eq!(written, 5000);
        assert_eq!(fs::read(&dest).unwrap(), plain);

        let short = [0u8; 15];
        let code = unsafe {
            tesdec_decrypt_file(
                src_c.as_ptr(),
                dest_c.as_ptr(),
                short.as_ptr(),
                short.len() as u64,
                std::ptr::null_mut(),
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert!(
            CStr::from_bytes_until_nul(&err)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("16 or 32"),
            "{err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_of_a_plain_mp4_allows_a_null_header() {
        let dir = scratch("plain");
        let src = dir.join("plain.mp4");
        fs::write(&src, plain_mp4()).unwrap();
        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let mut kind = -1;
        let code = unsafe {
            tesdec_probe(
                src_c.as_ptr(),
                &mut kind,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(code, TESDEC_OK);
        assert_eq!(kind, TESDEC_PLAIN);

        let mut header = TesdecHeader::zeroed();
        header.plaintext_size = 9;
        let code = unsafe {
            tesdec_probe(
                src_c.as_ptr(),
                &mut kind,
                &mut header,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(code, TESDEC_OK);
        assert_eq!(header.plaintext_size, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_writes_the_error_buffer() {
        let path = CString::new("/no/such/tesdec-clip.mp4").unwrap();
        let mut err = [0u8; 128];
        let mut kind = 7;
        let code = unsafe {
            tesdec_probe(
                path.as_ptr(),
                &mut kind,
                std::ptr::null_mut(),
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert_eq!(kind, 7);
        let msg = CStr::from_bytes_until_nul(&err).unwrap().to_str().unwrap();
        assert!(msg.contains("cannot read"), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn path_keeps_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let raw = b"clip-\xff.mp4\0";
        let path = c_path(raw.as_ptr().cast(), "path").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"clip-\xff.mp4");

        let mut kind = 7;
        let mut err = [0u8; 256];
        let code = unsafe {
            tesdec_probe(
                raw.as_ptr().cast(),
                &mut kind,
                std::ptr::null_mut(),
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert_eq!(kind, 7);
        let msg = CStr::from_bytes_until_nul(&err).unwrap().to_str().unwrap();
        assert!(msg.contains("cannot read"), "{msg}");
    }

    #[test]
    fn fetch_rejects_an_illegal_batch_without_a_request() {
        let mut err = [0u8; 128];
        let mut out = TesdecKeyResult::zeroed();
        let token = CString::new("token").unwrap();
        let code = unsafe {
            tesdec_fetch_keys(
                std::ptr::null(),
                token.as_ptr(),
                std::ptr::null(),
                31,
                &mut out,
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert!(
            CStr::from_bytes_until_nul(&err)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("31"),
            "{err:?}"
        );
        assert_eq!(out.key_len, 0);

        let code = unsafe {
            tesdec_fetch_keys(
                std::ptr::null(),
                token.as_ptr(),
                std::ptr::null(),
                0,
                &mut out,
                err.as_mut_ptr().cast(),
                err.len() as u64,
            )
        };
        assert_eq!(code, TESDEC_ERR);
        assert_eq!(out.key_len, 0);
        assert_eq!(out.error[0], 0);
    }
}
