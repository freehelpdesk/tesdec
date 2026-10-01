# tesdec

Decrypt TeslaCam clips from firmware 2026.20 and later. The command talks to the same Tesla key service as [dashcam.tesla.com](https://dashcam.tesla.com): it sends the ownership metadata stored in each clip header and decrypts the video on this machine. The footage is not uploaded.

Sign-in is Tesla's OAuth PKCE flow for the public `dashcam` client. Your password is entered on Tesla's page.

## Build

```bash
cargo build --release
```

The binary is `target/release/tesdec`. `cargo install --path .` installs it onto your `PATH`.

## Sign in

```bash
tesdec login
```

A window opens on Tesla's sign-in page. When login finishes, tesdec catches the redirect, exchanges the code, and stores the refresh token in `~/.config/tesdec/credentials.json` (mode 0600). Override that directory with `TESDEC_CONFIG`.

```bash
tesdec login --paste     # system browser; paste the callback URL
tesdec login --region cn # auth.tesla.cn
tesdec login --reauth    # show the password form again
tesdec status
tesdec logout
```

`--paste` is the fallback when the sign-in window cannot open. Copy the `https://dashcam.tesla.com/callback?code=…` URL as soon as it appears. If that page finishes loading, Tesla's viewer may spend the code.

## Decrypt

A path can be a clip or a directory. Directories are scanned recursively for `.mp4` files.

```bash
# New directory. Relative paths under the input folder are kept.
tesdec decrypt /Volumes/TESLA/TeslaCam --output ~/TeslaCam-plain

# Several files or folders. Each folder is placed under its own name.
tesdec decrypt ./TeslaCam ./extra.mp4 --output ~/out

# Replace an output file that is already there.
tesdec decrypt ./TeslaCam --output ~/TeslaCam-plain --overwrite

# Replace the encrypted clips on disk. Asks for confirmation unless --yes.
tesdec decrypt /Volumes/TESLA/TeslaCam --in-place

# One clip on stdin, decrypted MP4 on stdout. Status stays on stderr.
tesdec decrypt - < clip.mp4 > plain.mp4
tesdec decrypt clip.mp4 --output -
```

Plain MP4s in a folder are copied into `--output` and left alone with `--in-place`. `--mirror` also copies the other files (event JSON, thumbnails). Existing output files are skipped unless `--overwrite`.

`-` reads one clip from stdin. With no `--output`, that clip is written to stdout. `--output <DIR>` saves it as `stdin.mp4`. `--output -` writes one file or one stdin clip to stdout. A successful pipe receives only MP4 bytes; errors and `--dry-run` stay on stderr. Stdin is copied to a temp file first because the container length is checked before the key request. A folder that contains more than one clip cannot be written to stdout. `--in-place` and `--mirror` do not apply to a pipe.

`--in-place` writes a temp file beside the clip and renames it over the original, so a failed decrypt leaves the encrypted file in place. The disk needs room for the decrypted copy. If the USB stick is full, use `--output` on another drive.

`--dry-run` lists the plan and does not call Tesla. `--token` uses a bearer token you already have and does not save it. `--batch-size` defaults to 30, which is Tesla's maximum. Larger folders are split across several key requests. `-j` / `--jobs` decrypts that many clips at once. The default is the number of CPUs. The next key request is sent while those clips are still decrypting, and each worker reads the file in 1 MiB pieces. On Apple Silicon the build enables the CPU's AES instructions.

## What Tesla receives

For each encrypted clip, the request body contains a client-generated id plus the VIN, key id, timestamp, wrapped key, and public key from the file header. That is the same `POST /api/1/decrypt/batch` body the official viewer sends. Decryption is AES-CBC in 4096-byte pages, with the per-page IV from Tesla's encryptfs bundle. A result that does not start with an MP4 `ftyp` box is discarded.
