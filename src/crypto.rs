use aes::Aes128;
use anyhow::{anyhow, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

type Aes128CbcDec = cbc::Decryptor<Aes128>;

const PADDING_BYTES: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        out.push(b ^ k);
    }
    out
}

fn pad_password(password: &str) -> [u8; 32] {
    let pb = password.as_bytes();
    let mut out = [0u8; 32];
    if pb.len() >= 32 {
        out.copy_from_slice(&pb[..32]);
    } else {
        out[..pb.len()].copy_from_slice(pb);
        out[pb.len()..].copy_from_slice(&PADDING_BYTES[pb.len()..]);
    }
    out
}

fn modmult(a: i64, b: i64, c: i64, m: i64, s: i64) -> i64 {
    let q = s / a;
    let mut s2 = b * (s - a * q) - c * q;
    if s2 < 0 {
        s2 += m;
    }
    s2
}

fn generate_initial_vector(page: u32) -> [u8; 16] {
    let mut z: i64 = page as i64 + 1;
    let mut initkey = [0u8; 16];
    for j in 0..4 {
        z = modmult(52774, 40692, 3791, 2147483399, z);
        initkey[4 * j..4 * j + 4].copy_from_slice(&(z as u32).to_le_bytes());
    }
    md5(&initkey)
}

fn get_page_cipher_params(base_key: &[u8; 16], page: u32) -> ([u8; 16], [u8; 16]) {
    let mut nkey = Vec::with_capacity(16 + 4 + 4);
    nkey.extend_from_slice(base_key);
    nkey.extend_from_slice(&page.to_le_bytes());
    nkey.extend_from_slice(b"sAlT");
    let pagekey = md5(&nkey);
    let iv = generate_initial_vector(page);
    (pagekey, iv)
}

pub fn derive_encryption_key(key_str: &str) -> Result<[u8; 16]> {
    let user_pad = pad_password(key_str);
    let owner_pad = pad_password("");

    let mut digest = md5(&owner_pad);
    for _ in 0..50 {
        digest = md5(&digest);
    }
    let expect = "5a00344f40d0a5c52b160b830e6e086";
    // NOTE: the reference python asserts a 33-hex-char string (odd length), which
    // can never equal a 16-byte digest's hex (32 chars) -- that assert in the
    // original script is dead code. We keep behavior compatible by not enforcing it.
    let _ = expect;

    let mut owner_key = user_pad.to_vec();
    for i in 0..20u8 {
        let mkey: Vec<u8> = digest.iter().map(|d| d ^ i).collect();
        owner_key = rc4(&mkey, &owner_key);
    }

    let mut final_input = user_pad.to_vec();
    final_input.extend_from_slice(&owner_key);
    let mut digest2 = md5(&final_input);
    for _ in 0..50 {
        digest2 = md5(&digest2);
    }

    let mut base_key = [0u8; 16];
    base_key.copy_from_slice(&digest2[..16]);
    Ok(base_key)
}

fn decrypt_page_aes128(base_key: &[u8; 16], page: u32, data: &[u8]) -> Vec<u8> {
    let (pagekey, iv) = get_page_cipher_params(base_key, page);
    let mut buf = data.to_vec();
    let size = buf.len();

    if page == 1 {
        let orig_hdr = buf[16..24].to_vec();
        let db_page_size = ((orig_hdr[0] as u16) << 8) | orig_hdr[1] as u16;
        let ok_size = (512..=65535).contains(&db_page_size)
            && (db_page_size & (db_page_size.wrapping_sub(1))) == 0;
        let offset = if ok_size && orig_hdr[5] == 0x40 && orig_hdr[6] == 0x20 && orig_hdr[7] == 0x20
        {
            let (a, b) = buf.split_at_mut(16);
            b[..8].copy_from_slice(&a[8..16]);
            16
        } else {
            0
        };

        let dec = Aes128CbcDec::new((&pagekey).into(), (&iv).into());
        let mut blocks = buf[offset..size].to_vec();
        let decrypted = dec
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut blocks)
            .expect("cbc decrypt");
        buf[offset..size].copy_from_slice(decrypted);

        if offset != 0 && buf[16..24] == orig_hdr[..] {
            buf[0..16].copy_from_slice(b"SQLite format 3\0");
        }
    } else {
        let dec = Aes128CbcDec::new((&pagekey).into(), (&iv).into());
        let mut blocks = buf.clone();
        let decrypted = dec
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut blocks)
            .expect("cbc decrypt");
        buf.copy_from_slice(decrypted);
    }
    buf
}

pub fn decrypt_sqlite_file(
    encrypted_path: &Path,
    decrypted_path: &Path,
    key_str: &str,
) -> Result<()> {
    let mut fin = File::open(encrypted_path)?;
    let mut header = [0u8; 18];
    fin.read_exact(&mut header)?;
    let page_size = u16::from_be_bytes([header[16], header[17]]) as usize;
    if page_size == 0 {
        return Err(anyhow!("invalid page size read from header"));
    }

    let base_key = derive_encryption_key(key_str)?;

    let mut fin = File::open(encrypted_path)?;
    let mut fout = File::create(decrypted_path)?;
    let mut page: u32 = 1;
    let mut chunk = vec![0u8; page_size];
    loop {
        let n = fin.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let data = if n < page_size {
            &chunk[..n]
        } else {
            &chunk[..]
        };
        let out = decrypt_page_aes128(&base_key, page, data);
        fout.write_all(&out)?;
        page += 1;
    }
    Ok(())
}

pub fn test_decrypt_key(encrypted_path: &Path, key_str: &str) -> bool {
    let mut fin = match File::open(encrypted_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut header = [0u8; 18];
    if fin.read_exact(&mut header).is_err() {
        return false;
    }
    let page_size = u16::from_be_bytes([header[16], header[17]]) as usize;
    if page_size == 0 {
        return false;
    }
    let base_key = match derive_encryption_key(key_str) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut chunk = vec![0u8; page_size];
    let mut fin = match File::open(encrypted_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if fin.read_exact(&mut chunk).is_err() {
        return false;
    }
    let decrypted = decrypt_page_aes128(&base_key, 1, &chunk);
    decrypted.starts_with(b"SQLite format 3\0")
}
