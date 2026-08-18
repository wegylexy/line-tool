use regex::bytes::Regex;
use std::collections::BTreeSet;

fn ascii_pattern() -> Regex {
    Regex::new(r"(?i)encryptionKey.{0,12}?([0-9A-Fa-f]{32})mse").unwrap()
}

pub fn find_in_ascii(buf: &[u8], out: &mut BTreeSet<String>) {
    let re = ascii_pattern();
    for m in re.captures_iter(buf) {
        if let Some(g) = m.get(1) {
            if let Ok(s) = std::str::from_utf8(g.as_bytes()) {
                out.insert(s.to_string());
            }
        }
    }
}

/// Mirrors find_passphrase.py's UTF-16LE scan: after "encryptionKey" (UTF-16LE),
/// look for 32 hex chars each followed by a 0x00/0x20 byte, then "mse" in UTF-16LE.
pub fn find_in_utf16le(buf: &[u8], out: &mut BTreeSet<String>) {
    let key_utf16: Vec<u8> = "encryptionKey"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut start = 0usize;
    while let Some(rel) = find_sub(&buf[start..], &key_utf16) {
        let idx = start + rel;
        let pos = idx + key_utf16.len();
        let window_end = std::cmp::min(pos + 128, buf.len());
        let window = &buf[pos..window_end];

        let max_off = window.len().saturating_sub(64);
        for off in 0..max_off {
            let candidate_end = std::cmp::min(off + 32 * 2 + 3, window.len());
            let candidate = &window[off..candidate_end];
            if candidate.len() < 32 * 2 + 6 {
                continue;
            }
            let mut chars = Vec::with_capacity(32);
            let mut ok = true;
            let mut i = 0;
            while i < 32 * 2 {
                let ch = candidate[i];
                let pad = candidate[i + 1];
                if pad != 0x00 && pad != 0x20 {
                    ok = false;
                    break;
                }
                let is_hex = ch.is_ascii_digit()
                    || (b'A'..=b'F').contains(&ch)
                    || (b'a'..=b'f').contains(&ch);
                if !is_hex {
                    ok = false;
                    break;
                }
                chars.push(ch as char);
                i += 2;
            }
            if !ok {
                continue;
            }
            let mpos = 32 * 2;
            if mpos + 6 <= candidate.len()
                && candidate[mpos] == b'm'
                && candidate[mpos + 1] == 0x00
                && candidate[mpos + 2] == b's'
                && candidate[mpos + 3] == 0x00
                && candidate[mpos + 4] == b'e'
                && candidate[mpos + 5] == 0x00
            {
                out.insert(chars.into_iter().collect());
            }
        }
        start = idx + 2;
    }
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn scan_buffer(buf: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    find_in_ascii(buf, &mut out);
    find_in_utf16le(buf, &mut out);
    out
}
