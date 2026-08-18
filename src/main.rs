mod crypto;
mod discover;
mod extract;
mod findkey;
mod generic;
mod procmem;
mod schema;
mod server;

use anyhow::{anyhow, Result};
use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand};
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "line-tool",
    about = "LINE encrypted-db passphrase finder & message extractor"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find the LINE encryption passphrase by scanning a live process's memory
    /// (no memory dump file needed).
    FindKey {
        /// Process image name, e.g. LINE.exe
        #[arg(long, default_value = "LINE.exe")]
        process_name: String,
        /// Attach by PID instead of by name
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Decrypt the .edb and extract messages for a chat/sender/date, mirroring
    /// extract_messages.py.
    Extract {
        #[arg(long)]
        edb: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
        /// Scan this live process's memory for the passphrase instead of --passphrase
        #[arg(long)]
        process_name: Option<String>,
        #[arg(long)]
        pid: Option<u32>,

        /// Exact chat mid (group or contact) - unambiguous, skips name search
        #[arg(long = "chat-id")]
        chat_id: Option<String>,
        /// Group chat name (substring match) - searches _groupChat only
        #[arg(long)]
        group: Option<String>,
        /// Contact name (substring match), as the target chat - searches _contact only
        #[arg(long)]
        contact: Option<String>,

        /// Message sender's display name (substring match)
        #[arg(long)]
        sender: Option<String>,
        #[arg(long = "sender-id")]
        sender_id: Option<String>,

        #[arg(long)]
        date: Option<String>,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        end: Option<String>,
        #[arg(long)]
        limit: Option<i64>,

        /// Print candidate group/contact mids for NAME instead of extracting, then exit
        #[arg(long)]
        lookup: Option<String>,
    },
    /// Decrypt the .edb once and serve a REST API for lookups/message queries.
    Serve {
        /// Path to the encrypted .edb. Auto-discovered (largest .edb under
        /// %LOCALAPPDATA%\LINE\Data\db) when omitted.
        #[arg(long)]
        edb: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        process_name: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
        /// Explicit single bind address, e.g. "0.0.0.0:5463" - overrides the
        /// default of listening on both 127.0.0.1 and [::1] at --port
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value_t = 5463)]
        port: u16,
    },
}

fn resolve_passphrase(process_name: Option<&str>, pid: Option<u32>) -> Result<String> {
    let target_pid = match pid {
        Some(p) => p,
        None => procmem::find_pid_by_name(process_name.unwrap_or("LINE.exe"))?,
    };
    eprintln!("[*] Scanning process memory of PID {target_pid} ...");

    let mut candidates = std::collections::BTreeSet::new();
    let mut prev_tail: Vec<u8> = Vec::new();
    procmem::scan_process_memory(target_pid, |chunk| {
        let mut buf = Vec::with_capacity(prev_tail.len() + chunk.len());
        buf.extend_from_slice(&prev_tail);
        buf.extend_from_slice(chunk);
        for c in findkey::scan_buffer(&buf) {
            candidates.insert(c);
        }
        let keep = 256.min(chunk.len());
        prev_tail = chunk[chunk.len() - keep..].to_vec();
    })?;

    if candidates.is_empty() {
        return Err(anyhow!("no passphrase candidates found in process memory"));
    }
    eprintln!("[*] Found candidates:");
    for c in &candidates {
        eprintln!("    {c}");
    }
    let first = candidates.into_iter().next().unwrap();
    eprintln!("[*] Using passphrase = {first}");
    Ok(first)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::FindKey { process_name, pid } => {
            let key = resolve_passphrase(Some(&process_name), pid)?;
            println!("{key}");
        }
        Command::Extract {
            edb,
            passphrase,
            process_name,
            pid,
            chat_id,
            group,
            contact,
            sender,
            sender_id,
            date,
            start,
            end,
            limit,
            lookup,
        } => {
            let edb = edb.ok_or_else(|| anyhow!("--edb is required"))?;

            let passphrase = match passphrase {
                Some(p) => p,
                None => resolve_passphrase(process_name.as_deref(), pid)?,
            };

            let tmp_db = std::env::temp_dir().join(format!("line-tool-{}.db", std::process::id()));
            crypto::decrypt_sqlite_file(&edb, &tmp_db, &passphrase)?;
            let con = Connection::open(&tmp_db)?;

            if let Some(name) = lookup {
                println!("[*] Group chat matches for '{name}':");
                for row in extract::lookup_group_candidates(&con, &name)? {
                    println!("    {row:?}");
                }
                println!("[*] Contact matches for '{name}':");
                for row in extract::lookup_contact_candidates(&con, &name)? {
                    println!("    {row:?}");
                }
                let _ = std::fs::remove_file(&tmp_db);
                return Ok(());
            }

            let chat_id = extract::resolve_chat_id(
                &con,
                chat_id.as_deref(),
                group.as_deref(),
                contact.as_deref(),
            )?;
            let sender_id =
                extract::resolve_sender_id(&con, sender_id.as_deref(), sender.as_deref())?;

            let (start_ms, end_ms) = if let Some(d) = date {
                (
                    Some(extract::to_epoch_ms(&d, false)?),
                    Some(extract::to_epoch_ms(&d, true)?),
                )
            } else if start.is_some() || end.is_some() {
                (
                    start.map(|s| extract::to_epoch_ms(&s, false)).transpose()?,
                    end.map(|e| extract::to_epoch_ms(&e, true)).transpose()?,
                )
            } else {
                let today = extract::today_local_date();
                (
                    Some(extract::to_epoch_ms(&today, false)?),
                    Some(extract::to_epoch_ms(&today, true)?),
                )
            };

            let rows = extract::extract(
                &con,
                &chat_id,
                sender_id.as_deref(),
                start_ms,
                end_ms,
                limit,
                false,
                None,
            )?;
            let _ = std::fs::remove_file(&tmp_db);

            if rows.is_empty() {
                println!("[!] No messages found matching the given filters.");
                return Ok(());
            }
            for row in rows {
                let dt = Local.timestamp_millis_opt(row.created_ms).single().unwrap();
                println!(
                    "[{}] {}: {}",
                    dt.to_rfc3339(),
                    row.from_mid,
                    row.text.unwrap_or_default()
                );
            }
        }
        Command::Serve {
            edb,
            passphrase,
            process_name,
            pid,
            addr,
            port,
        } => {
            let edb = match edb {
                Some(p) => p,
                None => {
                    let found = discover::discover_edb()?;
                    eprintln!("[*] Auto-discovered edb: {}", found.display());
                    found
                }
            };

            let passphrase = match passphrase {
                Some(p) => p,
                None => resolve_passphrase(process_name.as_deref(), pid)?,
            };

            // Fixed name (not per-PID) so repeated server runs reuse/overwrite one file
            // instead of leaking a new temp db every start.
            let tmp_db = std::env::temp_dir().join("line-tool-server.db");
            crypto::decrypt_sqlite_file(&edb, &tmp_db, &passphrase)?;
            let con = Connection::open(&tmp_db)?;
            let schema = schema::load(&con)?;

            let addrs = match addr {
                Some(a) => vec![a],
                None => vec![format!("127.0.0.1:{port}"), format!("[::1]:{port}")],
            };
            server::run(&addrs, con, schema)?;
        }
    }
    Ok(())
}
