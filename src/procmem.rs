use anyhow::{anyhow, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// Finds the PID of the first process whose image name matches (case-insensitive).
pub fn find_pid_by_name(name: &str) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                if exe.eq_ignore_ascii_case(name) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found.ok_or_else(|| anyhow!("process '{name}' not found"))
    }
}

/// Reads all committed, non-guarded, readable pages of the target process and
/// runs `on_chunk` over each contiguous region (with a small overlap between
/// calls handled by the caller, since regions here are read whole).
pub fn scan_process_memory<F: FnMut(&[u8])>(pid: u32, mut on_chunk: F) -> Result<()> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        let mut addr: usize = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let written = VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if written == 0 {
                break;
            }

            let region_size = mbi.RegionSize;
            let readable = mbi.State == MEM_COMMIT
                && (mbi.Protect & PAGE_NOACCESS).0 == 0
                && (mbi.Protect & PAGE_GUARD).0 == 0
                && region_size > 0;

            if readable {
                // Cap single-region read to 64 MiB chunks to bound memory use.
                const MAX_CHUNK: usize = 64 * 1024 * 1024;
                let mut offset: usize = 0;
                while offset < region_size {
                    let len = std::cmp::min(MAX_CHUNK, region_size - offset);
                    let mut buf = vec![0u8; len];
                    let mut bytes_read = 0usize;
                    let base = mbi.BaseAddress as usize + offset;
                    let ok = ReadProcessMemory(
                        handle,
                        base as *const _,
                        buf.as_mut_ptr() as *mut _,
                        len,
                        Some(&mut bytes_read),
                    );
                    if ok.is_ok() && bytes_read > 0 {
                        buf.truncate(bytes_read);
                        on_chunk(&buf);
                    }
                    offset += len;
                }
            }

            let next = mbi.BaseAddress as usize + region_size;
            if next <= addr {
                break; // avoid infinite loop on overflow/zero-size regions
            }
            addr = next;
        }

        let _ = CloseHandle(handle);
    }
    Ok(())
}
