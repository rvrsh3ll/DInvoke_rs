#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{ffi::OsStr, os::windows::ffi::OsStrExt, slice};
use windows::{Win32::Foundation::UNICODE_STRING, core::PWSTR};

pub fn str_to_wide_string(s: &str) -> Vec<u16> 
{
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

pub fn osstr_to_wide_string(s: &OsStr) -> Vec<u16> 
{
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

pub fn pwstr_to_string(p: *const u16) -> String 
{
    if p.is_null() {
        return String::new();
    }

    unsafe 
    {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }

        let wide: &[u16] = slice::from_raw_parts(p, len);
        String::from_utf16_lossy(wide)
    }
}

pub fn str_to_unicode_string(s: &str) -> Result<UNICODE_STRING, &str> 
{
    let mut buf: Vec<u16> = s.encode_utf16().collect();
    buf.push(0);

    let len_bytes = (buf.len() - 1) * 2; 
    let max_bytes = buf.len() * 2;   

    if len_bytes > u16::MAX as usize || max_bytes > u16::MAX as usize {
        return Err("");
    }

    let us = UNICODE_STRING {
        Length: len_bytes as u16,
        MaximumLength: max_bytes as u16,
        Buffer: PWSTR(buf.as_mut_ptr()),
    };

    Ok(us)
}

pub fn get_module_entry_point_addr(module_base_address: usize) -> Result<usize, String> 
{
    let pe_info = manualmap::get_pe_metadata(module_base_address as _, false);
    if pe_info.is_err() {
        return Err(lc!("[x] Could not obtain the PE's metadata."));
    }

    let pe_info = pe_info.unwrap();
    let entry_point;
    if pe_info.is_32_bit {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as usize;
    } else {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as usize;
    }
    
    Ok(entry_point)
}