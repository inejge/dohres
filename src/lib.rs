use std::collections::HashSet;
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ptr;
use std::str::FromStr;

use libc::{self, c_char, c_int, hostent, int32_t, size_t, uint32_t};
use rustls::Certificate;
use trust_dns::client::{Client, SyncClient};
use trust_dns::https::HttpsClientConnection;
use trust_dns::op::{DnsResponse, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

pub const NSS_STATUS_TRYAGAIN: c_int = -2;
pub const NSS_STATUS_UNAVAIL: c_int  = -1; 
pub const NSS_STATUS_NOTFOUND: c_int = 0; 
pub const NSS_STATUS_SUCCESS: c_int  = 1; 

pub const HOST_NOT_FOUND: c_int = 1;
pub const TRY_AGAIN: c_int      = 2;
pub const NO_RECOVERY: c_int    = 3;
pub const NO_DATA: c_int        = 4;
pub const NETDB_INTERNAL: c_int = -1;
pub const NETDB_SUCCESS: c_int  = 0;

#[repr(C)]
pub struct gaih_addrtuple {
    next: *mut gaih_addrtuple,
    name: *mut c_char,
    family: c_int,
    addr: [uint32_t; 4],
    scopeid: uint32_t,
}

#[no_mangle]
pub extern "C" fn _nss_doh_gethostbyname_r(
    name: *const c_char,
    result_buf: *mut hostent,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    _nss_doh_gethostbyname2_r(name, libc::AF_INET, result_buf, buf, buflen, errnop, h_errnop)
}

#[no_mangle]
pub extern "C" fn _nss_doh_gethostbyname2_r(
    name: *const c_char,
    af: c_int,
    result_buf: *mut hostent,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    if af == libc::AF_INET6 {
        return NSS_STATUS_NOTFOUND;
    }
    let r_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let addrs = match retrieve_addrs(r_name.as_ref(), errnop, h_errnop) {
        (Some(addrs), _) => addrs,
        (None, status) => return status,
    };

    //
    // How to pack everything into buf:
    //
    // +-----+-----+------+----+----+-+-+-+-+--+
    // | &a0 | &a1 | NULL | a0 | a1 |n|a|m|e|\0|
    // +-----+-----+------+----+----+-+-+-+-+--+
    //
    // h_addr_list points to &a0
    // h_aliases points to the NULL at the end of h_addr_list
    // addresses follow h_addr_list
    // h_name follows addresses
    //
    let ptr_size = mem::size_of::<*const c_char>();
    let data_size = addrs.len() * (ptr_size + 4) + ptr_size + r_name.len() + 1;
    if data_size > buflen {
        unsafe {
            ptr::write(errnop, libc::ERANGE);
            ptr::write(h_errnop, TRY_AGAIN);
        }
        return NSS_STATUS_TRYAGAIN;
    }
    let mut addr_data_offset = (addrs.len() + 1) * ptr_size;
    for (ix, addr) in addrs.iter().enumerate() {
        unsafe {
            ptr::copy(&addr.octets() as *const u8, buf.offset(addr_data_offset as isize) as *mut u8, 4);
            let addr_ptr = buf.offset(addr_data_offset as isize) as *const c_char;
            let addr_ptr_slot = (buf as *mut *const c_char).offset(ix as isize);
            ptr::write(addr_ptr_slot, addr_ptr);
        }
        addr_data_offset += 4;
    }
    unsafe {
        let null_slot = (buf as *mut *const c_char).offset(addrs.len() as isize);
        ptr::write(null_slot, ptr::null());
        ptr::copy(name, buf.offset(addr_data_offset as isize) as *mut c_char, r_name.len() + 1);
        (*result_buf).h_addr_list = buf as *mut *mut c_char;
        (*result_buf).h_aliases = null_slot as *mut *mut c_char;
        (*result_buf).h_name = buf.offset(addr_data_offset as isize) as *mut c_char;
        ptr::write(h_errnop, NETDB_SUCCESS);
    }
    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn _nss_doh_gethostbyname4_r(
    name: *const c_char,
    pat: *mut *mut gaih_addrtuple,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut int32_t,
) -> c_int {
    if unsafe { (**pat).family } == libc::AF_INET6 {
        return NSS_STATUS_NOTFOUND;
    }
    let r_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let addrs = match retrieve_addrs(r_name.as_ref(), errnop, h_errnop) {
        (Some(addrs), _) => addrs,
        (None, status) => return status,
    };

    //
    // How to pack everything into buf:
    //
    // +----+-----+----+-+-+-+-+--+
    // | g0 | ... | gN |n|a|m|e|\0|
    // +----+-----+----+-+-+-+-+--+
    //
    // pat points to initial gaih_addrtuple, from which we get the address family.
    // *pat->next should be set to NULL for a single result, or to the next g_a
    // in the chain. The rest of g_a's are allocated inside of buf. *pat->name
    // points to the name allocated within buf, after all g_a's. In the rest of
    // g_a's, name is NULL.
    //
    let gaih_size = mem::size_of::<[gaih_addrtuple; 1]>();
    let name_offset = (addrs.len() - 1) * gaih_size;
    let data_size = name_offset + r_name.len() + 1;
    if data_size > buflen {
        unsafe {
            ptr::write(errnop, libc::ERANGE);
            ptr::write(h_errnop, TRY_AGAIN);
        }
        return NSS_STATUS_TRYAGAIN;
    }
    let mut gaih_array_offset = 0;
    for (ix, addr) in addrs.iter().enumerate() {
        unsafe {
            let addr_array: [uint32_t; 4] = [0; 4];
            ptr::copy(&addr.octets() as *const u8, &addr_array as *const u32 as *mut u8, 4);
            let next_ptr = if ix < addrs.len() - 1 {
                buf.offset((ix * gaih_size) as isize) as *mut gaih_addrtuple
            } else {
                ptr::null_mut()
            };
            let name_ptr = if ix == 0 {
                buf.offset(name_offset as isize) as *mut c_char
            } else {
                ptr::null_mut()
            };
            let elem = gaih_addrtuple {
                next: next_ptr,
                name: name_ptr,
                addr: addr_array,
                family: libc::AF_INET,
                scopeid: 0,
            };
            if ix == 0 {
                **pat = elem;
            } else {
                let gaih_ptr = buf.offset(gaih_array_offset as isize) as *mut gaih_addrtuple;
                ptr::write(gaih_ptr, elem);
                gaih_array_offset += gaih_size;
            }
        }
    }
    unsafe {
        ptr::copy(name, buf.offset(name_offset as isize) as *mut c_char, r_name.len() + 1);
        ptr::write(h_errnop, NETDB_SUCCESS);
    }
    NSS_STATUS_SUCCESS
}

fn retrieve_addrs(name: &str, errnop: *mut c_int, h_errnop: *mut c_int) -> (Option<Vec<Ipv4Addr>>, c_int) {
    unsafe {
        ptr::write(errnop, libc::ENOENT);
        ptr::write(h_errnop, NETDB_INTERNAL);
    }
    let mut dns_name = match Name::from_str(name) {
        Ok(name) => name,
        Err(_) => return (None, NSS_STATUS_UNAVAIL),
    };
    if !dns_name.is_fqdn() {
        dns_name = dns_name.append_name(&Name::root());
    }
    let resp = match resolve(&dns_name) {
        Ok(resp) => resp,
        Err(_) => return (None, NSS_STATUS_UNAVAIL),
    };
    let msg = match resp.messages().nth(0) {
        Some(msg) => msg,
        None => return (None, NSS_STATUS_UNAVAIL),
    };
    let ans = msg.answers();
    unsafe {
        ptr::write(errnop, 0);
        ptr::write(h_errnop, NO_DATA);
    }
    match msg.response_code() {
        ResponseCode::NoError => (),
        ResponseCode::NXDomain => {
            unsafe {
                ptr::write(h_errnop, HOST_NOT_FOUND);
            }
            return (None, NSS_STATUS_NOTFOUND);
        },
        ResponseCode::ServFail => {
            unsafe {
                ptr::write(h_errnop, TRY_AGAIN);
            }
            return (None, NSS_STATUS_TRYAGAIN);
        },
        _ => {
            unsafe {
                ptr::write(h_errnop, NO_RECOVERY);
            }
            return (None, NSS_STATUS_UNAVAIL);
        },
    }
    let mut looking_for = &dns_name;
    let mut addrs = vec![];
    let mut cnames = HashSet::new();
    'outer: loop {
        for record in ans.iter() {
            if record.name() == looking_for {
                match record.rr_type() {
                    RecordType::CNAME => {
                        // We must have no CNAME and A records with the same name
                        if !addrs.is_empty() {
                            addrs.clear();
                            break 'outer;
                        }
                        cnames.insert(looking_for);
                        looking_for = match record.rdata() {
                            RData::CNAME(ref name) => name,
                            _ => panic!("bogus record data"),
                        };
                        // CNAME loop
                        if cnames.contains(looking_for) {
                            break 'outer;
                        }
                        break;
                    },
                    RecordType::A => {
                        let addr = match record.rdata() {
                            RData::A(ref addr) => addr,
                            _ => panic!("bogus record data"),
                        };
                        addrs.push(addr.clone());
                    },
                    _ => (),
                }
            }
        } 
        if !addrs.is_empty() {
            break;
        }
    }
    if addrs.is_empty() {
        return (None, NSS_STATUS_NOTFOUND);
    }
    (Some(addrs), NSS_STATUS_SUCCESS)
}

fn resolve(dns_name: &Name) -> Result<DnsResponse, failure::Error> {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let mut conn = HttpsClientConnection::new();
    conn.add_ca(Certificate(Vec::from(
        &include_bytes!("../DigiCertGlobalRootCA.crt")[..],
    )));
    let conn = conn.build(socket, String::from("cloudflare-dns.com"));
    let client = SyncClient::new(conn);
    let resp = client.query(
        dns_name,
        DNSClass::IN,
        RecordType::A,
    )?;
    Ok(resp)
}
