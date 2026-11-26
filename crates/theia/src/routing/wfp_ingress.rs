//! Windows user-mode WFP redirect adapter. Requires a separate installed
//! ALE_CONNECT_REDIRECT callout driver and secure session provisioning.
//! No WFP filters or driver installation are performed here.
use super::{packet::FlowKey, wfp_context};
use std::{io, os::windows::io::AsRawSocket, ptr};
use tokio::net::TcpStream;
use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl};

// mstcpip.h: _WSAIOW(IOC_VENDOR, 220/221).
const QUERY_RECORDS: u32 = 0x9800_00dc;
const QUERY_CONTEXT: u32 = 0x9800_00dd;
const MAX_RECORDS: usize = 4096;

fn query(stream: &TcpStream, code: u32, buffer: &mut [u8]) -> io::Result<usize> {
    let mut returned = 0u32;
    // SAFETY: socket is owned by the caller, output memory is valid for
    // the synchronous call; no overlapped pointer or callback is retained.
    let rc = unsafe {
        WSAIoctl(stream.as_raw_socket() as usize, code, ptr::null(), 0,
            buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut returned,
            ptr::null_mut(), None)
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let n = returned as usize;
    if n == 0 || n > buffer.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(n)
}

pub(crate) fn original_tcp(stream: &TcpStream, token: &[u8; 32]) -> io::Result<FlowKey> {
    // The existing H2/H3 carrier is not a new direct socket to the original
    // destination. It still requires independently proven carrier exclusion.
    // Redirect records are queried to reject ordinary local TCP connections;
    // do not copy opaque records to an unrelated multiplexed carrier.
    let mut records = [0u8; MAX_RECORDS];
    query(stream, QUERY_RECORDS, &mut records)?;
    let mut context = [0u8; wfp_context::SIZE];
    let len = query(stream, QUERY_CONTEXT, &mut context)?;
    wfp_context::decode(&context[..len], token, stream.peer_addr()?, stream.local_addr()?)
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))
}
