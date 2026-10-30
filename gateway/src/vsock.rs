//! The link over vsock (roadmap 5.2): CDK listens on a vsock port inside
//! its VM, and the gateway connects to it from the host — the transport of
//! QEMU's `vhost-vsock-pci`, KubeVirt and Kata Containers.
//!
//! The standard library has no vsock socket type. The link only reads,
//! writes and sets a receive timeout, which are the same system calls for
//! every stream socket, so the connected socket is handed back as a
//! `UnixStream`.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// CDK's link port ("CD"); must match the kernel's `virtio_vsock::LINK_PORT`.
pub const LINK_PORT: u32 = 0x4344;

/// `vsock:CID[:PORT]` as `(cid, port)`, if `spec` is one.
pub fn parse(spec: &str) -> Option<Result<(u32, u32), String>> {
    let rest = spec.strip_prefix("vsock:")?;
    let (cid, port) = rest.split_once(':').unwrap_or((rest, ""));
    let cid = match cid.parse::<u32>() {
        Ok(c) if c >= 3 => c,
        _ => return Some(Err(format!("{spec}: the guest CID must be a number >= 3"))),
    };
    let port = if port.is_empty() {
        LINK_PORT
    } else {
        match port.parse::<u32>() {
            Ok(p) => p,
            Err(_) => return Some(Err(format!("{spec}: bad port"))),
        }
    };
    Some(Ok((cid, port)))
}

/// Connect to `port` in the VM with context id `cid`.
pub fn connect(cid: u32, port: u32) -> io::Result<UnixStream> {
    // SAFETY: plain socket calls with a zeroed, fully initialized address.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let r = libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(UnixStream::from(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `vsock:CID[:PORT]`; other strings are socket paths.
    #[test]
    fn parses_vsock_addresses() {
        assert_eq!(parse("vsock:3"), Some(Ok((3, LINK_PORT))));
        assert_eq!(parse("vsock:42:1024"), Some(Ok((42, 1024))));
        assert!(
            matches!(parse("vsock:2"), Some(Err(_))),
            "the host's own CID"
        );
        assert!(matches!(parse("vsock:x"), Some(Err(_))));
        assert!(matches!(parse("vsock:3:p"), Some(Err(_))));
        assert_eq!(parse("target/cdk-link.sock"), None);
    }
}
