use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::{frame_decode, Error, Result, FRAME_HEADER_SIZE};

fn debug_io() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("HWSHARE_DEBUG").is_some())
}

fn friendly_io(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(10054) => "对方中断了分享（连接被重置）".to_string(),
        Some(10060) | Some(10061) => "对方不在线或拒绝连接（超时）".to_string(),
        Some(10048) => "端口已被占用".to_string(),
        Some(10053) => "连接被本机中止（网络切换？）".to_string(),
        _ => e.to_string(),
    }
}

pub struct Channel {
    stream: TcpStream,
    peer: String,
    pending: Vec<u8>,
    label: String,
    role: &'static str,
    conn: u64,
    traced_open: bool,
    traced_t0: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    close_reason: &'static str,
}

fn transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    ) || matches!(e.raw_os_error(), Some(997) | Some(995))
}

#[cfg(windows)]
fn tune_buffers(stream: &TcpStream) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
    const SIZE: i32 = 1024 * 1024;
    let sock = stream.as_raw_socket() as usize;
    unsafe {
        let ptr = &SIZE as *const i32 as *const u8;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, ptr, 4);
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, ptr, 4);
    }
}

#[cfg(not(windows))]
fn tune_buffers(_stream: &TcpStream) {}

const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(windows)]
fn tune_keepalive(stream: &TcpStream) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, tcp_keepalive, WSAIoctl, SIO_KEEPALIVE_VALS, SOL_SOCKET, SO_KEEPALIVE,
    };
    let sock = stream.as_raw_socket() as usize;
    let on: i32 = 1;
    unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &on as *const i32 as *const u8,
            4,
        );

        let ka = tcp_keepalive {
            onoff: 1,
            keepalivetime: 30_000,
            keepaliveinterval: 5_000,
        };
        let mut returned: u32 = 0;
        WSAIoctl(
            sock,
            SIO_KEEPALIVE_VALS,
            &ka as *const tcp_keepalive as *const core::ffi::c_void,
            std::mem::size_of::<tcp_keepalive>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

#[cfg(not(windows))]
fn tune_keepalive(_stream: &TcpStream) {}

fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    tune_buffers(stream);
    tune_keepalive(stream);
}

impl Channel {
    pub fn connect(ip: &str, port: u16, timeout: Duration) -> Result<Self> {
        let addr = format!("{ip}:{port}");
        let sock: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| Error::Argument)?;
        let stream = TcpStream::connect_timeout(&sock, timeout).map_err(|e| {
            let msg = format!("连接 {ip}:{port} 失败: {e}");

            crate::trace::channel_fail(ip, port, &msg);
            Error::Io(msg)
        })?;
        tune_socket(&stream);
        Ok(Self {
            stream,
            peer: ip.to_string(),
            pending: Vec::new(),
            label: String::from("chan"),
            conn: crate::trace::next_conn(),
            role: "connect",
            traced_open: false,
            traced_t0: Instant::now(),
            tx_bytes: 0,
            rx_bytes: 0,
            close_reason: "closed",
        })
    }

    pub fn from_stream(stream: TcpStream, peer: impl Into<String>) -> Result<Self> {
        tune_socket(&stream);

        let _ = stream.set_nonblocking(false);
        Ok(Self {
            stream,
            peer: peer.into(),
            pending: Vec::new(),
            label: String::from("chan"),
            conn: crate::trace::next_conn(),
            role: "accept",
            traced_open: false,
            traced_t0: Instant::now(),
            tx_bytes: 0,
            rx_bytes: 0,
            close_reason: "closed",
        })
    }

    fn ensure_trace_open(&mut self) {
        if self.traced_open || !crate::trace::enabled() {
            return;
        }
        self.traced_open = true;
        let local = self
            .stream
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".into());
        let remote = self
            .stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| format!("{}:0", self.peer));
        crate::trace::channel_open(&self.label, self.role, &local, &remote, self.conn);
    }

    pub fn local_ip(&self) -> Option<String> {
        self.stream.local_addr().ok().map(|a| a.ip().to_string())
    }

    pub fn try_clone_stream(&self) -> std::io::Result<TcpStream> {
        self.stream.try_clone()
    }

    pub fn put_back(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.ensure_trace_open();
        crate::wire::rx(&self.label, data, self.conn);
        self.rx_bytes += data.len() as u64;
        let mut merged = Vec::with_capacity(data.len() + self.pending.len());
        merged.extend_from_slice(data);
        merged.extend_from_slice(&self.pending);
        self.pending = merged;
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn set_label(&mut self, label: &str) {
        self.label = label.to_string();
    }

    pub fn conn(&self) -> u64 {
        self.conn
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn close_reason(&self) -> &'static str {
        self.close_reason
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.ensure_trace_open();

        match self.stream.write_all(data) {
            Ok(()) => {
                self.tx_bytes += data.len() as u64;
                crate::wire::tx(&self.label, data, self.conn);
                crate::trace::frame(&self.label, "tx", data, self.conn);
                Ok(())
            }
            Err(e) => {
                self.close_reason = "write-error";
                let timeout = matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut);

                crate::trace::note(
                    &self.label,
                    &format!("写失败：本帧 {} 字节未完整写出（{e}）", data.len()),
                );
                Err(Error::Io(if timeout {
                    format!(
                        "发送超时（{} s 内没写完，对端可能已离线）",
                        WRITE_TIMEOUT.as_secs()
                    )
                } else {
                    format!("发送失败: {}", friendly_io(&e))
                }))
            }
        }
    }

    pub fn recv_exact(&mut self, size: usize, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; size];
        let mut filled = 0usize;

        if !self.pending.is_empty() {
            let take = size.min(self.pending.len());
            buf[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            filled = take;
        }
        while filled < size {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = self.stream.set_read_timeout(Some(remaining));
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    self.close_reason = "eof";
                    break;
                }
                Ok(n) => {
                    self.ensure_trace_open();
                    crate::wire::rx(&self.label, &buf[filled..filled + n], self.conn);
                    self.rx_bytes += n as u64;
                    filled += n;
                }
                Err(e) if transient(&e) => break,
                Err(e) => {
                    self.close_reason = "read-error";
                    return Err(Error::Io(format!("接收失败: {}", friendly_io(&e))));
                }
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }

    pub fn read_some(&mut self, max: usize, timeout: Duration) -> Result<Vec<u8>> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buf = vec![0u8; max];
        match self.stream.read(&mut buf) {
            Ok(0) => {
                self.close_reason = "eof";
                Ok(Vec::new())
            }
            Ok(n) => {
                self.ensure_trace_open();
                crate::wire::rx(&self.label, &buf[..n], self.conn);
                self.rx_bytes += n as u64;
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if transient(&e) => Ok(Vec::new()),
            Err(e) => {
                self.close_reason = "read-error";
                Err(Error::Io(format!("接收失败: {}", friendly_io(&e))))
            }
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.pending.len()
    }

    fn fill_pending(&mut self, want: usize, timeout: Duration) -> Result<usize> {
        if want == 0 {
            return Ok(0);
        }
        let _ = self.stream.set_read_timeout(Some(timeout));
        let old = self.pending.len();
        self.pending.resize(old + want, 0);
        match self.stream.read(&mut self.pending[old..]) {
            Ok(0) => {
                self.pending.truncate(old);
                self.close_reason = "eof";
                Ok(0)
            }
            Ok(n) => {
                self.pending.truncate(old + n);
                self.ensure_trace_open();
                crate::wire::rx(&self.label, &self.pending[old..], self.conn);
                self.rx_bytes += n as u64;
                Ok(n)
            }
            Err(e) if transient(&e) => {
                self.pending.truncate(old);
                Ok(0)
            }
            Err(e) => {
                self.pending.truncate(old);
                self.close_reason = "read-error";
                Err(Error::Io(format!("接收失败: {}", friendly_io(&e))))
            }
        }
    }

    pub fn peek(&self, n: usize) -> Result<Vec<u8>> {
        if self.pending.len() < n {
            return Err(Error::Truncated);
        }
        Ok(self.pending[..n].to_vec())
    }

    pub fn fill(&mut self, want: usize, timeout: Duration) -> Result<bool> {
        let n = self.fill_pending(want.max(16384).min(65536), timeout)?;
        Ok(n > 0)
    }

    pub fn take_buffered(&mut self, size: usize, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        while self.pending.len() < size {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let want = size - self.pending.len();
            let chunk = self.read_some(want.max(16384).min(65536), remaining)?;
            if chunk.is_empty() {
                break;
            }
            self.pending.extend_from_slice(&chunk);
        }
        let take = size.min(self.pending.len());
        let out = self.pending[..take].to_vec();
        self.pending.drain(..take);
        Ok(out)
    }

    pub fn read_frame(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut data: Vec<u8> = Vec::with_capacity(FRAME_HEADER_SIZE);
        let mut expected = FRAME_HEADER_SIZE;

        while data.len() < expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let chunk = self.recv_exact(expected - data.len(), remaining)?;
            if chunk.is_empty() {
                break;
            }
            data.extend_from_slice(&chunk);
            if data.len() == FRAME_HEADER_SIZE {
                let (_, _, _, _, len) = frame_decode(&data)?;
                expected += len as usize;
            }
        }

        if data.len() != expected {
            if std::env::var("HWSHARE_DEBUG").is_ok() {
                eprintln!(
                    "[rust-io] read_frame 不完整: 收到 {} 期望 {} 头={:02X?}",
                    data.len(), expected,
                    &data[..data.len().min(24)]
                );
            }
            self.close_reason = "truncated";
            return Err(Error::Truncated);
        }
        crate::trace::frame(&self.label, "rx", &data, self.conn);
        Ok(data)
    }

    pub fn try_read_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + timeout;

        loop {
            if self.pending.len() >= FRAME_HEADER_SIZE {
                let (_, _, _, _, len) = frame_decode(&self.pending[..FRAME_HEADER_SIZE])
                    .map_err(|e| {
                        if debug_io() {
                            let n = self.pending.len().min(40);
                            eprintln!("[io] 帧头非法({n}B): {:02X?}", &self.pending[..n]);
                        }
                        e
                    })?;
                let total = FRAME_HEADER_SIZE + len as usize;
                if self.pending.len() >= total {
                    let frame = self.pending[..total].to_vec();
                    self.pending.drain(..total);
                    crate::trace::frame(&self.label, "rx", &frame, self.conn);
                    return Ok(Some(frame));
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let want = if self.pending.len() < FRAME_HEADER_SIZE {
                FRAME_HEADER_SIZE - self.pending.len()
            } else {
                let (_, _, _, _, len) = frame_decode(&self.pending[..FRAME_HEADER_SIZE])?;
                (FRAME_HEADER_SIZE + len as usize).saturating_sub(self.pending.len()).max(1)
            };
            if self.fill_pending(want.max(16384).min(65536), remaining)? == 0 {
                return Ok(None);
            }
        }
    }

    pub fn try_read_dfile(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        const DFILE_HEADER: usize = 8;
        let deadline = Instant::now() + timeout;

        loop {
            if self.pending.len() >= DFILE_HEADER {
                let size = u16::from_be_bytes([self.pending[6], self.pending[7]]) as usize;
                let total = DFILE_HEADER + size;
                if self.pending.len() >= total {
                    let frame = self.pending[..total].to_vec();
                    self.pending.drain(..total);
                    crate::trace::frame(&self.label, "rx", &frame, self.conn);
                    return Ok(Some(frame));
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let want = if self.pending.len() < DFILE_HEADER {
                DFILE_HEADER - self.pending.len()
            } else {
                let size = u16::from_be_bytes([self.pending[6], self.pending[7]]) as usize;
                (DFILE_HEADER + size).saturating_sub(self.pending.len()).max(1)
            };
            if self.fill_pending(want.max(16384).min(65536), remaining)? == 0 {
                return Ok(None);
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.close_reason = "shutdown";
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if !crate::trace::enabled() {
            return;
        }

        if !self.traced_open {
            self.ensure_trace_open();
        }

        if !self.pending.is_empty() {
            crate::trace::frame_partial(&self.label, "rx", &self.pending, self.conn);
        }
        crate::trace::channel_close(
            &self.label,
            self.tx_bytes,
            self.rx_bytes,
            self.traced_t0.elapsed().as_millis(),
            self.close_reason,
            self.conn,
        );
    }
}

pub struct Listener {
    inner: TcpListener,
    pub ip: String,
    pub port: u16,
}

impl Listener {
    pub fn bind(ip: &str, port: u16) -> Result<Self> {
        let addr = format!("{ip}:{port}");
        let sock: std::net::SocketAddr = addr.parse().map_err(|_| Error::Argument)?;
        let inner = TcpListener::bind(sock)
            .map_err(|e| Error::Io(format!("监听 {addr} 失败: {}", friendly_io(&e))))?;
        let bound = inner.local_addr().map_err(|e| Error::Io(e.to_string()))?;
        inner
            .set_nonblocking(false)
            .map_err(|e| Error::Io(e.to_string()))?;

        crate::trace::listen("tcp", &bound.to_string());
        Ok(Self { inner, ip: ip.to_string(), port: bound.port() })
    }

    pub fn try_accept(&self) -> Option<Channel> {
        self.inner.set_nonblocking(true).ok()?;
        let result = self.inner.accept();
        let _ = self.inner.set_nonblocking(false);
        match result {
            Ok((stream, addr)) => {
                let local = stream
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| format!("{}:{}", self.ip, self.port));
                crate::trace::note("tcp", &format!("accept {} → 本机 {local}", addr));
                Channel::from_stream(stream, addr.ip().to_string()).ok()
            }
            Err(_) => None,
        }
    }

    pub fn accept(&self, timeout: Duration) -> Result<Channel> {
        struct Restore<'a>(&'a TcpListener);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                let _ = self.0.set_nonblocking(false);
            }
        }
        self.inner
            .set_nonblocking(true)
            .map_err(|e| Error::Io(e.to_string()))?;
        let _restore = Restore(&self.inner);

        let deadline = Instant::now() + timeout;
        let mut spins = 0u32;
        loop {
            match self.inner.accept() {
                Ok((stream, addr)) => {
                    let local = stream
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| format!("{}:{}", self.ip, self.port));
                    crate::trace::note(
                        "tcp",
                        &format!("accept {} → 本机 {local}", addr),
                    );
                    return Channel::from_stream(stream, addr.ip().to_string());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Error::Io("等待对端连接超时".into()));
                    }

                    spins += 1;
                    std::thread::sleep(if spins <= 20 {
                        Duration::from_millis(1)
                    } else {
                        Duration::from_millis(20)
                    });
                }
                Err(e) => {
                    return Err(Error::Io(format!("accept 失败: {}", friendly_io(&e))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_encode;

    #[test]
    fn reads_dfile_frames_in_sequence() {
        let listener = Listener::bind("127.0.0.1", 0).unwrap();
        let port = listener.port;
        let writer = std::thread::spawn(move || {
            let mut c = Channel::connect("127.0.0.1", port, Duration::from_secs(5)).unwrap();
            c.send(&crate::transfer::dfile_settings(true)).unwrap();
            let pkt = crate::transfer::dfile_packet(11, 0, 0, 0, b"xyz").unwrap();
            c.send(&pkt).unwrap();
            std::thread::sleep(Duration::from_millis(120));
        });

        let mut chan = listener.accept(Duration::from_secs(5)).unwrap();
        let first = chan
            .try_read_dfile(Duration::from_millis(500))
            .unwrap()
            .expect("应能读到 settings 帧");
        assert_eq!(first[0], 8, "kind 应为 SETTINGS");
        assert_eq!(first.len(), 8 + 100, "settings 负载 100 字节");
        assert_eq!(first[6..8], 100u16.to_be_bytes());

        let second = chan
            .try_read_dfile(Duration::from_millis(500))
            .unwrap()
            .expect("应能读到第二帧，且不串帧");
        assert_eq!(second[0], 11);
        assert_eq!(&second[8..], b"xyz");

        writer.join().unwrap();
    }

    #[test]
    fn frame_over_tcp() {
        let listener = Listener::bind("127.0.0.1", 0).unwrap();
        let port = listener.port;

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            let mut c = Channel::connect("127.0.0.1", port, Duration::from_secs(3)).unwrap();
            let frame = frame_encode(9, 7, 0, b"hello").unwrap();
            c.send(&frame).unwrap();
            c.send(&frame).unwrap();
        });

        let mut server = listener.accept(Duration::from_secs(3)).unwrap();
        let first = server.read_frame(Duration::from_secs(2)).unwrap();
        assert_eq!(first.len(), FRAME_HEADER_SIZE + 5);
        let (_, module, seq, _, len) = frame_decode(&first).unwrap();
        assert_eq!((module, seq, len), (9, 7, 5));

        let second = server.read_frame(Duration::from_secs(2)).unwrap();
        assert_eq!(&second[FRAME_HEADER_SIZE..], b"hello");
        handle.join().unwrap();
    }

    #[test]
    fn failed_send_does_not_count_bytes() {
        let listener = Listener::bind("127.0.0.1", 0).unwrap();
        let port = listener.port;

        let mut chan = Channel::connect("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        let _peer = listener.accept(Duration::from_secs(5)).unwrap();

        chan.stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(chan.send(b"hello").is_err());
        assert_eq!(chan.tx_bytes, 0, "写失败不能计进 tx_bytes");
        assert_eq!(chan.close_reason, "write-error");
    }

    #[test]
    fn put_back_restores_drained_bytes_at_front() {
        let listener = Listener::bind("127.0.0.1", 0).unwrap();
        let port = listener.port;
        let handle = std::thread::spawn(move || {
            let mut c = Channel::connect("127.0.0.1", port, Duration::from_secs(3)).unwrap();
            c.send(&frame_encode(9, 1, 0, b"first").unwrap()).unwrap();
            c.send(&frame_encode(9, 2, 0, b"second").unwrap()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let mut chan = listener.accept(Duration::from_secs(3)).unwrap();

        let clone = chan.try_clone_stream().unwrap();
        clone.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut taken = vec![0u8; FRAME_HEADER_SIZE + 5];
        (&clone).read_exact(&mut taken).unwrap();
        assert_eq!(&taken[FRAME_HEADER_SIZE..], b"first");

        chan.put_back(&taken);

        let first = chan.read_frame(Duration::from_secs(2)).unwrap();
        assert_eq!(&first[FRAME_HEADER_SIZE..], b"first", "还回来的字节要排在队首");
        let second = chan.read_frame(Duration::from_secs(2)).unwrap();
        assert_eq!(&second[FRAME_HEADER_SIZE..], b"second");
        assert_eq!(
            chan.rx_bytes,
            (FRAME_HEADER_SIZE + 5) as u64 + (FRAME_HEADER_SIZE + 6) as u64,
            "还回来的字节也要算进 rx（它们确实到过本机）"
        );
        handle.join().unwrap();
    }

    #[test]
    fn socket_has_write_timeout() {
        let listener = Listener::bind("127.0.0.1", 0).unwrap();
        let port = listener.port;
        let chan = Channel::connect("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        let _peer = listener.accept(Duration::from_secs(5)).unwrap();
        assert_eq!(chan.stream.write_timeout().unwrap(), Some(WRITE_TIMEOUT));
    }
}
