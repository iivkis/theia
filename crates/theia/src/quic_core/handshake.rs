//! TLS CRYPTO stream driver. Incoming data must be opened with the
//! corresponding packet protection keys before it is passed here.
//! No UDP I/O, CID validation, admission or H3 is implemented by this driver.
use super::stream::{ReceiveBuffer, ReceiveError};
use rustls::quic::{Connection, KeyChange};

const MAX_CRYPTO: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level { Initial, Handshake, Application }

#[derive(Debug)]
pub enum Error { Level, Limit, Receive(ReceiveError), Tls(rustls::Error), Failed }

pub struct Flight {
    pub level: Level,
    pub offset: u64,
    pub data: Vec<u8>,
    /// Keys apply to subsequent output, never to data in this Flight.
    pub keys: Option<KeyChange>,
}

pub struct Driver {
    tls: Connection,
    level: Level,
    receive: [ReceiveBuffer; 3],
    sent: [u64; 3],
    failed: bool,
}

impl Driver {
    pub fn new(tls: Connection) -> Self {
        Self {
            tls, level: Level::Initial,
            receive: std::array::from_fn(|_| ReceiveBuffer::new(MAX_CRYPTO, MAX_CRYPTO as u64).expect("valid fixed bounds")),
            sent: [0; 3], failed: false,
        }
    }

    pub fn tls_complete(&self) -> bool { !self.failed && !self.tls.is_handshaking() }

    pub fn peer_parameters(&self) -> Option<&[u8]> {
        if self.tls_complete() { self.tls.quic_transport_parameters() } else { None }
    }

    pub(crate) fn channel_binding(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
        if !self.tls_complete() { return Err(Error::Failed); }
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        self.tls.export_keying_material(&mut key[..], crate::channel_binding::LABEL,
            Some(crate::channel_binding::H3)).map_err(Error::Tls)?;
        Ok(key)
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        if self.tls_complete() { self.tls.alpn_protocol() } else { None }
    }

    /// Consume reassembled TLS bytes at one encryption level. A future
    /// endpoint may buffer packets from an unavailable level separately.
    pub fn receive(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), Error> {
        if self.failed { return Err(Error::Failed); }
        if level as usize > self.level as usize { return Err(Error::Level); }
        let result = self.receive_inner(level, offset, data);
        if result.is_err() { self.failed = true; }
        result
    }

    fn receive_inner(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), Error> {
        let buffer = &mut self.receive[level as usize];
        buffer.insert(offset, data, false).map_err(Error::Receive)?;
        let mut scratch = [0; 4096];
        loop {
            let n = buffer.read(&mut scratch);
            if n == 0 { return Ok(()); }
            // Once TLS has changed levels, only previously consumed
            // retransmissions are accepted at an older level.
            if (level as usize) < self.level as usize && level == Level::Initial {
                return Err(Error::Level);
            }
            self.tls.read_hs(&scratch[..n]).map_err(Error::Tls)?;
        }
    }

    pub fn poll_output(&mut self) -> Result<Option<Flight>, Error> {
        if self.failed { return Err(Error::Failed); }
        let result = self.output_inner();
        if result.is_err() { self.failed = true; }
        result
    }

    fn output_inner(&mut self) -> Result<Option<Flight>, Error> {
        let level = self.level;
        let mut data = Vec::new();
        let keys = self.tls.write_hs(&mut data);
        let offset = self.sent[level as usize];
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Limit)?;
        if end > MAX_CRYPTO as u64 { return Err(Error::Limit); }
        self.sent[level as usize] = end;
        match &keys {
            Some(KeyChange::Handshake { .. }) if level == Level::Initial => self.level = Level::Handshake,
            Some(KeyChange::OneRtt { .. }) if level == Level::Handshake => self.level = Level::Application,
            Some(_) => return Err(Error::Level),
            None => {}
        }
        if data.is_empty() && keys.is_none() { return Ok(None); }
        Ok(Some(Flight { level, offset, data, keys }))
    }
}
