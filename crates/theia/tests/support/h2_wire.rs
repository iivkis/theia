//! Bounded test-only inspector of **decrypted** H2 client frames.
//! Values are never returned: HEADER blocks may contain Authorization.
//! No production code imports this module. This is NOT a Chrome profile.
use std::io;

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CAPTURE: usize = 65_536;
const MAX_FRAME: usize = 16_384;
const MAX_HEADERS: usize = 32_768;

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub settings: Vec<(u16, u32)>,
    pub frames_before_headers: Vec<u8>,
    /// Increment values of valid connection-level WINDOW_UPDATE frames before
    /// the first request, without retaining any header or application bytes.
    /// Timing varies: absence here does not mean a different TLS/H2 profile.
    pub connection_window_updates: Vec<u32>,
    /// Timing-dependent acknowledgement of the server's SETTINGS; not a
    /// client fingerprint parameter, so excluded from frame-order matching.
    pub settings_ack_before_headers: bool,
    pub pseudo_headers: Vec<&'static str>,
    pub ordinary_fields: usize,
    pub request_end_stream: bool,
}

impl Observation {
    #[allow(dead_code)]
    pub fn sanitized_json(&self) -> String {
        let settings: Vec<[u32; 2]> = self.settings.iter().map(|&(id, value)| [u32::from(id), value]).collect();
        format!(
            "{{\"settings\":{:?},\"frames_before_headers\":{:?},\"connection_window_updates\":{:?},\"pseudo_headers\":{:?},\"ordinary_fields\":{},\"request_end_stream\":{}}}",
            settings, self.frames_before_headers, self.connection_window_updates, self.pseudo_headers,
            self.ordinary_fields, self.request_end_stream
        )
    }
}

fn read_int(data: &[u8], cursor: &mut usize, prefix: u8) -> Result<usize, &'static str> {
    let first = *data.get(*cursor).ok_or("truncated HPACK integer")?;
    *cursor += 1;
    let mask = (1usize << prefix) - 1;
    let mut value = usize::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    for shift in (0..=28).step_by(7) {
        let b = *data.get(*cursor).ok_or("truncated HPACK continuation")?;
        *cursor += 1;
        value = value
            .checked_add(usize::from(b & 0x7f) << shift)
            .ok_or("HPACK integer overflow")?;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("HPACK integer too long")
}

fn read_string<'a>(data: &'a [u8], cursor: &mut usize) -> Result<(&'a [u8], bool), &'static str> {
    let huffman = data.get(*cursor).ok_or("truncated HPACK string")? & 0x80 != 0;
    let length = read_int(data, cursor, 7)?;
    let end = cursor.checked_add(length).ok_or("HPACK string overflow")?;
    let bytes = data
        .get(*cursor..end)
        .ok_or("truncated HPACK string body")?;
    *cursor = end;
    Ok((bytes, huffman))
}

fn static_name(index: usize) -> Result<Option<&'static str>, &'static str> {
    match index {
        1 => Ok(Some(":authority")),
        2 | 3 => Ok(Some(":method")),
        4 | 5 => Ok(Some(":path")),
        6 | 7 => Ok(Some(":scheme")),
        8..=14 => Err("response-only pseudo-header in client request"),
        15..=61 => Ok(None),
        _ => Err("unsupported dynamic/out-of-range HPACK name index"),
    }
}

/// Inspect HPACK *field names only*. First request's dynamic table is empty;
/// reject unknown dynamic name references rather than fabricate their order.
fn header_order(block: &[u8]) -> Result<(Vec<&'static str>, usize), &'static str> {
    let mut cursor = 0;
    let mut pseudo = Vec::new();
    let mut ordinary = 0usize;
    let mut regular_started = false;
    let mut seen_field = false;
    while cursor < block.len() {
        let first = block[cursor];
        if first & 0xe0 == 0x20 {
            if seen_field {
                return Err("HPACK dynamic table update inside fields");
            }
            read_int(block, &mut cursor, 5)?;
            continue;
        }
        seen_field = true;
        let name = if first & 0x80 != 0 {
            let index = read_int(block, &mut cursor, 7)?;
            static_name(index)?
        } else {
            let prefix = if first & 0x40 != 0 { 6 } else { 4 };
            let name_index = read_int(block, &mut cursor, prefix)?;
            let name = if name_index == 0 {
                let (raw, huffman) = read_string(block, &mut cursor)?;
                if huffman {
                    // Chromium compresses ordinary header *names*. The
                    // observer never decodes or logs those bytes. Refuse
                    // unknown Huffman names until all four recognized
                    // pseudo fields are present; no name order is guessed.
                    if pseudo.len() != 4 {
                        return Err("Huffman name before complete pseudo-header set");
                    }
                    None
                } else {
                    match raw {
                        b":authority" => Some(":authority"),
                        b":method" => Some(":method"),
                        b":path" => Some(":path"),
                        b":scheme" => Some(":scheme"),
                        _ if raw.starts_with(b":") => {
                            return Err("unknown request pseudo-header");
                        }
                        _ => None,
                    }
                }
            } else {
                static_name(name_index)?
            };
            // The value may be Huffman encoded and may contain credentials.
            // Only skip it; never copy, decode or log it.
            read_string(block, &mut cursor)?;
            name
        };
        if let Some(name) = name {
            if regular_started || pseudo.contains(&name) {
                return Err("duplicate or out-of-order pseudo-header");
            }
            pseudo.push(name);
        } else {
            regular_started = true;
            ordinary += 1;
        }
        if pseudo.len() + ordinary > 64 {
            return Err("too many HPACK header fields");
        }
    }
    for required in [":method", ":authority", ":scheme", ":path"] {
        if !pseudo.contains(&required) {
            return Err("required request pseudo-header missing");
        }
    }
    Ok((pseudo, ordinary))
}

/// Only first client SETTINGS and first request HEADERS. Frames after the
/// request are intentionally not parsed; this is a bounded fingerprint sample.
pub fn inspect(bytes: &[u8]) -> Result<Observation, &'static str> {
    if bytes.len() > MAX_CAPTURE || !bytes.starts_with(CLIENT_PREFACE) {
        return Err("invalid/bounded H2 client connection preface");
    }
    let mut cursor = CLIENT_PREFACE.len();
    let mut settings = None;
    let mut prior = Vec::new();
    let mut connection_window_updates = Vec::new();
    let mut headers = Vec::new();
    let mut in_headers = false;
    let mut settings_ack_before_headers = false;
    let mut end_stream = false;
    loop {
        let header_end = cursor.checked_add(9).ok_or("H2 frame overflow")?;
        let frame = bytes
            .get(cursor..header_end)
            .ok_or("incomplete H2 frame header")?;
        cursor = header_end;
        let length =
            (usize::from(frame[0]) << 16) | (usize::from(frame[1]) << 8) | usize::from(frame[2]);
        if length > MAX_FRAME {
            return Err("H2 frame size exceeds default limit");
        }
        let end = cursor.checked_add(length).ok_or("H2 frame overflow")?;
        let payload = bytes
            .get(cursor..end)
            .ok_or("incomplete H2 frame payload")?;
        cursor = end;
        let kind = frame[3];
        let flags = frame[4];
        let stream = u32::from_be_bytes(frame[5..9].try_into().unwrap());
        if stream & 0x8000_0000 != 0 {
            return Err("reserved H2 stream bit");
        }
        if settings.is_none() {
            if kind != 4 || flags != 0 || stream != 0 || length % 6 != 0 {
                return Err("client preface must start with SETTINGS");
            }
            let mut entries = Vec::new();
            for pair in payload.as_chunks::<6>().0 {
                entries.push((
                    u16::from_be_bytes(pair[..2].try_into().unwrap()),
                    u32::from_be_bytes(pair[2..].try_into().unwrap()),
                ));
            }
            settings = Some(entries);
            continue;
        }

        if in_headers && (kind != 9 || stream != 1) {
            return Err("non-CONTINUATION frame inside HEADERS");
        }
        // A client may ACK the server's SETTINGS before or after its first
        // HEADERS depending on scheduling. This is a valid control response,
        // not a stable H2 fingerprint parameter. Never accept malformed ACK.
        if kind == 4 && !in_headers {
            if stream != 0 || flags != 1 || length != 0 {
                return Err("unexpected/malformed subsequent client SETTINGS");
            }
            settings_ack_before_headers = true;
            continue;
        }
        if kind == 8 && !in_headers {
            if flags != 0 || stream != 0 || length != 4 {
                return Err("malformed first-flight connection WINDOW_UPDATE");
            }
            let increment = u32::from_be_bytes(payload.try_into().unwrap());
            if increment == 0 || increment & 0x8000_0000 != 0 {
                return Err("zero or reserved-bit WINDOW_UPDATE credit");
            }
            if connection_window_updates.len() >= 4 {
                return Err("too many connection WINDOW_UPDATE frames before HEADERS");
            }
            connection_window_updates.push(increment);
            prior.push(kind);
            continue;
        }
        if kind == 1 && !in_headers {
            if stream != 1 {
                return Err("first request must use stream 1");
            }
            end_stream = flags & 1 != 0;
            let mut offset = 0usize;
            let padding = if flags & 8 != 0 {
                offset = 1;
                usize::from(*payload.first().ok_or("missing pad length")?)
            } else {
                0
            };
            if flags & 0x20 != 0 {
                offset += 5;
            }
            if payload.len() < offset + padding {
                return Err("invalid padded HEADERS");
            }
            headers.extend_from_slice(&payload[offset..payload.len() - padding]);
            if headers.len() > MAX_HEADERS {
                return Err("HPACK header block too large");
            }
            in_headers = true;
        } else if kind == 9 && in_headers {
            headers.extend_from_slice(payload);
            if headers.len() > MAX_HEADERS {
                return Err("HPACK header block too large");
            }
        } else if !in_headers {
            if prior.len() >= 16 {
                return Err("too many frames before first HEADERS");
            }
            prior.push(kind);
            continue;
        } else {
            return Err("unexpected frame while decoding HEADERS");
        }
        if flags & 4 != 0 {
            let (pseudo_headers, ordinary_fields) = header_order(&headers)?;
            headers.fill(0); // HPACK may contain the ephemeral auth token.
            return Ok(Observation {
                settings: settings.unwrap(),
                frames_before_headers: prior,
                connection_window_updates,
                settings_ack_before_headers,
                pseudo_headers,
                ordinary_fields,
                request_end_stream: end_stream,
            });
        }
    }
}

/// Converts parser error into an IO error without including untrusted bytes.
pub fn capture_error() -> io::Error {
    io::Error::other("test-only H2 capture exceeded bounded transcript size")
}

pub const MAX_CAPTURE_BYTES: usize = MAX_CAPTURE;

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, body.len() as u8, kind, flags];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn example() -> Vec<u8> {
        let mut raw = CLIENT_PREFACE.to_vec();
        raw.extend(frame(4, 0, 0, &[0, 1, 0, 0, 0, 0x64]));
        // Four static pseudo-header indexes: method POST, scheme https,
        // path /, authority (empty static-table value).
        raw.extend(frame(1, 4, 1, &[0x83, 0x87, 0x84, 0x81]));
        raw
    }

    #[test]
    fn preserves_first_settings_and_hpack_pseudo_wire_order() {
        let summary = inspect(&example()).unwrap();
        assert_eq!(summary.settings, [(1, 100)]);
        assert_eq!(
            summary.pseudo_headers,
            [":method", ":scheme", ":path", ":authority"]
        );
        assert!(!summary.request_end_stream);
    }

    #[test]
    fn ignores_valid_timing_dependent_settings_ack_but_rejects_malformed_ack() {
        let mut raw = CLIENT_PREFACE.to_vec();
        raw.extend(frame(4, 0, 0, &[0, 6, 0, 0, 0x20, 0]));
        raw.extend(frame(4, 1, 0, &[])); // valid SETTINGS ACK, not H2 profile
        raw.extend(frame(1, 4, 1, &[0x83, 0x87, 0x84, 0x81]));
        let observed = inspect(&raw).unwrap();
        assert!(observed.settings_ack_before_headers);
        assert!(observed.frames_before_headers.is_empty());
        let mut malformed = raw;
        // Nonempty SETTINGS ACK payload is forbidden, even if it arrives early.
        malformed[CLIENT_PREFACE.len() + 9 + 6] = 0;
        malformed[CLIENT_PREFACE.len() + 9 + 6 + 1] = 0;
        malformed[CLIENT_PREFACE.len() + 9 + 6 + 2] = 1;
        assert!(inspect(&malformed).is_err());
    }

    #[test]
    fn observes_valid_connection_window_update_increment_before_headers() {
        let mut raw = CLIENT_PREFACE.to_vec();
        raw.extend(frame(4, 0, 0, &[0, 2, 0, 0, 0, 0]));
        raw.extend(frame(8, 0, 0, &15_663_105u32.to_be_bytes()));
        raw.extend(frame(1, 4, 1, &[0x83, 0x87, 0x81, 0x84]));
        let observed = inspect(&raw).unwrap();
        assert_eq!(observed.connection_window_updates, [15_663_105]);
        assert_eq!(observed.frames_before_headers, [8]);
        assert_eq!(observed.pseudo_headers.len(), 4);
    }

    #[test]
    fn refuses_invalid_first_flight_window_update_without_guessing_credit() {
        for (flags, stream, body) in [
            (0, 0, 0u32.to_be_bytes().to_vec()),
            (0, 0, 0x8000_0001u32.to_be_bytes().to_vec()),
            (1, 0, 1u32.to_be_bytes().to_vec()),
            (0, 1, 1u32.to_be_bytes().to_vec()),
            (0, 0, vec![0, 1, 2]),
        ] {
            let mut raw = CLIENT_PREFACE.to_vec();
            raw.extend(frame(4, 0, 0, &[]));
            raw.extend(frame(8, flags, stream, &body));
            raw.extend(frame(1, 4, 1, &[0x83, 0x87, 0x81, 0x84]));
            assert!(inspect(&raw).is_err(), "bad WINDOW_UPDATE must fail");
        }
    }

    #[test]
    fn allows_huffman_literal_ordinary_header_name_only_after_all_pseudos() {
        // Four indexed pseudo headers followed by one Huffman-literal name.
        // Its contents are NEVER decoded, copied into Observation or logged.
        let mut valid = CLIENT_PREFACE.to_vec();
        valid.extend(frame(4, 0, 0, &[0, 6, 0, 0, 0x20, 0]));
        valid.extend(frame(1, 4, 1, &[0x83, 0x87, 0x81, 0x84, 0, 0x81, 0xff, 0]));
        let obs = inspect(&valid).unwrap();
        assert_eq!(obs.pseudo_headers.len(), 4);
        assert_eq!(obs.ordinary_fields, 1);

        let mut premature = CLIENT_PREFACE.to_vec();
        premature.extend(frame(4, 0, 0, &[]));
        premature.extend(frame(1, 4, 1, &[0, 0x81, 0xff, 0, 0x83, 0x87, 0x81, 0x84]));
        assert!(inspect(&premature).is_err());
    }

    #[test]
    fn rejects_malformed_or_truncated_h2_without_leaking_values() {
        let mut bad = example();
        bad[24 + 3] = 1; // SETTINGS replaced with HEADERS
        assert!(inspect(&bad).is_err());
        let mut short = example();
        short.truncate(short.len() - 1);
        assert!(inspect(&short).is_err());
        let mut misplaced = example();
        misplaced.extend_from_slice(b"secret-never-logged");
        // Trailing application DATA is intentionally excluded from fingerprint.
        assert!(inspect(&misplaced).is_ok());
    }

    #[test]
    fn rejects_missing_and_duplicate_pseudo_fields() {
        let mut missing = CLIENT_PREFACE.to_vec();
        missing.extend(frame(4, 0, 0, &[]));
        missing.extend(frame(1, 4, 1, &[0x83, 0x87, 0x84]));
        assert!(inspect(&missing).is_err());

        let mut dup = CLIENT_PREFACE.to_vec();
        dup.extend(frame(4, 0, 0, &[]));
        dup.extend(frame(1, 4, 1, &[0x83, 0x83, 0x87, 0x84, 0x81]));
        assert!(inspect(&dup).is_err());
    }
}
