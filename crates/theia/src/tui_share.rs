//! Explicit invitation export. No network, shell, logging or clipboard reads.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use qrcode::{Color, EcLevel, QrCode};
use std::{
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum Action {
    Qr,
    Clipboard,
}

fn valid_link(link: &str) -> bool {
    link.len() <= crate::invite::MAX_URI && crate::invite::decode_wire(link).is_ok()
}
fn qr_svg(link: &str) -> Result<Option<Zeroizing<String>>, &'static str> {
    if !valid_link(link) {
        return Err("Неверное приглашение.");
    }
    // QR is finite (version 40-L byte capacity 2953); do not truncate or
    // invent a multi-QR protocol. Oversize is handled by protected URI export.
    let Ok(code) = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::L) else {
        return Ok(None);
    };
    let width = code.width();
    let size = width + 8;
    let mut svg = Zeroizing::new(format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" width=\"{}\" height=\"{}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path fill=\"black\" d=\"", size*4,size*4));
    for y in 0..width {
        for x in 0..width {
            if code[(x, y)] == Color::Dark {
                write!(&mut *svg, "M{} {}h1v1h-1z", x + 4, y + 4)
                    .map_err(|_| "QR не сформирован.")?;
            }
        }
    }
    svg.push_str("\"/></svg>");
    Ok(Some(svg))
}

pub(crate) fn export_qr(config: &Path, link: &str) -> Result<(PathBuf, bool), &'static str> {
    match qr_svg(link)? {
        Some(svg) => {
            let mut guard = crate::client_import::PrivateBearer::create_payload(
                config,
                "qr",
                "invitation.svg",
                svg.as_bytes(),
            )
            .map_err(|_| "Защищённый QR не сохранён.")?;
            let reference = guard.reference().map_err(|_| "Неверный путь QR.")?;
            let path = PathBuf::from(reference.strip_prefix("file:").ok_or("Неверный путь QR.")?);
            guard.commit();
            Ok((path, true))
        }
        None => crate::client_import::export_encoded_invitation(config, link)
            .map(|p| (p, false))
            .map_err(|_| "Приглашение не помещается в QR, защищённый URI-файл не сохранён."),
    }
}

/// OSC 52 is a request to the attached terminal, not an acknowledgement.
/// No clipboard readback, no clipboard history manipulation, no automatic
/// clearing (which might overwrite something the user subsequently copied).
pub(crate) fn send_clipboard(mut out: impl io::Write, link: &str) -> io::Result<()> {
    if !valid_link(link) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid invitation",
        ));
    }
    let encoded = Zeroizing::new(STANDARD.encode(link));
    out.write_all(b"\x1b]52;c;")?;
    out.write_all(encoded.as_bytes())?;
    out.write_all(b"\x07")?;
    out.flush()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qr_has_quiet_zone_and_no_uri_metadata_clipboard_is_exact() {
        let crate::config::Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let link = crate::invite::Invitation::public_from_profile(&doc.client.profiles[0])
            .unwrap()
            .encode()
            .unwrap();
        let svg = qr_svg(&link).unwrap().unwrap();
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("M4 4h1v1h-1z"));
        assert!(!svg.contains(&link));
        let mut bytes = Vec::new();
        send_clipboard(&mut bytes, &link).unwrap();
        let encoded = bytes
            .strip_prefix(b"\x1b]52;c;")
            .unwrap()
            .strip_suffix(b"\x07")
            .unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), link.as_bytes());
        let mut invalid = Vec::new();
        assert!(send_clipboard(&mut invalid, "not a link\x07").is_err());
        assert!(invalid.is_empty());
        assert!(qr_svg("invalid").is_err());
    }

    #[test]
    fn protected_qr_export_is_complete_and_create_new() {
        let crate::config::Config::Client(doc) =
            crate::config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let link = crate::invite::Invitation::public_from_profile(&doc.client.profiles[0])
            .unwrap()
            .encode()
            .unwrap();
        let dir = std::env::temp_dir().join(crate::tui_editor::generated_id("qr-test").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let config = dir.join("client.toml");
        let (first, is_qr) = export_qr(&config, &link).unwrap();
        assert!(is_qr);
        let (second, is_qr) = export_qr(&config, &link).unwrap();
        assert!(is_qr && first != second);
        let expected = qr_svg(&link).unwrap().unwrap();
        for path in [first, second] {
            let actual = crate::bounded_input::read(&path, 2 * 1024 * 1024, true, true).unwrap();
            assert_eq!(&actual[..], expected.as_bytes());
        }
        assert!(!config.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
