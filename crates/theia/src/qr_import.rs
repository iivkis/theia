//! Offline scanner for a single QR in PNG or Theia's exact exported SVG.
//! No generic SVG/XML interpreter, URL fetching, external program or telemetry.
use std::{io::Cursor, path::Path};
use zeroize::Zeroizing;

const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PIXELS: usize = 4 * 1024 * 1024;
const INVALID: &str = "Не удалось прочитать один QR с приглашением Theia.";

pub(crate) fn image_path(raw: &str) -> bool {
    !raw.starts_with("theia://")
        && Path::new(raw).extension().and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("png") || s.eq_ignore_ascii_case("svg"))
}

pub(crate) fn scan_file(raw: &str) -> Result<Zeroizing<String>, &'static str> {
    if !image_path(raw) { return Err(INVALID); }
    // A QR may contain a live credential. Explicit absolute local, regular,
    // non-symlink file; require the same private-file contract as credentials.
    let path = Path::new(raw);
    let data = crate::bounded_input::read(path, MAX_IMAGE_BYTES, true, true)
        .map_err(|_| "QR-файл должен быть локальным, абсолютным и защищённым.")?;
    if path.extension().and_then(|s| s.to_str()).is_some_and(|s| s.eq_ignore_ascii_case("png")) {
        let (w, h, pixels) = png_pixels(&data)?;
        decode(w, h, &pixels)
    } else {
        let (size, pixels) = theia_svg(&data)?;
        decode(size, size, &pixels)
    }
}

fn pixel_count(w: usize, h: usize) -> Result<usize, &'static str> {
    if w == 0 || h == 0 || w > 4096 || h > 4096 { return Err(INVALID); }
    w.checked_mul(h).filter(|n| *n <= MAX_PIXELS).ok_or(INVALID)
}
fn png_pixels(data: &[u8]) -> Result<(usize, usize, Zeroizing<Vec<u8>>), &'static str> {
    let mut decoder = png::Decoder::new_with_limits(Cursor::new(data), png::Limits { bytes: 32 * 1024 * 1024 });
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let header = decoder.read_header_info().map_err(|_| INVALID)?;
    let (w, h) = (header.width as usize, header.height as usize);
    let count = pixel_count(w, h)?;
    let mut reader = decoder.read_info().map_err(|_| INVALID)?;
    if reader.info().animation_control.is_some() { return Err(INVALID); }
    let size = reader.output_buffer_size().filter(|s| *s <= count * 4).ok_or(INVALID)?;
    let mut pixels = Zeroizing::new(vec![0; size]);
    let info = reader.next_frame(&mut pixels).map_err(|_| INVALID)?;
    if info.width as usize != w || info.height as usize != h || info.bit_depth != png::BitDepth::Eight {
        return Err(INVALID);
    }
    let channels = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err(INVALID),
    };
    if info.buffer_size() != count * channels { return Err(INVALID); }
    let mut gray = Zeroizing::new(Vec::with_capacity(count));
    for p in pixels[..info.buffer_size()].chunks_exact(channels) {
        let (lum, alpha) = match channels {
            1 => (u32::from(p[0]), 255),
            2 => (u32::from(p[0]), u32::from(p[1])),
            3 | 4 => (
                (299 * u32::from(p[0]) + 587 * u32::from(p[1]) + 114 * u32::from(p[2])) / 1000,
                if channels == 4 { u32::from(p[3]) } else { 255 },
            ),
            _ => return Err(INVALID),
        };
        gray.push(((lum * alpha + 255 * (255 - alpha)) / 255) as u8);
    }
    Ok((w, h, gray))
}

// Only the exact, bounded QR matrix format emitted by tui_share::qr_svg.
// No XML parsing, external references, attributes, scripts or arbitrary paths.
fn theia_svg(data: &[u8]) -> Result<(usize, Zeroizing<Vec<u8>>), &'static str> {
    let text = std::str::from_utf8(data).map_err(|_| INVALID)?;
    let prefix = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ";
    let rest = text.strip_prefix(prefix).ok_or(INVALID)?;
    let (n, _) = rest.split_once(' ').ok_or(INVALID)?;
    let size: usize = n.parse().map_err(|_| INVALID)?;
    if !(29..=185).contains(&size) || (size - 29) & 3 != 0 { return Err(INVALID); }
    let scaled = size * 4;
    let header = format!("{prefix}{size} {size}\" width=\"{scaled}\" height=\"{scaled}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path fill=\"black\" d=\"");
    let mut path = text.strip_prefix(&header).and_then(|s| s.strip_suffix("\"/></svg>")).ok_or(INVALID)?;
    let mut pixels = Zeroizing::new(vec![255; scaled * scaled]);
    while !path.is_empty() {
        let (x, rest) = path.strip_prefix('M').and_then(|s| s.split_once(' ')).ok_or(INVALID)?;
        let (y, rest) = rest.split_once("h1v1h-1z").ok_or(INVALID)?;
        let x: usize = x.parse().map_err(|_| INVALID)?;
        let y: usize = y.parse().map_err(|_| INVALID)?;
        if !(4..size - 4).contains(&x) || !(4..size - 4).contains(&y)
            || pixels[(y * 4) * scaled + x * 4] == 0 { return Err(INVALID); }
        for row in y * 4..y * 4 + 4 {
            pixels[row * scaled + x * 4..row * scaled + x * 4 + 4].fill(0);
        }
        path = rest;
    }
    Ok((scaled, pixels))
}

fn decode(w: usize, h: usize, pixels: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    if pixel_count(w, h)? != pixels.len() { return Err(INVALID); }
    let mut decoder = quircs::Quirc::default();
    let mut codes = decoder.identify(w, h, pixels);
    let code = codes.next().ok_or(INVALID)?.map_err(|_| INVALID)?;
    if codes.next().is_some() { return Err("В изображении несколько QR-кодов; выберите один."); }
    let data = Zeroizing::new(code.decode().map_err(|_| INVALID)?.payload);
    if data.len() > crate::invite::MAX_URI { return Err(INVALID); }
    let text = std::str::from_utf8(&data).map_err(|_| INVALID)?;
    crate::invite::decode_wire(text).map_err(|_| INVALID)?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_actual_png_qr_matrix_and_rejects_noninvitation() {
        let crate::config::Config::Client(doc) = crate::config::parse(include_str!("../../../examples/client.toml")).unwrap() else { panic!("client") };
        let link = crate::invite::Invitation::public_from_profile(&doc.client.profiles[0]).unwrap().encode().unwrap();
        let qr = qrcode::QrCode::new(link.as_bytes()).unwrap();
        let width = (qr.width() + 8) * 4;
        let mut pixels = vec![255u8; width * width];
        for y in 0..qr.width() {
            for x in 0..qr.width() {
                if qr[(x,y)] == qrcode::Color::Dark {
                    for dy in 0..4 {
                        let i = ((y+4)*4+dy)*width+(x+4)*4;
                        pixels[i..i+4].fill(0);
                    }
                }
            }
        }
        let mut png = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png, width as u32, width as u32);
            encoder.set_color(png::ColorType::Grayscale);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&pixels).unwrap();
        }
        let (w,h,p) = png_pixels(&png).unwrap();
        assert_eq!(decode(w,h,&p).unwrap().as_str(), link.as_str());
        assert!(decode(64,64,&[255;4096]).is_err());
        assert!(pixel_count(4096,4096).is_err());
        assert!(theia_svg(b"<svg onload='invalid'/>").is_err());
    }
}
