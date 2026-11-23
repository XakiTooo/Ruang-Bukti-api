use crate::crypto::{self, Envelope, R};
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"STEG1";

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut check = Vec::with_capacity(4 + data.len());
    check.extend_from_slice(kind);
    check.extend_from_slice(data);
    out.extend_from_slice(&crc32(&check).to_be_bytes());
}

fn encode_uncompressed_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let stride = (width as usize) * 3;
    let mut raw = Vec::with_capacity((stride + 1) * (height as usize));
    for row in 0..(height as usize) {
        raw.push(0); // filter type 0 (None)
        raw.extend_from_slice(&rgb[row * stride..(row + 1) * stride]);
    }
    let mut zlib = Vec::with_capacity(raw.len() + 64);
    zlib.extend_from_slice(&[0x78, 0x01]); // zlib header (no compression)
    let chunks: Vec<&[u8]> = raw.chunks(65_535).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let last = u8::from(index + 1 == chunks.len());
        let len = chunk.len() as u16;
        zlib.push(last);
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(chunk);
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut png = Vec::with_capacity(zlib.len() + 64);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
    write_chunk(&mut png, b"IHDR", &ihdr);
    write_chunk(&mut png, b"IDAT", &zlib);
    write_chunk(&mut png, b"IEND", &[]);
    png
}

fn read_carrier(bytes: &[u8]) -> R<image::RgbImage> {
    if bytes.len() > 1_000_000 { return Err("Gambar pembawa maksimal 1 MB.".into()); }
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()
        .map_err(|_| "Format gambar tidak terbaca.")?;
    if !matches!(reader.format(), Some(image::ImageFormat::Png | image::ImageFormat::Jpeg)) {
        return Err("Pilih gambar PNG atau JPEG.".into());
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    reader.decode().map(|img| if img.width() > 256 || img.height() > 256 { img.thumbnail(256, 256).to_rgb8() } else { img.to_rgb8() }).map_err(|_| "Gambar rusak atau melebihi 4096 × 4096 piksel.".to_owned())
}

pub fn cover_png(bytes: &[u8]) -> R<Vec<u8>> {
    let rgb = read_carrier(bytes)?;
    Ok(encode_uncompressed_png(rgb.width(), rgb.height(), rgb.as_raw()))
}

pub fn seal_png_message(master: &[u8; 32], message: &str, context_id: &str, carrier: &[u8]) -> R<Vec<u8>> {
    let trimmed = message.trim();
    if trimmed.is_empty() || trimmed.len() > 400 {
        return Err("Pesan gambar harus antara 1 sampai 400 karakter.".into());
    }
    let context = format!("ruang-bukti:{context_id}:stego");
    let key = Zeroizing::new(crypto::key(master, &context));
    let envelope = crypto::seal(&key, trimmed.as_bytes(), &context, false)?;
    let payload = serde_json::to_vec(&envelope).map_err(|_| "Gagal membungkus pesan steganografi.")?;

    let mut packet = Vec::with_capacity(9 + payload.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(&payload);

    let image = read_carrier(carrier)?;
    let (width, height) = image.dimensions();
    let mut rgb = image.into_raw();
    if packet.len() * 8 > rgb.len() {
        return Err("Gambar terlalu kecil untuk pesan ini. Pilih gambar lebih besar.".into());
    }
    for (bit_idx, bit) in packet.iter().flat_map(|b| (0..8).rev().map(move |shift| (b >> shift) & 1)).enumerate() {
        rgb[bit_idx] = (rgb[bit_idx] & 0xFE) | bit;
    }
    Ok(encode_uncompressed_png(width, height, &rgb))
}

pub fn open_png_message(master: &[u8; 32], png: &[u8], context_id: &str) -> R<String> {
    let rgb = read_carrier(png)?.into_raw();
    let read_byte = |byte_idx: usize| -> u8 {
        (0..8).fold(0u8, |acc, bit| (acc << 1) | (rgb[byte_idx * 8 + bit] & 1))
    };
    if rgb.len() < 72 || &(0..5).map(read_byte).collect::<Vec<u8>>()[..] != MAGIC {
        return Err("Header STEG1 tidak ditemukan pada citra PNG.".into());
    }
    let len = u32::from_be_bytes([read_byte(5), read_byte(6), read_byte(7), read_byte(8)]) as usize;
    if len == 0 || len > 4096 || (9 + len) * 8 > rgb.len() {
        return Err("Panjang muatan steganografi tidak valid.".into());
    }
    let payload: Vec<u8> = (9..9 + len).map(read_byte).collect();
    let envelope: Envelope = serde_json::from_slice(&payload).map_err(|_| "Amplop AES-256-GCM pada citra rusak.")?;
    let context = format!("ruang-bukti:{context_id}:stego");
    let key = Zeroizing::new(crypto::key(master, &context));
    let plain = crypto::open(&key, &envelope, &context)?;
    String::from_utf8(plain).map_err(|_| "Teks steganografi bukan UTF-8 yang valid.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uploaded_compressed_png_preserves_dimensions_and_only_changes_lsb() {
        let mut source = image::RgbImage::new(100, 90);
        for (x, y, pixel) in source.enumerate_pixels_mut() {
            *pixel = image::Rgb([x as u8, y as u8, 200]);
        }
        let mut uploaded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(source.clone()).write_to(&mut uploaded, image::ImageFormat::Png).unwrap();
        let cover = cover_png(uploaded.get_ref()).unwrap();
        let output = seal_png_message(&[5; 32], "pesan uji", "bukti-1", uploaded.get_ref()).unwrap();
        let decoded = read_carrier(&output).unwrap();
        assert_eq!(decoded.dimensions(), source.dimensions());
        assert_eq!(cover.len(), output.len());
        for (before, after) in source.as_raw().iter().zip(decoded.as_raw()) {
            assert_eq!(before & 0xfe, after & 0xfe);
        }
        assert_eq!(open_png_message(&[5; 32], &output, "bukti-1").unwrap(), "pesan uji");
        assert!(open_png_message(&[6; 32], &output, "bukti-1").is_err());
        assert!(open_png_message(&[5; 32], &output[..100], "bukti-1").is_err());
    }

    #[test]
    fn stego_png_roundtrip_and_context_protection() {
        let master = [5u8; 32];
        let msg = "Periksa koneksi Android-2F pukul 19.25 WIB.";
        let cover = encode_uncompressed_png(80, 60, &vec![120; 80 * 60 * 3]);
        let png = seal_png_message(&master, msg, "SIM-BB/001:BB-001", &cover).unwrap();
        assert_eq!(png.len(), cover.len());
        assert_ne!(png, cover);
        assert!(seal_png_message(&master, msg, "ctx", b"not an image").is_err());
        let tiny = encode_uncompressed_png(1, 1, &[120; 3]);
        assert!(seal_png_message(&master, msg, "ctx", &tiny).is_err());
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let extracted = open_png_message(&master, &png, "SIM-BB/001:BB-001").unwrap();
        assert_eq!(extracted, msg);
        assert!(open_png_message(&master, &png, "SIM-BB/001:BB-002").is_err());
    }
}
