use crate::crypto::{self, Envelope, R};
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"STEG1";
const WIDTH: u32 = 80;
const HEIGHT: u32 = 60;

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

fn decode_uncompressed_png(png: &[u8]) -> R<Vec<u8>> {
    if png.len() < 33 || &png[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err("Citra pembawa PNG tidak valid.".into());
    }
    let mut pos = 8;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut idat = Vec::new();
    while pos + 12 <= png.len() {
        let len = u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
        let kind = &png[pos + 4..pos + 8];
        if pos + 12 + len > png.len() {
            return Err("Potongan citra PNG rusak.".into());
        }
        let data = &png[pos + 8..pos + 8 + len];
        if kind == b"IHDR" && len >= 8 {
            width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        } else if kind == b"IDAT" {
            idat.extend_from_slice(data);
        } else if kind == b"IEND" {
            break;
        }
        pos += 12 + len;
    }
    if width == 0 || height == 0 || idat.len() < 7 {
        return Err("Data piksel PNG tidak ditemukan.".into());
    }
    let mut raw = Vec::new();
    let mut zpos = 2; // skip 2-byte zlib header
    while zpos + 5 <= idat.len() {
        let header = idat[zpos];
        let len = u16::from_le_bytes([idat[zpos + 1], idat[zpos + 2]]) as usize;
        zpos += 5;
        if zpos + len > idat.len() {
            return Err("Aliran zlib PNG tidak valid.".into());
        }
        raw.extend_from_slice(&idat[zpos..zpos + len]);
        zpos += len;
        if header & 1 != 0 {
            break;
        }
    }
    let stride = (width as usize) * 3;
    let mut rgb = Vec::with_capacity(stride * (height as usize));
    for row in 0..(height as usize) {
        let start = row * (stride + 1);
        if start + stride + 1 > raw.len() {
            return Err("Baris piksel PNG tidak lengkap.".into());
        }
        rgb.extend_from_slice(&raw[start + 1..start + 1 + stride]);
    }
    Ok(rgb)
}

pub fn seal_png_message(master: &[u8; 32], message: &str, context_id: &str) -> R<Vec<u8>> {
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

    let total_channels = (WIDTH as usize) * (HEIGHT as usize) * 3;
    if packet.len() * 8 > total_channels {
        return Err("Pesan terlalu panjang untuk kapasitas piksel PNG.".into());
    }
    let mut rgb = vec![0u8; total_channels];
    for y in 0..HEIGHT as usize {
        for x in 0..WIDTH as usize {
            let idx = (y * (WIDTH as usize) + x) * 3;
            rgb[idx] = (28 + (x * 2) % 160) as u8;
            rgb[idx + 1] = (76 + (y * 2) % 140) as u8;
            rgb[idx + 2] = (62 + ((x + y) % 120)) as u8;
        }
    }
    for (bit_idx, bit) in packet.iter().flat_map(|b| (0..8).rev().map(move |shift| (b >> shift) & 1)).enumerate() {
        rgb[bit_idx] = (rgb[bit_idx] & 0xFE) | bit;
    }
    Ok(encode_uncompressed_png(WIDTH, HEIGHT, &rgb))
}

pub fn open_png_message(master: &[u8; 32], png: &[u8], context_id: &str) -> R<String> {
    let rgb = decode_uncompressed_png(png)?;
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
    fn stego_png_roundtrip_and_context_protection() {
        let master = [5u8; 32];
        let msg = "Periksa koneksi Android-2F pukul 19.25 WIB.";
        let png = seal_png_message(&master, msg, "SIM-BB/001:BB-001").unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let extracted = open_png_message(&master, &png, "SIM-BB/001:BB-001").unwrap();
        assert_eq!(extracted, msg);
        assert!(open_png_message(&master, &png, "SIM-BB/001:BB-002").is_err());
    }
}
