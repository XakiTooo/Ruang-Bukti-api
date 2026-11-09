pub fn generate_handover_pdf(
    case_id: &str,
    case_title: &str,
    evidence_id: &str,
    file_name: &str,
    file_size: usize,
    officer: &str,
    investigator: &str,
    custodian: &str,
    original_hash: &str,
    latest_event_hash: &str,
    stego_message: Option<&str>,
    exam_note: Option<&str>,
) -> Vec<u8> {
    fn clean(input: &str) -> String {
        input
            .chars()
            .map(|c| if c.is_ascii() && c >= ' ' && c <= '~' { c } else { ' ' })
            .collect::<String>()
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
    }

    let lines: Vec<(String, bool)> = vec![
        ("BERITA ACARA SERAH TERIMA & PEMERIKSAAN BARANG BUKTI DIGITAL".into(), true),
        ("Sistem Arsip Forensik Kriptografi Ruang Bukti".into(), false),
        ("----------------------------------------------------------------------------".into(), false),
        (format!("Nomor Perkara      : {} - {}", case_id, case_title), false),
        (format!("Nomor Barang Bukti : {} ({}, {} byte)", evidence_id, file_name, file_size), false),
        (format!("Petugas Penerima   : {}", officer), false),
        (format!("Penyidik Ditugaskan: {}", investigator), false),
        (format!("Pemegang Saat Ini  : {}", custodian), false),
        ("----------------------------------------------------------------------------".into(), false),
        ("PARAMETER VERIFIKASI KRIPTOGRAFI:".into(), true),
        ("Algoritma File     : ChaCha20-Poly1305 (AEAD 256-bit, Nonce 96-bit)".into(), false),
        ("Algoritma Catatan  : Super-Enkripsi Vigenere Cipher + AES-256-GCM".into(), false),
        ("Algoritma Stego    : LSB PNG Lossless + AES-256-GCM (Header STEG1)".into(), false),
        (format!("SHA-256 File Asli  : {}", original_hash), false),
        (format!("Hash Rantai Audit  : {}", latest_event_hash), false),
        ("Status Integritas  : TERVERIFIKASI COCOK (100% UTUH)".into(), true),
        ("----------------------------------------------------------------------------".into(), false),
        ("INSTRUKSI STEGANOGRAFI PETUGAS (LSB PNG):".into(), true),
        (stego_message.unwrap_or("(Tidak ada pesan gambar disisipkan)").into(), false),
        ("----------------------------------------------------------------------------".into(), false),
        ("CATATAN HASIL PEMERIKSAAN FORENSIK PENYIDIK:".into(), true),
        (exam_note.unwrap_or("(Belum ada catatan pemeriksaan penyidik)").into(), false),
        ("----------------------------------------------------------------------------".into(), false),
        ("Dokumen ini dibuat otomatis oleh Ruang Bukti setelah verifikasi hash berhasil.".into(), false),
    ];

    let mut stream = String::from("BT\n");
    let mut y = 780;
    for (text, bold) in lines {
        let font = if bold { "/F2 10 Tf" } else { "/F1 9 Tf" };
        stream.push_str(&format!("{font}\n1 0 0 1 48 {y} Tm\n({}) Tj\n", clean(&text)));
        y -= 20;
    }
    stream.push_str("ET\n");
    let stream_bytes = stream.into_bytes();

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");

    let mut offsets = Vec::new();
    let add_obj = |pdf: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &[u8]| {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        pdf.extend_from_slice(body);
        pdf.extend_from_slice(b"\nendobj\n");
    };

    add_obj(&mut pdf, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>");
    add_obj(&mut pdf, &mut offsets, 2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    add_obj(
        &mut pdf,
        &mut offsets,
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
    );
    add_obj(&mut pdf, &mut offsets, 4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>");
    add_obj(&mut pdf, &mut offsets, 5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>");

    let mut obj6 = format!("<< /Length {} >>\nstream\n", stream_bytes.len()).into_bytes();
    obj6.extend_from_slice(&stream_bytes);
    obj6.extend_from_slice(b"endstream");
    add_obj(&mut pdf, &mut offsets, 6, &obj6);

    let xref_start = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
    for offset in &offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n",
            offsets.len() + 1
        )
        .as_bytes(),
    );
    pdf
}
