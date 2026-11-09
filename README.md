# Backend Ruang Bukti

API Rust `POST /api/bukti` untuk aplikasi Windows Ruang Bukti. Pembacaan USB dan pengambilan sampel wajah dilakukan di desktop.

Di Vercel, gunakan root repo sebagai Root Directory. Backend memerlukan Rust 1.94.1 atau lebih baru. Atur variabel dari `.env.example` sebagai rahasia server. Gunakan kunci induk arsip yang sudah ada untuk mempertahankan akses ke bukti dan template wajah lama.

Supabase menyimpan akun, metadata, catatan terenkripsi, dan audit. Gunakan schema dan RPC dari migrasi 001–004 yang sesuai dengan kondisi proyek. R2 menyimpan file baru dalam bentuk envelope ChaCha20-Poly1305 di bucket privat. File lama yang masih tersimpan sebagai envelope di Supabase tetap didukung. Batasi kredensial R2 ke bucket tersebut.

Jalankan tes dengan `cargo test --locked`.
