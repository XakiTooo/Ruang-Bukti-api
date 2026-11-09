import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';

const accounts = JSON.parse(await readFile(new URL('./accounts.private.json', import.meta.url), 'utf8'));
const base = new URL(process.env.SUPABASE_URL);
const secret = process.env.SUPABASE_SECRET_KEY;
if (!secret || base.protocol !== 'https:' || !base.hostname.endsWith('.supabase.co') || base.username || base.password) {
  throw Error('Konfigurasi server Supabase tidak valid.');
}

async function rpc(name, body) {
  const response = await fetch(new URL('/rest/v1/rpc/' + name, base), {
    method: 'POST',
    headers: { apikey: secret, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    redirect: 'error',
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw Error(`${name} gagal (HTTP ${response.status}).`);
  return response.json();
}

await rpc('ruang_bukti_import_accounts', { account_rows: accounts });
for (const account of accounts) {
  const saved = await rpc('ruang_bukti_account', { account_username: account.username });
  if (!isDeepStrictEqual(saved, account)) {
    throw Error('Akun di database berbeda dari cadangan lokal. Periksa sebelum menghapus schema lama.');
  }
}
console.log(`${accounts.length} akun diverifikasi di schema ruang_bukti.`);
