begin;

create table ruang_bukti.accounts (
  username text primary key check (username ~ '^[a-z0-9_]{3,40}$'),
  role text not null check (role in ('Petugas penerima', 'Penyidik', 'Pengawas')),
  password_hash text not null check (password_hash like '$argon2id$%'),
  dongle_hash text not null check (dongle_hash ~ '^[a-f0-9]{64}$'),
  face jsonb not null check (
    (face->>'algorithm') is not distinct from 'AES-256-GCM'
    and coalesce(length(face->>'nonce'), 0) = 16
    and coalesce(length(face->>'ciphertext'), 0) between 24 and 40000
  )
);

alter table ruang_bukti.accounts enable row level security;
revoke all on ruang_bukti.accounts from public, anon, authenticated, service_role;
grant select, insert on ruang_bukti.accounts to service_role;
create policy accounts_backend_read on ruang_bukti.accounts for select to service_role using (true);
create policy accounts_backend_import on ruang_bukti.accounts for insert to service_role with check (true);

create function public.ruang_bukti_account(account_username text) returns jsonb
language sql stable security invoker set search_path = '' as $$
  select to_jsonb(a) from ruang_bukti.accounts a where a.username = account_username;
$$;

create function public.ruang_bukti_import_accounts(account_rows jsonb) returns integer
language plpgsql security invoker set search_path = '' as $$
declare
  imported integer;
begin
  if jsonb_typeof(account_rows) is distinct from 'array' then
    raise exception 'Daftar akun tidak valid';
  end if;
  if jsonb_array_length(account_rows) not between 1 and 20 then
    raise exception 'Jumlah akun tidak valid';
  end if;
  insert into ruang_bukti.accounts (username, role, password_hash, dongle_hash, face)
  select username, role, password_hash, dongle_hash, face
  from jsonb_populate_recordset(null::ruang_bukti.accounts, account_rows)
  on conflict (username) do nothing;
  get diagnostics imported = row_count;
  return imported;
end;
$$;

revoke all on function public.ruang_bukti_account(text), public.ruang_bukti_import_accounts(jsonb)
  from public, anon, authenticated;
grant execute on function public.ruang_bukti_account(text), public.ruang_bukti_import_accounts(jsonb)
  to service_role;

commit;
