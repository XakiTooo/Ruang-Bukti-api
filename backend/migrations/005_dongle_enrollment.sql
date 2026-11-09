create table ruang_bukti.dongles (
  key_hash text primary key check (key_hash ~ '^[a-f0-9]{64}$'),
  registered_at timestamptz not null default now()
);

alter table ruang_bukti.dongles enable row level security;
revoke all on ruang_bukti.dongles from public, anon, authenticated;
grant select, insert on ruang_bukti.dongles to service_role;

alter table ruang_bukti.accounts
  add column device_hash text references ruang_bukti.dongles(key_hash);
create index accounts_device_hash_idx on ruang_bukti.accounts(device_hash);

create function public.ruang_bukti_enroll(account_row jsonb, device_key_hash text)
returns boolean language plpgsql security invoker set search_path = '' as $enroll$
begin
  insert into ruang_bukti.dongles (key_hash) values (device_key_hash)
  on conflict (key_hash) do nothing;

  insert into ruang_bukti.accounts (username, role, password_hash, dongle_hash, face, device_hash)
  values (account_row->>'username', account_row->>'role', account_row->>'password_hash',
    account_row->>'dongle_hash', account_row->'face', device_key_hash)
  on conflict (username) do nothing;

  if found then return true; end if;
  if not exists (
    select 1 from ruang_bukti.accounts
    where username = account_row->>'username' and role = account_row->>'role'
      and dongle_hash = account_row->>'dongle_hash' and device_hash = device_key_hash
  ) then
    raise exception using errcode = '23505', message = 'Nama akun sudah terdaftar.';
  end if;
  return false;
end;
$enroll$;

revoke all on function public.ruang_bukti_enroll(jsonb,text) from public, anon, authenticated;
grant execute on function public.ruang_bukti_enroll(jsonb,text) to service_role;
