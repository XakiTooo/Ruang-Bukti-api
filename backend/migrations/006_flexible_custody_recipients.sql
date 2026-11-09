begin;

alter table ruang_bukti.cases
  add column if not exists officer text references ruang_bukti.accounts(username),
  add column if not exists investigator text references ruang_bukti.accounts(username);

create index if not exists cases_officer_idx on ruang_bukti.cases(officer);
create index if not exists cases_investigator_idx on ruang_bukti.cases(investigator);

grant update (revision, officer, investigator) on ruang_bukti.cases to service_role;

create or replace function public.ruang_bukti_create(case_row jsonb) returns void
language sql security invoker set search_path = '' as $$
  insert into ruang_bukti.cases(id, title, location, incident_time, officer, investigator)
  values (
    case_row->>'id',
    case_row->>'title',
    coalesce(case_row->>'location', ''),
    coalesce(case_row->>'incident_time', ''),
    nullif(case_row->>'officer', ''),
    nullif(case_row->>'investigator', '')
  );
$$;

create or replace function public.ruang_bukti_recipients() returns jsonb
language sql stable security invoker set search_path = '' as $$
  select coalesce(
    jsonb_agg(jsonb_build_object('username', a.username, 'role', a.role) order by a.role, a.username),
    '[]'::jsonb
  )
  from ruang_bukti.accounts a
  where a.role in ('Petugas penerima', 'Penyidik');
$$;

create or replace function public.ruang_bukti_commit_custody(
  case_key text, expected_revision bigint, change_type text, evidence_row jsonb, audit_row jsonb
) returns boolean
language plpgsql security invoker set search_path = '' as $$
declare
  evidence_key text := audit_row->>'evidence';
  event_actor text := audit_row->>'actor';
  event_action text := audit_row->>'action';
  event_username text := audit_row->>'actor_username';
  target_username text := audit_row->>'recipient';
  prior_hash text;
  owner_username text;
begin
  if event_actor is null or event_actor not in ('Petugas penerima', 'Penyidik', 'Pengawas')
    or coalesce(evidence_key, '') = ''
    or coalesce(audit_row->>'hash', '') !~ '^[a-f0-9]{64}$'
    or coalesce(audit_row->>'time', '') !~ '^[0-9]{1,19}$'
  then
    raise exception 'Catatan audit tidak valid';
  end if;

  if not exists (select 1 from ruang_bukti.accounts where username = event_username and role = event_actor) then
    raise exception 'Identitas akun audit tidak valid';
  end if;

  -- The revision check serializes mutations for this case.
  update ruang_bukti.cases set revision = revision + 1
    where id = case_key and revision = expected_revision;
  if not found then return false; end if;

  select a.hash into prior_hash from ruang_bukti.audit_events a
    where a.case_id = case_key order by sequence desc limit 1;
  if (audit_row->>'previous') is distinct from coalesce(prior_hash, 'GENESIS') then
    raise exception 'Rantai audit tidak cocok';
  end if;

  case change_type
    when 'receive' then
      if event_actor <> 'Petugas penerima' or event_action is distinct from 'Bukti diterima'
        or evidence_key is distinct from evidence_row->>'id'
        or (select count(*) from ruang_bukti.evidence where case_id = case_key) >= 12
      then
        raise exception 'Penerimaan bukti tidak valid atau kapasitas demo sudah penuh';
      end if;
      insert into ruang_bukti.evidence(case_id,id,name,note,file,original_hash,custodian,size)
      values (case_key,evidence_key,evidence_row->>'name',evidence_row->'note',
        evidence_row->'file',evidence_row->>'original_hash',event_actor,(evidence_row->>'size')::integer);
      update ruang_bukti.cases set officer = coalesce(officer, event_username)
        where id = case_key;
    when 'offer' then
      select actor_username into owner_username from ruang_bukti.audit_events
        where case_id = case_key and evidence = evidence_key
          and action in ('Bukti diterima', 'Bukti diterima penyidik', 'Bukti dikembalikan ke petugas')
        order by sequence desc limit 1;
      if owner_username is not null and owner_username <> event_username then
        raise exception 'Bukti dipegang oleh akun lain';
      end if;
      if target_username is null or not exists (
        select 1 from ruang_bukti.accounts
        where username = target_username
          and role = (case when event_actor = 'Petugas penerima' then 'Penyidik' else 'Petugas penerima' end)
      ) then
        raise exception 'Akun tujuan tidak valid';
      end if;
      if event_actor = 'Pengawas' or event_action is distinct from
        (case when event_actor = 'Petugas penerima' then 'Serah terima diajukan' else 'Pengembalian diajukan' end)
      then
        raise exception 'Pengajuan serah terima tidak valid';
      end if;
      update ruang_bukti.evidence set pending = true
        where case_id = case_key and id = evidence_key and not pending and custodian = event_actor;
      if not found then raise exception 'Bukti tidak dapat diserahkan'; end if;
      if event_actor = 'Petugas penerima' then
        update ruang_bukti.cases
          set officer = coalesce(officer, event_username), investigator = target_username
          where id = case_key;
      end if;
    when 'accept' then
      if (select recipient from ruang_bukti.audit_events
          where case_id = case_key and evidence = evidence_key
            and action in ('Serah terima diajukan', 'Pengembalian diajukan')
          order by sequence desc limit 1) is distinct from target_username
        or (target_username is not null and target_username <> event_username)
      then
        raise exception 'Serah terima ditujukan ke akun lain';
      end if;
      if event_actor = 'Pengawas' or event_action is distinct from
        (case when event_actor = 'Penyidik' then 'Bukti diterima penyidik' else 'Bukti dikembalikan ke petugas' end)
      then
        raise exception 'Penerimaan serah terima tidak valid';
      end if;
      update ruang_bukti.evidence set custodian = event_actor, pending = false
        where case_id = case_key and id = evidence_key and pending and custodian <> event_actor;
      if not found then raise exception 'Serah terima tidak tersedia'; end if;
    when 'verify' then
      if event_action is null or event_action not in ('Hash file cocok', 'Hash file berbeda') then
        raise exception 'Hasil verifikasi tidak valid';
      end if;
    else raise exception 'Jenis perubahan tidak didukung';
  end case;

  insert into ruang_bukti.audit_events(case_id,sequence,evidence,action,actor,time,previous,hash,actor_username,recipient)
  values (case_key,expected_revision + 1,evidence_key,event_action,
    event_actor,(audit_row->>'time')::bigint,audit_row->>'previous',audit_row->>'hash',event_username,target_username);
  return true;
end;
$$;

revoke all on function public.ruang_bukti_create(jsonb), public.ruang_bukti_recipients(),
  public.ruang_bukti_commit_custody(text, bigint, text, jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.ruang_bukti_create(jsonb), public.ruang_bukti_recipients(),
  public.ruang_bukti_commit_custody(text, bigint, text, jsonb, jsonb) to service_role;

commit;
