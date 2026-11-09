begin;

-- Keep the existing RPC signature and preserve previously recorded events.
create or replace function public.ruang_bukti_commit(
  case_key text, expected_revision bigint, change_type text, evidence_row jsonb, audit_row jsonb
) returns boolean
language plpgsql security invoker set search_path = '' as $$
declare
  evidence_key text := audit_row->>'evidence';
  event_actor text := audit_row->>'actor';
  event_action text := audit_row->>'action';
  prior_hash text;
begin
  if event_actor is null or event_actor not in ('Petugas penerima', 'Penyidik', 'Pengawas')
    or coalesce(evidence_key, '') = ''
    or coalesce(audit_row->>'hash', '') !~ '^[a-f0-9]{64}$'
    or coalesce(audit_row->>'time', '') !~ '^[0-9]{1,19}$'
  then
    raise exception 'Catatan audit tidak valid';
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
    when 'offer' then
      if event_actor = 'Pengawas' or event_action is distinct from
        (case when event_actor = 'Petugas penerima' then 'Serah terima diajukan' else 'Pengembalian diajukan' end)
      then
        raise exception 'Pengajuan serah terima tidak valid';
      end if;
      update ruang_bukti.evidence set pending = true
        where case_id = case_key and id = evidence_key and not pending and custodian = event_actor;
      if not found then raise exception 'Bukti tidak dapat diserahkan'; end if;
    when 'accept' then
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

  insert into ruang_bukti.audit_events(case_id,sequence,evidence,action,actor,time,previous,hash)
  values (case_key,expected_revision + 1,evidence_key,event_action,
    event_actor,(audit_row->>'time')::bigint,audit_row->>'previous',audit_row->>'hash');
  return true;
end;
$$;

revoke all on function public.ruang_bukti_commit(text, bigint, text, jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.ruang_bukti_commit(text, bigint, text, jsonb, jsonb) to service_role;

commit;
