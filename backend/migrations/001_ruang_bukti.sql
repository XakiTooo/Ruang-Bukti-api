begin;
create schema ruang_bukti;
revoke all on schema ruang_bukti from public, anon, authenticated;
grant usage on schema ruang_bukti to service_role;

create table ruang_bukti.cases (
  id text primary key,
  title text not null,
  location text not null default '',
  incident_time text not null default '',
  revision bigint not null default 0
);
insert into ruang_bukti.cases(id, title)
values ('SIM-BB/001', 'Penggunaan jaringan Wi-Fi');

create table ruang_bukti.evidence (
  case_id text not null references ruang_bukti.cases(id),
  id text not null,
  name text not null,
  note jsonb not null,
  file jsonb not null,
  original_hash text not null check (original_hash ~ '^[a-f0-9]{64}$'),
  custodian text not null check (custodian in ('Petugas penerima', 'Penyidik')),
  pending boolean not null default false,
  size integer not null check (size between 1 and 2097152),
  primary key (case_id, id)
);

create table ruang_bukti.audit_events (
  case_id text not null,
  sequence bigint not null,
  evidence text not null,
  action text not null,
  actor text not null,
  time bigint not null,
  previous text not null,
  hash text not null check (hash ~ '^[a-f0-9]{64}$'),
  primary key (case_id, sequence),
  foreign key (case_id, evidence) references ruang_bukti.evidence(case_id, id)
);
create index on ruang_bukti.audit_events(case_id, evidence);

alter table ruang_bukti.cases enable row level security;
alter table ruang_bukti.evidence enable row level security;
alter table ruang_bukti.audit_events enable row level security;
revoke all on all tables in schema ruang_bukti from public, anon, authenticated, service_role;
grant select on all tables in schema ruang_bukti to service_role;
grant insert on ruang_bukti.cases to service_role;
grant update (revision) on ruang_bukti.cases to service_role;
grant insert on ruang_bukti.evidence, ruang_bukti.audit_events to service_role;
grant update (custodian, pending) on ruang_bukti.evidence to service_role;
create policy backend_cases on ruang_bukti.cases to service_role using (true) with check (true);
create policy backend_evidence on ruang_bukti.evidence to service_role using (true) with check (true);
create policy backend_audit on ruang_bukti.audit_events to service_role using (true) with check (true);

create function public.ruang_bukti_cases() returns jsonb
language sql stable security invoker set search_path = '' as $$
  select coalesce(jsonb_agg(to_jsonb(c) - 'revision' order by c.id), '[]'::jsonb)
  from ruang_bukti.cases c;
$$;

create function public.ruang_bukti_create(case_row jsonb) returns void
language sql security invoker set search_path = '' as $$
  insert into ruang_bukti.cases(id,title,location,incident_time)
  values (case_row->>'id', case_row->>'title', case_row->>'location', case_row->>'incident_time');
$$;

create function public.ruang_bukti_read(case_key text) returns jsonb
language sql stable security invoker set search_path = '' as $$
  select jsonb_build_object('revision', c.revision,
    'evidence', coalesce((select jsonb_agg(to_jsonb(e) - 'case_id' order by e.id)
      from ruang_bukti.evidence e where e.case_id = c.id), '[]'::jsonb),
    'events', coalesce((select jsonb_agg(to_jsonb(a) - 'case_id' - 'sequence' order by a.sequence)
      from ruang_bukti.audit_events a where a.case_id = c.id), '[]'::jsonb))
  from ruang_bukti.cases c where c.id = case_key;
$$;

create function public.ruang_bukti_commit(case_key text, expected_revision bigint, change_type text, evidence_row jsonb, audit_row jsonb)
returns boolean
language plpgsql security invoker set search_path = '' as $$
declare
  evidence_key text := audit_row->>'evidence';
  prior_hash text;
begin
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
      if evidence_key is distinct from evidence_row->>'id' or
          (select count(*) from ruang_bukti.evidence where case_id = case_key) >= 12 then
        raise exception 'Bukti tidak valid atau kapasitas demo sudah penuh';
      end if;
      insert into ruang_bukti.evidence(case_id,id,name,note,file,original_hash,custodian,size)
      values (case_key,evidence_key,evidence_row->>'name',evidence_row->'note',
        evidence_row->'file',evidence_row->>'original_hash','Petugas penerima',(evidence_row->>'size')::integer);
    when 'offer' then
      update ruang_bukti.evidence set pending = true
        where case_id = case_key and id = evidence_key and not pending
          and custodian = audit_row->>'actor';
      if not found then raise exception 'Bukti tidak dapat diserahkan'; end if;
    when 'accept' then
      update ruang_bukti.evidence set custodian = audit_row->>'actor', pending = false
        where case_id = case_key and id = evidence_key and pending
          and custodian <> audit_row->>'actor';
      if not found then raise exception 'Serah terima tidak tersedia'; end if;
    when 'verify' then
      null;
    else raise exception 'Jenis perubahan tidak didukung';
  end case;

  insert into ruang_bukti.audit_events(case_id,sequence,evidence,action,actor,time,previous,hash)
  values (case_key,expected_revision + 1,evidence_key,audit_row->>'action',
    audit_row->>'actor',(audit_row->>'time')::bigint,audit_row->>'previous',audit_row->>'hash');
  return true;
end;
$$;

revoke all on function public.ruang_bukti_cases(), public.ruang_bukti_create(jsonb),
  public.ruang_bukti_read(text), public.ruang_bukti_commit(text, bigint, text, jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.ruang_bukti_cases(), public.ruang_bukti_create(jsonb),
  public.ruang_bukti_read(text), public.ruang_bukti_commit(text, bigint, text, jsonb, jsonb) to service_role;
commit;
