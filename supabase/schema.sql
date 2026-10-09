-- Doughbird donuts - accounts schema
-- Run on Supabase project lsxcdyzjyfsohdezdlkl (doughbird-donuts)
--
-- Design notes:
--   * auth.users holds email + password (Supabase Auth owns it; no PII duplicated here).
--   * public.profiles holds the public handle, keyed 1:1 to auth.users by a real FK.
--   * Uniqueness of a handle is case-insensitive: "DonutKing" and "donutking" collide.
--   * Profiles are created by a trigger, never by the client, so a signed-up user
--     always has exactly one profile and cannot invent one for somebody else.
--
-- This migration is additive only (new table, new function, new trigger).
-- Rollback: drop trigger on_auth_user_created on auth.users;
--           drop function public.handle_new_user();
--           drop function public.username_available(text);
--           drop table public.profiles;   -- destroys handles, auth.users is untouched

-- ---------------------------------------------------------------- profiles

create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade on update cascade,
  username   text not null,
  created_at timestamptz not null default now(),
  constraint profiles_username_len   check (char_length(username) between 3 and 20),
  constraint profiles_username_chars check (username ~ '^[A-Za-z0-9_]+$')
);

comment on table  public.profiles is 'Public handle for each signed-up user. One row per auth.users row.';
comment on column public.profiles.username is 'Display handle. Case preserved for display, uniqueness is case-insensitive.';

-- case-insensitive uniqueness
create unique index if not exists profiles_username_lower_key
  on public.profiles (lower(username));

-- ---------------------------------------------------------------- new user -> profile

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  uname text;
begin
  uname := nullif(btrim(new.raw_user_meta_data ->> 'username'), '');

  -- fallback keeps the row valid if a user was created without a username
  if uname is null or char_length(uname) < 3 then
    uname := 'donut_' || substr(replace(new.id::text, '-', ''), 1, 8);
  end if;

  insert into public.profiles (id, username) values (new.id, uname);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------- availability check

-- Lets the sign-up form say "that handle is taken" before creating an account.
-- SECURITY DEFINER so it can see every row without exposing the list itself.
create or replace function public.username_available(candidate text)
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select
    char_length(btrim(coalesce(candidate, ''))) between 3 and 20
    and not exists (
      select 1 from public.profiles p
      where lower(p.username) = lower(btrim(candidate))
    );
$$;

revoke all on function public.username_available(text) from public;
grant execute on function public.username_available(text) to anon, authenticated;

-- ---------------------------------------------------------------- RLS

alter table public.profiles enable row level security;

-- You can read your own handle (the header shows it, and nothing else is needed).
drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

-- You can rename yourself, but only yourself, and only to a valid handle.
drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- No insert or delete policy on purpose: rows are created by the trigger and
-- removed by the auth.users cascade. The client cannot do either by hand.

grant select, update on public.profiles to authenticated;
