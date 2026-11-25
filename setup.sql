-- Piškvorky: přezdívky, přátelé, pozvánky a žebříček
-- Vlož celé do Supabase -> SQL Editor a klikni na Run. Je bezpečné spustit i opakovaně.

create extension if not exists pgcrypto with schema extensions;

-- ---------- tabulky (zvenku nepřístupné, přístup jen přes funkce níže) ----------
create table if not exists public.players (
  id uuid primary key default gen_random_uuid(),
  nick text not null,
  token_hash text not null,
  wins int not null default 0,
  losses int not null default 0,
  last_seen timestamptz,
  created_at timestamptz not null default now()
);
create unique index if not exists players_nick_ci on public.players (lower(nick));

create table if not exists public.friendships (
  requester uuid not null references public.players(id) on delete cascade,
  addressee uuid not null references public.players(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  primary key (requester, addressee)
);

create table if not exists public.invites (
  from_id uuid not null references public.players(id) on delete cascade,
  to_id uuid not null references public.players(id) on delete cascade,
  code text not null,
  created_at timestamptz not null default now(),
  primary key (from_id, to_id)
);

create table if not exists public.result_reports (
  game_id text not null,
  reporter uuid not null references public.players(id) on delete cascade,
  opponent uuid not null references public.players(id) on delete cascade,
  outcome text not null check (outcome in ('win','loss')),
  created_at timestamptz not null default now(),
  primary key (game_id, reporter)
);

create table if not exists public.games_done (
  game_id text primary key,
  created_at timestamptz not null default now()
);

alter table public.players enable row level security;
alter table public.friendships enable row level security;
alter table public.invites enable row level security;
alter table public.result_reports enable row level security;
alter table public.games_done enable row level security;

-- ---------- pomocná funkce: ověření přezdívky a tajného kódu ----------
create or replace function public._auth(p_nick text, p_token text)
returns uuid
language plpgsql security definer set search_path = public, extensions
as $$
declare v_id uuid;
begin
  select id into v_id from public.players
   where lower(nick) = lower(coalesce(p_nick,''))
     and token_hash = encode(digest(coalesce(p_token,''), 'sha256'), 'hex');
  return v_id;
end $$;
revoke all on function public._auth(text, text) from public, anon, authenticated;

-- ---------- registrace a přihlášení ----------
create or replace function public.register(p_nick text, p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_id uuid; v_nick text := trim(coalesce(p_nick,''));
begin
  if v_nick !~ '^[[:alnum:]_.-]{3,16}$' then
    return jsonb_build_object('ok', false, 'err', 'nick_format');
  end if;
  if length(coalesce(p_token,'')) < 12 then
    return jsonb_build_object('ok', false, 'err', 'token');
  end if;
  begin
    insert into public.players (nick, token_hash)
    values (v_nick, encode(digest(p_token, 'sha256'), 'hex'))
    returning id into v_id;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'err', 'taken');
  end;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function public.login(p_nick text, p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_nick text;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'bad'); end if;
  select nick into v_nick from public.players where id = v_me;
  return jsonb_build_object('ok', true, 'nick', v_nick);
end $$;

-- ---------- přátelé ----------
create or replace function public.friend_request(p_nick text, p_token text, p_target text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_t uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select id into v_t from public.players where lower(nick) = lower(trim(coalesce(p_target,'')));
  if v_t is null then return jsonb_build_object('ok', false, 'err', 'notfound'); end if;
  if v_t = v_me then return jsonb_build_object('ok', false, 'err', 'self'); end if;
  if exists (select 1 from public.friendships f
              where f.status = 'accepted'
                and ((f.requester = v_me and f.addressee = v_t) or (f.requester = v_t and f.addressee = v_me))) then
    return jsonb_build_object('ok', false, 'err', 'already');
  end if;
  if exists (select 1 from public.friendships f
              where f.requester = v_t and f.addressee = v_me and f.status = 'pending') then
    update public.friendships set status = 'accepted'
     where requester = v_t and addressee = v_me;
    return jsonb_build_object('ok', true, 'res', 'accepted');
  end if;
  insert into public.friendships (requester, addressee) values (v_me, v_t)
  on conflict do nothing;
  return jsonb_build_object('ok', true, 'res', 'sent');
end $$;

create or replace function public.friend_respond(p_nick text, p_token text, p_other text, p_accept boolean)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_o uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select id into v_o from public.players where lower(nick) = lower(trim(coalesce(p_other,'')));
  if v_o is null then return jsonb_build_object('ok', false, 'err', 'notfound'); end if;
  if p_accept then
    update public.friendships set status = 'accepted'
     where requester = v_o and addressee = v_me and status = 'pending';
  else
    delete from public.friendships
     where requester = v_o and addressee = v_me and status = 'pending';
  end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.friend_remove(p_nick text, p_token text, p_other text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_o uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select id into v_o from public.players where lower(nick) = lower(trim(coalesce(p_other,'')));
  if v_o is null then return jsonb_build_object('ok', false, 'err', 'notfound'); end if;
  delete from public.friendships
   where (requester = v_me and addressee = v_o) or (requester = v_o and addressee = v_me);
  delete from public.invites
   where (from_id = v_me and to_id = v_o) or (from_id = v_o and to_id = v_me);
  return jsonb_build_object('ok', true);
end $$;

-- Seznam kamarádů, žádosti a pozvánky. Zároveň slouží jako "jsem online" (last_seen).
create or replace function public.friends_list(p_nick text, p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  update public.players set last_seen = now() where id = v_me;
  delete from public.invites where created_at < now() - interval '10 minutes';
  return jsonb_build_object(
    'ok', true,
    'me', (select jsonb_build_object('nick', p.nick, 'wins', p.wins, 'losses', p.losses)
             from public.players p where p.id = v_me),
    'friends', coalesce((
        select jsonb_agg(jsonb_build_object(
                 'nick', p.nick, 'wins', p.wins, 'losses', p.losses,
                 'online', coalesce(p.last_seen > now() - interval '40 seconds', false))
               order by lower(p.nick))
          from public.friendships f
          join public.players p on p.id = case when f.requester = v_me then f.addressee else f.requester end
         where f.status = 'accepted' and (f.requester = v_me or f.addressee = v_me)
      ), '[]'::jsonb),
    'incoming', coalesce((
        select jsonb_agg(p.nick order by lower(p.nick))
          from public.friendships f join public.players p on p.id = f.requester
         where f.addressee = v_me and f.status = 'pending'
      ), '[]'::jsonb),
    'outgoing', coalesce((
        select jsonb_agg(p.nick order by lower(p.nick))
          from public.friendships f join public.players p on p.id = f.addressee
         where f.requester = v_me and f.status = 'pending'
      ), '[]'::jsonb),
    'invites', coalesce((
        select jsonb_agg(jsonb_build_object('from', p.nick, 'code', i.code) order by i.created_at desc)
          from public.invites i join public.players p on p.id = i.from_id
         where i.to_id = v_me and i.created_at > now() - interval '3 minutes'
      ), '[]'::jsonb)
  );
end $$;

-- ---------- pozvánky do hry ----------
create or replace function public.invite_send(p_nick text, p_token text, p_target text, p_code text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_t uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if coalesce(p_code,'') !~ '^[0-9]{4}$' then return jsonb_build_object('ok', false, 'err', 'code'); end if;
  select id into v_t from public.players where lower(nick) = lower(trim(coalesce(p_target,'')));
  if v_t is null then return jsonb_build_object('ok', false, 'err', 'notfound'); end if;
  if not exists (select 1 from public.friendships f
                  where f.status = 'accepted'
                    and ((f.requester = v_me and f.addressee = v_t) or (f.requester = v_t and f.addressee = v_me))) then
    return jsonb_build_object('ok', false, 'err', 'notfriend');
  end if;
  insert into public.invites (from_id, to_id, code) values (v_me, v_t, p_code)
  on conflict (from_id, to_id) do update set code = excluded.code, created_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.invite_clear(p_nick text, p_token text, p_from text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  delete from public.invites
   where to_id = v_me
     and from_id = (select id from public.players where lower(nick) = lower(trim(coalesce(p_from,''))));
  return jsonb_build_object('ok', true);
end $$;

-- ---------- žebříček ----------
create or replace function public.leaderboard()
returns jsonb
language sql security definer set search_path = public, extensions
as $$
  select coalesce(jsonb_agg(x), '[]'::jsonb)
    from (select nick, wins, losses
            from public.players
           where wins + losses > 0
           order by wins desc, losses asc, lower(nick)
           limit 20) x
$$;

-- Výsledek se započítá, až ho nahlásí oba hráči shodně (jedna výhra, jedna prohra).
create or replace function public.report_result(p_nick text, p_token text, p_game text, p_opp text, p_outcome text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_o uuid; v_n int;
begin
  v_me := public._auth(p_nick, p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if p_outcome not in ('win','loss') or length(coalesce(p_game,'')) not between 3 and 60 then
    return jsonb_build_object('ok', false, 'err', 'bad');
  end if;
  select id into v_o from public.players where lower(nick) = lower(trim(coalesce(p_opp,'')));
  if v_o is null or v_o = v_me then return jsonb_build_object('ok', false, 'err', 'opp'); end if;
  if exists (select 1 from public.games_done where game_id = p_game) then
    return jsonb_build_object('ok', true, 'res', 'done');
  end if;

  insert into public.result_reports (game_id, reporter, opponent, outcome)
  values (p_game, v_me, v_o, p_outcome)
  on conflict do nothing;

  if exists (select 1 from public.result_reports r
              where r.game_id = p_game and r.reporter = v_o and r.opponent = v_me
                and r.outcome = case when p_outcome = 'win' then 'loss' else 'win' end) then
    insert into public.games_done (game_id) values (p_game) on conflict do nothing;
    get diagnostics v_n = row_count;
    if v_n > 0 then
      update public.players set wins = wins + 1
       where id = case when p_outcome = 'win' then v_me else v_o end;
      update public.players set losses = losses + 1
       where id = case when p_outcome = 'win' then v_o else v_me end;
    end if;
    delete from public.result_reports where game_id = p_game;
  end if;

  delete from public.result_reports where created_at < now() - interval '1 day';
  return jsonb_build_object('ok', true);
end $$;

-- ---------- oprávnění: web smí volat jen tyto funkce ----------
grant execute on function public.register(text, text) to anon, authenticated;
grant execute on function public.login(text, text) to anon, authenticated;
grant execute on function public.friend_request(text, text, text) to anon, authenticated;
grant execute on function public.friend_respond(text, text, text, boolean) to anon, authenticated;
grant execute on function public.friend_remove(text, text, text) to anon, authenticated;
grant execute on function public.friends_list(text, text) to anon, authenticated;
grant execute on function public.invite_send(text, text, text, text) to anon, authenticated;
grant execute on function public.invite_clear(text, text, text) to anon, authenticated;
grant execute on function public.leaderboard() to anon, authenticated;
grant execute on function public.report_result(text, text, text, text, text) to anon, authenticated;
