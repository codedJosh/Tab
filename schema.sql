create table if not exists jade_workspaces (
  id text primary key,
  state jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists jade_workspaces_updated_at_idx
  on jade_workspaces (updated_at desc);

create table if not exists jade_sessions (
  id text primary key,
  workspace_id text not null references jade_workspaces(id) on delete cascade,
  email text not null,
  token_hash text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists jade_sessions_workspace_idx
  on jade_sessions (workspace_id);

create index if not exists jade_sessions_email_idx
  on jade_sessions (email);

create index if not exists jade_sessions_expires_idx
  on jade_sessions (expires_at);
