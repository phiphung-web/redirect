ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS telegram_chat_id text,
  ADD COLUMN IF NOT EXISTS telegram_username text,
  ADD COLUMN IF NOT EXISTS telegram_link_alerts boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS telegram_system_alerts boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS telegram_connect_code_hash text,
  ADD COLUMN IF NOT EXISTS telegram_connect_expires_at timestamp with time zone,
  ADD COLUMN IF NOT EXISTS telegram_connected_at timestamp with time zone;

CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_chat_id_unique
  ON public.users (telegram_chat_id)
  WHERE telegram_chat_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS users_telegram_connect_code_idx
  ON public.users (telegram_connect_code_hash, telegram_connect_expires_at)
  WHERE telegram_connect_code_hash IS NOT NULL;
