-- Redirect Pro product hardening and low-resource indexes

CREATE INDEX IF NOT EXISTS idx_domains_active_url_lower
    ON public.domains (lower(domain_url), status);

CREATE INDEX IF NOT EXISTS idx_campaigns_route_lookup
    ON public.campaigns (domain_id, param_key, param_value, is_active);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_domain_date
    ON public.traffic_logs (domain_id, created_at);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_action_date
    ON public.traffic_logs (action, created_at);

CREATE TABLE IF NOT EXISTS public.user_sessions (
    sid varchar NOT NULL COLLATE "default" PRIMARY KEY,
    sess json NOT NULL,
    expire timestamp(6) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_expire
    ON public.user_sessions (expire);

CREATE TABLE IF NOT EXISTS public.traffic_daily_stats (
    day date NOT NULL,
    domain_id integer NOT NULL DEFAULT 0,
    campaign_id integer NOT NULL DEFAULT 0,
    action text NOT NULL,
    hits bigint NOT NULL DEFAULT 0,
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (day, domain_id, campaign_id, action)
);

CREATE INDEX IF NOT EXISTS idx_traffic_daily_stats_domain_day
    ON public.traffic_daily_stats (domain_id, day);

CREATE TABLE IF NOT EXISTS public.app_settings (
    setting_key text PRIMARY KEY,
    setting_value jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);
