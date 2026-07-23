-- Browser-confirmed analytics for delayed short links.
-- An open visit starts as short_link_open and is atomically promoted to
-- short_redirect_confirmed only when the signed timer callback arrives.

ALTER TABLE public.traffic_logs
    ADD COLUMN IF NOT EXISTS request_id text;

ALTER TABLE public.traffic_logs
    ADD COLUMN IF NOT EXISTS short_link_id integer REFERENCES public.short_links(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_traffic_logs_short_confirmation
    ON public.traffic_logs (request_id, short_link_id, domain_id, action)
    WHERE action IN ('short_link_open', 'short_redirect_confirmed');
