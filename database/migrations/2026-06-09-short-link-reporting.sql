-- Short link reporting support
-- Run on PostgreSQL 14+

ALTER TABLE public.traffic_logs
    ADD COLUMN IF NOT EXISTS short_link_id integer REFERENCES public.short_links(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_traffic_logs_short_link_date
    ON public.traffic_logs USING btree (short_link_id, created_at);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_short_link_action
    ON public.traffic_logs USING btree (short_link_id, action);
