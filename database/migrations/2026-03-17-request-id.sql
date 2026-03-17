ALTER TABLE public.traffic_logs
    ADD COLUMN IF NOT EXISTS request_id text;

CREATE INDEX IF NOT EXISTS idx_traffic_logs_request_id
    ON public.traffic_logs USING btree (request_id);
