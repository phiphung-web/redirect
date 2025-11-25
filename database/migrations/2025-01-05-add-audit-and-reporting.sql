-- Audit & reporting enhancements
-- Run on PostgreSQL 14+

-- Add audit columns for domains and campaigns
ALTER TABLE public.domains
    ADD COLUMN IF NOT EXISTS updated_at timestamp without time zone DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_by integer REFERENCES public.users(id);

ALTER TABLE public.campaigns
    ADD COLUMN IF NOT EXISTS updated_at timestamp without time zone DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_by integer REFERENCES public.users(id);

-- Touch updated_at automatically on update
CREATE OR REPLACE FUNCTION public.fn_touch_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_touch_domains ON public.domains;
CREATE TRIGGER trg_touch_domains
BEFORE UPDATE ON public.domains
FOR EACH ROW EXECUTE FUNCTION public.fn_touch_updated_at();

DROP TRIGGER IF EXISTS trg_touch_campaigns ON public.campaigns;
CREATE TRIGGER trg_touch_campaigns
BEFORE UPDATE ON public.campaigns
FOR EACH ROW EXECUTE FUNCTION public.fn_touch_updated_at();

-- Helpful indexes for reporting
CREATE INDEX IF NOT EXISTS idx_traffic_logs_campaign_date ON public.traffic_logs USING btree (campaign_id, created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_action ON public.traffic_logs USING btree (action);
