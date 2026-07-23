-- Preserve country and device report dimensions when raw traffic logs are compacted.

ALTER TABLE public.traffic_daily_stats
    ADD COLUMN IF NOT EXISTS country text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_type text NOT NULL DEFAULT '';

DO $migration$
DECLARE
    primary_key_definition text;
BEGIN
    SELECT pg_get_constraintdef(oid)
      INTO primary_key_definition
      FROM pg_constraint
     WHERE conrelid='public.traffic_daily_stats'::regclass
       AND contype='p'
     LIMIT 1;

    IF primary_key_definition IS NULL
       OR position('country' IN primary_key_definition)=0
       OR position('device_type' IN primary_key_definition)=0 THEN
        ALTER TABLE public.traffic_daily_stats
            DROP CONSTRAINT IF EXISTS traffic_daily_stats_pkey;
        ALTER TABLE public.traffic_daily_stats
            ADD CONSTRAINT traffic_daily_stats_pkey
            PRIMARY KEY (
                day,
                domain_id,
                campaign_id,
                short_link_id,
                action,
                country,
                device_type
            );
    END IF;
END
$migration$;

CREATE INDEX IF NOT EXISTS idx_traffic_daily_stats_campaign_dimensions
    ON public.traffic_daily_stats (campaign_id, day, country, device_type);

CREATE INDEX IF NOT EXISTS idx_traffic_daily_stats_short_link_dimensions
    ON public.traffic_daily_stats (short_link_id, day, country, device_type);
