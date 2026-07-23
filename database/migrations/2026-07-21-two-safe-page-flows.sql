-- Product simplification: two built-in safe pages and two link flows.

ALTER TABLE public.campaigns
    ADD COLUMN IF NOT EXISTS safe_template_override text;

UPDATE public.campaigns c
SET safe_template_override = CASE
    WHEN sp.template IN ('clean', 'age_gate') THEN sp.template
    ELSE NULL
END
FROM public.safe_pages sp
WHERE c.safe_page_id = sp.id
  AND c.safe_template_override IS NULL;

UPDATE public.domains
SET safe_template = 'clean'
WHERE safe_template IS NULL
   OR safe_template NOT IN ('clean', 'age_gate');

UPDATE public.domains
SET safe_content = '{}'::jsonb;

ALTER TABLE public.domains
    ALTER COLUMN safe_template SET DEFAULT 'clean';

UPDATE public.short_links
SET redirect_delay_seconds = 3
WHERE redirect_delay_seconds < 1 OR redirect_delay_seconds > 30;

ALTER TABLE public.short_links
    ALTER COLUMN redirect_delay_seconds SET DEFAULT 3;

ALTER TABLE public.short_links
    DROP CONSTRAINT IF EXISTS short_links_redirect_delay_range;

ALTER TABLE public.short_links
    ADD CONSTRAINT short_links_redirect_delay_range
    CHECK (redirect_delay_seconds BETWEEN 1 AND 30);

COMMENT ON COLUMN public.campaigns.safe_template_override IS
    'Optional built-in safe page override: clean or age_gate. NULL uses the domain default.';

COMMENT ON COLUMN public.short_links.redirect_delay_seconds IS
    'Delay before automatic redirect. New product flow accepts 1-30 seconds.';
