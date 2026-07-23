-- Safe Page is selected once per domain. Campaign-level overrides are retired.

UPDATE public.campaigns
SET safe_template_override = NULL,
    safe_page_id = NULL
WHERE safe_template_override IS NOT NULL
   OR safe_page_id IS NOT NULL;

ALTER TABLE public.campaigns
    DROP CONSTRAINT IF EXISTS campaigns_domain_safe_page_only;

ALTER TABLE public.campaigns
    ADD CONSTRAINT campaigns_domain_safe_page_only
    CHECK (safe_template_override IS NULL AND safe_page_id IS NULL);

COMMENT ON COLUMN public.campaigns.safe_template_override IS
    'Deprecated compatibility column. Safe Page is selected only on the domain.';
