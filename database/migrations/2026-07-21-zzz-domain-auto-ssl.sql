-- Track automatic certificate provisioning for each configured domain.

ALTER TABLE public.domains
    ADD COLUMN IF NOT EXISTS ssl_status text,
    ADD COLUMN IF NOT EXISTS ssl_error text,
    ADD COLUMN IF NOT EXISTS ssl_attempts integer,
    ADD COLUMN IF NOT EXISTS ssl_updated_at timestamp without time zone,
    ADD COLUMN IF NOT EXISTS ssl_expires_at timestamp with time zone;

-- Existing domains already have the server-wide Cloudflare origin fallback.
UPDATE public.domains
SET ssl_status = 'fallback'
WHERE ssl_status IS NULL;

UPDATE public.domains
SET ssl_attempts = 0
WHERE ssl_attempts IS NULL;

ALTER TABLE public.domains
    ALTER COLUMN ssl_status SET DEFAULT 'pending',
    ALTER COLUMN ssl_status SET NOT NULL,
    ALTER COLUMN ssl_attempts SET DEFAULT 0,
    ALTER COLUMN ssl_attempts SET NOT NULL;

ALTER TABLE public.domains
    DROP CONSTRAINT IF EXISTS domains_ssl_status_allowed;

ALTER TABLE public.domains
    ADD CONSTRAINT domains_ssl_status_allowed
    CHECK (ssl_status IN ('pending', 'provisioning', 'active', 'fallback', 'error', 'disabled'));

ALTER TABLE public.domains
    DROP CONSTRAINT IF EXISTS domains_ssl_attempts_nonnegative;

ALTER TABLE public.domains
    ADD CONSTRAINT domains_ssl_attempts_nonnegative
    CHECK (ssl_attempts >= 0);

COMMENT ON COLUMN public.domains.ssl_status IS
    'pending/provisioning/active/fallback/error/disabled state for automatic TLS provisioning';

COMMENT ON COLUMN public.domains.ssl_expires_at IS
    'Expiration time reported by the provision helper for the active certificate';
