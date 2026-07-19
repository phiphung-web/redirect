-- Optional interstitial delay for short links.
-- Existing links keep redirecting immediately; new delayed links use 3 seconds.

ALTER TABLE public.short_links
    ADD COLUMN IF NOT EXISTS redirect_delay_seconds smallint NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.short_links.redirect_delay_seconds IS
    'Seconds to show the redirect waiting page. Zero redirects immediately.';
