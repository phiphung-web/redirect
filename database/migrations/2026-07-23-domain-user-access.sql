-- A domain has one explicit owner and may be shared with many active users.
-- Existing production resources are migrated exactly once to the oldest active
-- super admin so no legacy domain/link becomes invisible after the RBAC upgrade.

CREATE TABLE IF NOT EXISTS public.domain_user_access (
    domain_id integer NOT NULL
        REFERENCES public.domains(id) ON DELETE CASCADE,
    user_id integer NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    access_level text NOT NULL DEFAULT 'member'
        CHECK (access_level IN ('owner', 'member')),
    granted_by integer
        REFERENCES public.users(id) ON DELETE SET NULL,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_user_access_one_owner
    ON public.domain_user_access (domain_id)
    WHERE access_level='owner';

CREATE INDEX IF NOT EXISTS idx_domain_user_access_user
    ON public.domain_user_access (user_id, domain_id);

DO $migration$
DECLARE
    super_admin_id integer;
    already_migrated boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM public.app_settings
        WHERE setting_key='migration.domain_user_access.legacy_owner_v1'
    ) INTO already_migrated;

    IF already_migrated THEN
        RETURN;
    END IF;

    SELECT u.id
      INTO super_admin_id
      FROM public.users u
      JOIN public.roles r ON r.id=u.role_id
     WHERE r.name='super_admin' AND u.is_active=true
     ORDER BY u.id
     LIMIT 1;

    IF super_admin_id IS NULL THEN
        RAISE EXCEPTION 'A live super_admin is required before domain access migration';
    END IF;

    -- The user explicitly requested all legacy domains and links to belong to
    -- super_admin. Creator/update audit columns remain available separately.
    UPDATE public.domains
       SET user_id=super_admin_id;

    UPDATE public.campaigns
       SET user_id=super_admin_id;

    UPDATE public.short_links
       SET user_id=super_admin_id;

    INSERT INTO public.domain_user_access
        (domain_id, user_id, access_level, granted_by)
    SELECT d.id, super_admin_id, 'owner', super_admin_id
      FROM public.domains d
    ON CONFLICT (domain_id, user_id) DO UPDATE
       SET access_level='owner',
           granted_by=EXCLUDED.granted_by,
           updated_at=now();

    INSERT INTO public.app_settings (setting_key, setting_value, updated_at)
    VALUES (
        'migration.domain_user_access.legacy_owner_v1',
        jsonb_build_object(
            'super_admin_id', super_admin_id,
            'migrated_at', now()
        ),
        now()
    )
    ON CONFLICT (setting_key) DO NOTHING;
END
$migration$;

-- Self-heal owner membership for domains created by an older application
-- version during a rolling deployment.
INSERT INTO public.domain_user_access
    (domain_id, user_id, access_level, granted_by)
SELECT d.id, d.user_id, 'owner', d.user_id
  FROM public.domains d
 WHERE d.user_id IS NOT NULL
   AND NOT EXISTS (
       SELECT 1
       FROM public.domain_user_access dua
       WHERE dua.domain_id=d.id AND dua.access_level='owner'
   )
ON CONFLICT (domain_id, user_id) DO UPDATE
   SET access_level='owner',
       updated_at=now();
