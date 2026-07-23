-- Read-only project sharing. Project owners remain in projects.user_id and
-- super admins retain implicit access without explicit membership rows.

CREATE TABLE IF NOT EXISTS public.project_user_access (
    project_id integer NOT NULL
        REFERENCES public.projects(id) ON DELETE CASCADE,
    user_id integer NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    access_level text NOT NULL DEFAULT 'viewer',
    granted_by integer
        REFERENCES public.users(id) ON DELETE SET NULL,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    CONSTRAINT project_user_access_pk PRIMARY KEY (project_id, user_id),
    CONSTRAINT project_user_access_level_check
        CHECK (access_level = 'viewer')
);

CREATE INDEX IF NOT EXISTS idx_project_user_access_user
    ON public.project_user_access (user_id, project_id);

DELETE FROM public.project_user_access pua
USING public.users u, public.roles r
WHERE pua.user_id=u.id
  AND u.role_id=r.id
  AND r.name='super_admin';
