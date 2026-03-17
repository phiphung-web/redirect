CREATE TABLE IF NOT EXISTS public.admin_audit_logs (
    id bigserial PRIMARY KEY,
    request_id text,
    user_id integer REFERENCES public.users(id) ON DELETE SET NULL,
    username text,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text,
    status text NOT NULL DEFAULT 'success',
    detail jsonb,
    ip text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created_at
    ON public.admin_audit_logs USING btree (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_user_id
    ON public.admin_audit_logs USING btree (user_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_request_id
    ON public.admin_audit_logs USING btree (request_id);
