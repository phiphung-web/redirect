INSERT INTO public.roles (name, description)
VALUES ('user', 'Manage own domains and links; no user administration')
ON CONFLICT (name) DO UPDATE SET description=EXCLUDED.description;

UPDATE public.users
SET role_id=(SELECT id FROM public.roles WHERE name='user')
WHERE role_id IN (SELECT id FROM public.roles WHERE name='admin');

DELETE FROM public.roles WHERE name='admin';
