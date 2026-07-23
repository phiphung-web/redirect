-- Super admins have implicit access to every domain and must not appear as
-- ordinary shared members. Explicit owner rows are preserved.

DELETE FROM public.domain_user_access dua
USING public.users u, public.roles r
WHERE dua.user_id=u.id
  AND u.role_id=r.id
  AND r.name='super_admin'
  AND dua.access_level='member';

