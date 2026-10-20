import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, type ReactNode } from 'react';
import { api, ApiError, call, setCsrfToken, setUnauthorizedHandler } from '../api/client';
import { AuthContext, meKey, type Role } from './context';

const rank: Record<Role, number> = { viewer: 1, operator: 2, owner: 3 };

/** Loads the current administrator; a 401 means "show the login page". */
export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: meKey,
    queryFn: async () => {
      try {
        return await call(api.GET('/auth/me'));
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    retry: false,
    staleTime: Infinity,
  });
  const me = q.data ?? null;
  useEffect(() => {
    setCsrfToken(me?.csrfToken ?? '');
  }, [me]);
  useEffect(() => {
    setUnauthorizedHandler(() => {
      qc.setQueryData(meKey, null);
    });
  }, [qc]);
  const can = (min: Role) => (me ? rank[me.role] >= rank[min] : false);
  return <AuthContext.Provider value={{ me, loading: q.isPending, can }}>{children}</AuthContext.Provider>;
}
