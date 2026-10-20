import { useMutation, useQueryClient } from '@tanstack/react-query';
import { NavLink, Outlet } from 'react-router-dom';
import { api, call } from '@/shared/api/client';
import { meKey, useAuth, type Role } from '@/shared/auth/context';
import { useLiveEvents } from '@/shared/hooks/useLiveEvents';
import { useI18n } from '@/shared/i18n/useI18n';
import { Badge, Button } from '@/shared/ui';
import { cx } from '@/shared/ui/cx';
import { LiveContext } from './live';

export function Layout() {
  const { m } = useI18n();
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const live = useLiveEvents(true);

  const logout = useMutation({
    mutationFn: () => call(api.POST('/auth/logout')),
    onSettled: () => {
      qc.clear();
      qc.setQueryData(meKey, null);
    },
  });

  const links: { to: string; label: string; min: Role }[] = [
    { to: '/', label: m.nav.dashboard, min: 'viewer' },
    { to: '/peers', label: m.nav.peers, min: 'viewer' },
    { to: '/ports', label: m.nav.ports, min: 'viewer' },
    { to: '/config', label: m.nav.config, min: 'viewer' },
    { to: '/admins', label: m.nav.admins, min: 'owner' },
    { to: '/audit', label: m.nav.audit, min: 'operator' },
    { to: '/settings', label: m.nav.settings, min: 'viewer' },
  ];

  return (
    <div className="min-h-dvh md:grid md:grid-cols-[14rem_minmax(0,1fr)]">
      <aside className="border-b border-stone-200 bg-white md:min-h-dvh md:border-e md:border-b-0 dark:border-stone-800 dark:bg-stone-900">
        <div className="flex items-center justify-between gap-2 px-4 py-4">
          <div>
            <p className="text-lg font-bold">{m.app.name}</p>
            <p className="text-xs text-stone-500">{m.app.tagline}</p>
          </div>
          <Badge tone={live.connected ? 'good' : 'warn'}>
            {live.connected ? m.status.live : m.status.offline}
          </Badge>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:overflow-visible">
          {links
            .filter((l) => can(l.min))
            .map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.to === '/'}
                className={({ isActive }) =>
                  cx(
                    'rounded-md px-3 py-1.5 text-sm whitespace-nowrap',
                    isActive
                      ? 'bg-sky-50 font-semibold text-sky-800 dark:bg-sky-950 dark:text-sky-200'
                      : 'text-stone-700 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800',
                  )
                }
              >
                {l.label}
              </NavLink>
            ))}
        </nav>
        <div className="hidden border-t border-stone-200 px-4 py-3 text-sm md:block dark:border-stone-800">
          <p className="truncate font-medium">{me?.username}</p>
          <p className="mb-2 text-xs text-stone-500">{me ? m.admins.roles[me.role] : ''}</p>
          <Button
            variant="ghost"
            className="-ms-2"
            busy={logout.isPending}
            onClick={() => {
              logout.mutate();
            }}
          >
            {m.nav.logout}
          </Button>
        </div>
      </aside>
      <main className="mx-auto w-full max-w-6xl min-w-0 p-4 md:p-6">
        <LiveContext.Provider value={live}>
          <Outlet />
        </LiveContext.Provider>
      </main>
    </div>
  );
}
