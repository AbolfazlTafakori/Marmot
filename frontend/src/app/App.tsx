import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AdminsPage } from '@/features/admins/AdminsPage';
import { AuditPage } from '@/features/audit/AuditPage';
import { LoginPage } from '@/features/auth/LoginPage';
import { ConfigPage } from '@/features/config/ConfigPage';
import { DashboardPage } from '@/features/dashboard/DashboardPage';
import { PeersPage } from '@/features/peers/PeersPage';
import { PortsPage } from '@/features/ports/PortsPage';
import { SettingsPage } from '@/features/settings/SettingsPage';
import { useAuth, type Role } from '@/shared/auth/context';
import { Loading } from '@/shared/ui';
import { Layout } from './Layout';

function Gate({ min, children }: { min: Role; children: React.ReactElement }) {
  const { can } = useAuth();
  return can(min) ? children : <Navigate to="/" replace />;
}

export function App() {
  const { me, loading } = useAuth();
  if (loading) {
    return (
      <div className="grid min-h-dvh place-items-center">
        <Loading />
      </div>
    );
  }
  if (!me) return <LoginPage />;
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="peers" element={<PeersPage />} />
          <Route path="ports" element={<PortsPage />} />
          <Route path="config" element={<ConfigPage />} />
          <Route
            path="admins"
            element={
              <Gate min="owner">
                <AdminsPage />
              </Gate>
            }
          />
          <Route
            path="audit"
            element={
              <Gate min="operator">
                <AuditPage />
              </Gate>
            }
          />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
