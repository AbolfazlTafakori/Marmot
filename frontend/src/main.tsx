import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import { ApiError } from './shared/api/client';
import { AuthProvider } from './shared/auth/AuthProvider';
import { I18nProvider } from './shared/i18n/I18nProvider';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 4xx will not fix itself by retrying.
      retry: (n, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && n < 2,
      refetchOnWindowFocus: true,
    },
  },
});

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <I18nProvider>
          <AuthProvider>
            <App />
          </AuthProvider>
        </I18nProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
