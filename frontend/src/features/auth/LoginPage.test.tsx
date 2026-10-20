import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { meKey } from '@/shared/auth/context';
import { renderWithProviders, stubFetch } from '@/test/render';
import { LoginPage } from './LoginPage';

const me = { id: '1', username: 'root', role: 'owner', totpEnabled: true, csrfToken: 'c', locale: 'fa' };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('LoginPage', () => {
  it('is Persian and right-to-left by default', () => {
    renderWithProviders(<LoginPage />);
    expect(screen.getByRole('heading', { name: 'ورود به پنل' })).toBeInTheDocument();
    expect(document.documentElement.dir).toBe('rtl');
    expect(document.documentElement.lang).toBe('fa');
  });

  it('asks for the TOTP code when the server requires it, then signs in', async () => {
    const calls = stubFetch([
      { status: 401, body: { code: 'totp_required', message: 'enter code' } },
      { status: 200, body: me },
    ]);
    const user = userEvent.setup();
    const { qc } = renderWithProviders(<LoginPage />);
    await user.type(screen.getByLabelText('نام کاربری'), 'root');
    await user.type(screen.getByLabelText('رمز عبور'), 'secret-password');
    await user.click(screen.getByRole('button', { name: 'ورود' }));

    const code = await screen.findByLabelText('کد احراز هویت');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument(); // a step, not an error
    await user.type(code, '12a3456');
    await user.click(screen.getByRole('button', { name: 'ورود' }));

    await waitFor(() => {
      expect(qc.getQueryData(meKey)).toEqual(me);
    });
    const body = (await calls[1]?.json()) as Record<string, string>;
    expect(body).toEqual({ username: 'root', password: 'secret-password', totp: '123456' });
  });

  it('shows the server error in Persian', async () => {
    stubFetch([
      { status: 401, body: { code: 'invalid_credentials', message: 'wrong username or password' } },
    ]);
    const user = userEvent.setup();
    renderWithProviders(<LoginPage />);
    await user.type(screen.getByLabelText('نام کاربری'), 'root');
    await user.type(screen.getByLabelText('رمز عبور'), 'x');
    await user.click(screen.getByRole('button', { name: 'ورود' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('نام کاربری یا رمز عبور اشتباه است.');
  });

  it('switches to English', async () => {
    const user = userEvent.setup();
    renderWithProviders(<LoginPage />);
    await user.click(screen.getByRole('button', { name: 'English' }));
    expect(screen.getByRole('heading', { name: 'Sign in to the panel' })).toBeInTheDocument();
    expect(document.documentElement.dir).toBe('ltr');
  });
});
