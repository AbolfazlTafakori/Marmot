import createClient, { type Middleware } from 'openapi-fetch';
import type { components, paths } from './schema';

export type Schemas = components['schemas'];

/** An API failure with the server's error code (see openapi.yaml Error). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
  }
}

// The CSRF token comes with the session (Me.csrfToken) and must accompany
// every state-changing request.
let csrfToken = '';
export function setCsrfToken(t: string): void {
  csrfToken = t;
}

// Called when the server says the session is gone, so the app can show
// the login page.
let onUnauthorized: () => void = () => undefined;
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

const csrf: Middleware = {
  onRequest({ request }) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method) && csrfToken) {
      request.headers.set('X-CSRF-Token', csrfToken);
    }
    return request;
  },
  onResponse({ response, request }) {
    if (response.status === 401 && !request.url.endsWith('/auth/login')) onUnauthorized();
    return response;
  },
};

// fetch is looked up per call (not captured once), and the base is the
// page's own origin, so the panel always talks to the node that served it.
export const api = createClient<paths>({
  baseUrl: `${window.location.origin}/api/v1`,
  credentials: 'same-origin',
  fetch: (req: Request) => globalThis.fetch(req),
});
api.use(csrf);

interface Result<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Returns the data or throws an ApiError carrying the server's code. */
export async function call<T>(p: Promise<Result<T>>): Promise<T> {
  let r: Result<T>;
  try {
    r = await p;
  } catch (e) {
    throw new ApiError(0, 'network', e instanceof Error ? e.message : 'network error');
  }
  if (r.response.ok) return r.data as T;
  const err = r.error as { code?: string; message?: string } | undefined;
  throw new ApiError(
    r.response.status,
    err?.code ?? `http_${r.response.status}`,
    err?.message ?? r.response.statusText,
    r.error,
  );
}

/** The validation result of a 422 answer, if that is what err is. */
export function validationOf(err: unknown): Schemas['ValidationResult'] | null {
  if (err instanceof ApiError && err.status === 422) return err.body as Schemas['ValidationResult'];
  return null;
}
