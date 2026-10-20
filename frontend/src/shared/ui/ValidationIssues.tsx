import type { Schemas } from '../api/client';
import { Alert, Ltr } from './index';

/** The issues of a rejected configuration, each with its config path. */
export function ValidationIssues({ result }: { result: Schemas['ValidationResult'] | null }) {
  if (!result || result.issues.length === 0) return null;
  const errors = result.issues.some((i) => i.severity === 'error');
  return (
    <Alert tone={errors ? 'error' : 'warning'}>
      <ul className="space-y-0.5">
        {result.issues.map((i, n) => (
          <li key={n}>
            {i.path && (
              <>
                <Ltr>{i.path}</Ltr>:{' '}
              </>
            )}
            <Ltr mono={false}>{i.message}</Ltr>
          </li>
        ))}
      </ul>
    </Alert>
  );
}
