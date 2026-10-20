import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { api, call, type Schemas } from '@/shared/api/client';
import { useAuth } from '@/shared/auth/context';
import { fill, useI18n } from '@/shared/i18n/useI18n';
import {
  Badge,
  Button,
  Card,
  ErrorMessage,
  Field,
  Input,
  Loading,
  Ltr,
  PageHeader,
  Select,
  Td,
  Table,
} from '@/shared/ui';

type Role = Schemas['Role'];
const adminsKey = ['admins'] as const;

export function AdminsPage() {
  const { m, f } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: adminsKey, queryFn: () => call(api.GET('/admins')) });
  const [adding, setAdding] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('operator');

  const create = useMutation({
    mutationFn: () => call(api.POST('/admins', { body: { username, password, role } })),
    onSuccess: () => {
      setAdding(false);
      setUsername('');
      setPassword('');
      void qc.invalidateQueries({ queryKey: adminsKey });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => call(api.DELETE('/admins/{adminId}', { params: { path: { adminId: id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminsKey }),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };

  return (
    <>
      <PageHeader
        title={m.admins.title}
        actions={
          !adding && (
            <Button
              onClick={() => {
                setAdding(true);
              }}
            >
              {m.admins.add}
            </Button>
          )
        }
      />
      <div className="space-y-4">
        {adding && (
          <Card title={m.admins.add}>
            <form onSubmit={submit} className="grid gap-3 sm:grid-cols-3 sm:items-end">
              <Field label={m.admins.username}>
                <Input
                  ltr
                  required
                  minLength={3}
                  maxLength={32}
                  autoComplete="off"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                  }}
                />
              </Field>
              <Field label={m.admins.password} hint={m.admins.passwordHint}>
                <Input
                  ltr
                  type="password"
                  required
                  minLength={12}
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                  }}
                />
              </Field>
              <Field label={m.admins.role}>
                <Select
                  value={role}
                  onChange={(e) => {
                    setRole(e.target.value as Role);
                  }}
                >
                  {(['owner', 'operator', 'viewer'] as const).map((r) => (
                    <option key={r} value={r}>
                      {m.admins.roles[r]}
                    </option>
                  ))}
                </Select>
              </Field>
              <div className="flex gap-2 sm:col-span-3">
                <Button type="submit" busy={create.isPending}>
                  {m.common.add}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setAdding(false);
                  }}
                >
                  {m.common.cancel}
                </Button>
              </div>
              <div className="sm:col-span-3">
                <ErrorMessage error={create.error} />
              </div>
            </form>
          </Card>
        )}
        <ErrorMessage error={remove.error} />
        <Card>
          <ErrorMessage error={q.error} />
          {!q.data ? (
            <Loading />
          ) : (
            <Table head={[m.admins.username, m.admins.role, m.admins.totp, m.admins.lastLogin, '']}>
              {q.data.map((a) => (
                <tr key={a.id}>
                  <Td>
                    <Ltr>{a.username}</Ltr>
                  </Td>
                  <Td>{m.admins.roles[a.role]}</Td>
                  <Td>
                    <Badge tone={a.totpEnabled ? 'good' : 'neutral'}>
                      {a.totpEnabled ? m.common.yes : m.common.no}
                    </Badge>
                  </Td>
                  <Td>{a.lastLoginAt ? f.dateTime(a.lastLoginAt) : m.common.never}</Td>
                  <Td className="text-end">
                    {a.id !== me?.id && (
                      <Button
                        variant="ghost"
                        className="text-red-700 dark:text-red-400"
                        onClick={() => {
                          if (window.confirm(fill(m.admins.confirmDelete, { name: a.username })))
                            remove.mutate(a.id);
                        }}
                      >
                        {m.common.delete}
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
