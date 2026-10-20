import { createContext, useContext } from 'react';
import type { Schemas } from '../api/client';

export type Me = Schemas['Me'];
export type Role = Schemas['Role'];

export interface Auth {
  me: Me | null;
  loading: boolean;
  can: (min: Role) => boolean;
}

export const AuthContext = createContext<Auth>({ me: null, loading: true, can: () => false });

export const meKey = ['me'] as const;

export function useAuth(): Auth {
  return useContext(AuthContext);
}
