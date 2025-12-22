/**
 * useAuth Hook - Access authentication context
 *
 * Provides access to authentication state and actions.
 * Must be used within AuthProvider.
 */

import { useContext } from 'react';
import { AuthContext, AuthContextType } from '../contexts/AuthContext';

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
}
