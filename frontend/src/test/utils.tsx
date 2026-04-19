import React, { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { TooltipProvider } from '../components/ui/tooltip';

// Mock AuthProvider to avoid Supabase calls during tests
// We'll create a MockAuthProvider that can be customized
export const MockAuthProvider = ({ children, user = null, loading = false }: any) => {
  // We need to match the shape of the actual AuthContext
  // We can't use the real AuthContext because it calls Supabase on mount

  // To properly mock the context, we'd need to export the context object itself from AuthContext
  // or mock the whole module.

  // For now, let's rely on module mocking in the tests themselves for AuthContext
  // OR we can just wrap with MemoryRouter which is usually enough if we mock the hooks.
  return <>{children}</>;
};

const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
  return (
    <MemoryRouter>
      <TooltipProvider>
        {children}
      </TooltipProvider>
    </MemoryRouter>
  );
};

const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>,
) => render(ui, { wrapper: AllTheProviders, ...options });

export * from '@testing-library/react';
export { customRender as render };
