import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render as rtlRender, screen } from '@testing-library/react';
import ProtectedRoute from '../ProtectedRoute';
import { useAuth } from '../../contexts/AuthContext';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// Mock the AuthContext module
vi.mock('../../contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders children when user is authenticated', () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'user-1' },
      loading: false,
    });

    rtlRender(
      <MemoryRouter>
        <ProtectedRoute><div>Protected Content</div></ProtectedRoute>
      </MemoryRouter>
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('redirects to home when user is not authenticated and not loading', () => {
    (useAuth as any).mockReturnValue({
      user: null,
      loading: false,
    });

    // To test redirection, we need to wrap in Routes and check where we end up.
    // Use rtlRender directly to avoid double MemoryRouter from test/utils wrapper.
    rtlRender(
      <MemoryRouter initialEntries={['/protected']}>
        <Routes>
          <Route path="/" element={<div>Home Page</div>} />
          <Route path="/protected" element={
            <ProtectedRoute>
              <div>Protected Content</div>
            </ProtectedRoute>
          } />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Home Page')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });
});
