import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../test/utils';
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

  it('renders loading state when loading is true', () => {
    (useAuth as any).mockReturnValue({
      user: null,
      loading: true,
    });

    render(<ProtectedRoute><div>Protected Content</div></ProtectedRoute>);

    // It should render the spinner container (checking for class or structure could be fragile, but let's check for "min-h-screen" div or similar)
    // Actually, looking at the code:
    /*
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    */
    // We can query by generic role or class if we really want, but checking that content is NOT there is a good start.
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();

    // We can check for the spinner by class
    const spinner = document.querySelector('.animate-spin');
    expect(spinner).toBeInTheDocument();
  });

  it('renders children when user is authenticated', () => {
    (useAuth as any).mockReturnValue({
      user: { id: 'user-1' },
      loading: false,
    });

    render(<ProtectedRoute><div>Protected Content</div></ProtectedRoute>);

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('redirects to home when user is not authenticated and not loading', () => {
    (useAuth as any).mockReturnValue({
      user: null,
      loading: false,
    });

    // To test redirection, we need to wrap in Routes and check where we end up
    render(
      <MemoryRouter initialEntries={['/protected']}>
        <Routes>
          <Route path="/" element={<div>Home Page</div>} />
          <Route path="/protected" element={
            <ProtectedRoute>
              <div>Protected Content</div>
            </ProtectedRoute>
          } />
        </Routes>
      </MemoryRouter>,
      { wrapper: undefined } // Override the default wrapper which adds another router
    );

    expect(screen.getByText('Home Page')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });
});
