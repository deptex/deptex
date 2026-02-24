import { authenticateUser, AuthRequest } from '../auth';
import { Response, NextFunction } from 'express';
import { supabase } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase');

describe('Auth Middleware', () => {
  let req: Partial<AuthRequest>;
  let res: Partial<Response>;
  let next: jest.Mock;

  beforeEach(() => {
    req = {
      headers: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
    (supabase.auth.getUser as jest.Mock).mockReset();
  });

  it('should return 401 if no auth header', async () => {
    await authenticateUser(req as AuthRequest, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Missing or invalid authorization header' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('should return 401 if auth header does not start with Bearer', async () => {
    req.headers = { authorization: 'Basic token' };
    await authenticateUser(req as AuthRequest, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Missing or invalid authorization header' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('should return 401 if token is invalid', async () => {
    req.headers = { authorization: 'Bearer invalid-token' };
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: null }, error: { message: 'Invalid token' } });

    await authenticateUser(req as AuthRequest, res as Response, next);
    expect(supabase.auth.getUser).toHaveBeenCalledWith('invalid-token');
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid or expired token' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('should call next and set req.user if token is valid', async () => {
    req.headers = { authorization: 'Bearer valid-token' };
    const mockUser = { id: 'user-123', email: 'test@example.com' };
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });

    await authenticateUser(req as AuthRequest, res as Response, next);
    expect(supabase.auth.getUser).toHaveBeenCalledWith('valid-token');
    expect(req.user).toEqual({ id: 'user-123', email: 'test@example.com' });
    expect(next).toHaveBeenCalled();
  });
});
