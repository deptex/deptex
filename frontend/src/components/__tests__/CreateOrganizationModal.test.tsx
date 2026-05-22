import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import userEvent from '@testing-library/user-event';
import CreateOrganizationModal from '../CreateOrganizationModal';

const mockCreateOrganization = vi.fn();

vi.mock('../../lib/api', () => ({
  api: {
    createOrganization: (...a: unknown[]) => mockCreateOrganization(...a),
  },
}));

describe('CreateOrganizationModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateOrganization.mockResolvedValue({ id: 'new-org', name: 'New Org' });
  });

  it('renders nothing when closed', () => {
    render(<CreateOrganizationModal isOpen={false} onClose={vi.fn()} onSuccess={vi.fn()} />);
    expect(screen.queryByText('Create a new organization')).not.toBeInTheDocument();
  });

  it('Create is disabled until a name is entered', async () => {
    render(<CreateOrganizationModal isOpen onClose={vi.fn()} onSuccess={vi.fn()} />);
    const create = screen.getByRole('button', { name: 'Create' });
    expect(create).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Organization Name'), 'Acme');
    expect(create).not.toBeDisabled();
  });

  it('submitting creates the org and fires onSuccess then onClose', async () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();
    render(<CreateOrganizationModal isOpen onClose={onClose} onSuccess={onSuccess} />);

    await userEvent.type(screen.getByLabelText('Organization Name'), 'Acme');
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(mockCreateOrganization).toHaveBeenCalledWith('Acme');
      expect(onSuccess).toHaveBeenCalledWith({ id: 'new-org', name: 'New Org' });
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('surfaces the error message when creation fails', async () => {
    mockCreateOrganization.mockRejectedValueOnce(new Error('Name already taken'));
    render(<CreateOrganizationModal isOpen onClose={vi.fn()} onSuccess={vi.fn()} />);

    await userEvent.type(screen.getByLabelText('Organization Name'), 'Acme');
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(screen.getByText('Name already taken')).toBeInTheDocument();
    });
  });

  it('Cancel closes the modal without creating', async () => {
    const onClose = vi.fn();
    render(<CreateOrganizationModal isOpen onClose={onClose} onSuccess={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onClose).toHaveBeenCalled();
    expect(mockCreateOrganization).not.toHaveBeenCalled();
  });
});
