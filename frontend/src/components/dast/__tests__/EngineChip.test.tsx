import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/utils';
import { EngineChip } from '../EngineChip';

// EngineChip labels each DAST finding with its producing engine. Pre-v2.1c
// rows carry no engine value and must fall back to ZAP rather than render blank.

describe('EngineChip', () => {
  it('renders the ZAP label for engine="zap"', () => {
    render(<EngineChip engine="zap" />);
    expect(screen.getByText('ZAP')).toBeInTheDocument();
  });

  it('renders the Nuclei label for engine="nuclei"', () => {
    render(<EngineChip engine="nuclei" />);
    expect(screen.getByText('Nuclei')).toBeInTheDocument();
  });

  it('renders the Merged label for engine="merged"', () => {
    render(<EngineChip engine="merged" />);
    expect(screen.getByText('Merged')).toBeInTheDocument();
  });

  it('falls back to ZAP when engine is null (pre-v2.1c rows)', () => {
    render(<EngineChip engine={null} />);
    expect(screen.getByText('ZAP')).toBeInTheDocument();
  });

  it('falls back to ZAP when engine is undefined', () => {
    render(<EngineChip />);
    expect(screen.getByText('ZAP')).toBeInTheDocument();
  });
});
