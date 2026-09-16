import { describe, it, expect } from 'vitest';
import { cn } from '../utils';

describe('Utility: cn()', () => {
  it('combines class names correctly', () => {
    const result = cn('px-4', 'py-2', 'bg-blue-600');
    expect(result).toBe('px-4 py-2 bg-blue-600');
  });

  it('handles conditional class values', () => {
    const isActive = true;
    const isDisabled = false;
    const result = cn('btn', isActive && 'btn-active', isDisabled && 'btn-disabled');
    expect(result).toBe('btn btn-active');
  });

  it('resolves conflicting Tailwind classes by prioritizing the latter', () => {
    // tailwind-merge should ensure px-4 is overridden by px-8
    const result = cn('px-4 py-2', 'px-8');
    expect(result).toBe('py-2 px-8');
  });
});
