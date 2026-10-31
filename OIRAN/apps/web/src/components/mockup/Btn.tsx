import clsx from 'clsx';
import type { MouseEventHandler, ReactNode } from 'react';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type IconComponent = any;

export function Btn({
  children,
  icon: IconComp,
  primary,
  danger,
  onClick,
  disabled,
  type = 'button',
  title,
  className,
  'data-testid': testId,
}: {
  children: ReactNode;
  icon?: IconComponent;
  primary?: boolean;
  danger?: boolean;
  onClick?: MouseEventHandler<HTMLButtonElement>;
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
  title?: string;
  className?: string;
  'data-testid'?: string;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      data-testid={testId}
      className={clsx(
        'inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap',
        primary
          ? 'bg-brand text-white shadow-e1 hover:brightness-110'
          : danger
            ? 'border border-bad text-bad hover:bg-bad-soft'
            : 'border border-line bg-surface hover:bg-canvas text-ink',
        className,
      )}
    >
      {IconComp ? <IconComp width={15} height={15} aria-hidden /> : null}
      {children}
    </button>
  );
}
