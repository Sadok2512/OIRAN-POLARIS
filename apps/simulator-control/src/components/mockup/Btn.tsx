import clsx from 'clsx';
import type { ComponentType, MouseEventHandler, ReactNode } from 'react';

type IconComponent = ComponentType<{ width?: number; height?: number; 'aria-hidden'?: boolean }>;

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
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={clsx(
        'inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-ep-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
        primary
          ? 'bg-brand text-white shadow-e1 hover:brightness-110'
          : danger
            ? 'border border-bad text-bad hover:bg-bad-soft'
            : 'border border-line hover:bg-canvas',
        className,
      )}
    >
      {IconComp ? <IconComp width={15} height={15} aria-hidden /> : null}
      {children}
    </button>
  );
}
