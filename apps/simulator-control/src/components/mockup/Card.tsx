import clsx from 'clsx';
import type { HTMLAttributes, ReactNode } from 'react';

type CardProps = Omit<HTMLAttributes<HTMLElement>, 'className'> & {
  children: ReactNode;
  className?: string;
};

export function Card({ children, className, ...rest }: CardProps) {
  return (
    <section
      className={clsx('rounded-xl border border-line bg-surface shadow-e1', className)}
      {...rest}
    >
      {children}
    </section>
  );
}
