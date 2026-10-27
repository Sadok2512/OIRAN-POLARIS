export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header
      className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between pb-4 border-b border-border mb-5"
      data-testid="page-header"
    >
      <div>
        {eyebrow && (
          <p className="text-ep-xs font-semibold tracking-wider uppercase text-text-secondary">
            {eyebrow}
          </p>
        )}
        <h1 className="text-ep-h2 font-semibold text-text-primary mt-1">
          {title}
        </h1>
        {description && (
          <p className="text-ep-sm text-text-secondary mt-1 max-w-3xl">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
