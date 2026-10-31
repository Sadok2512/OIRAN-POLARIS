export type RadioTechnology = '5G_SA' | 'LTE';

export function TechnologySelector({
  value,
  onChange,
}: {
  value: RadioTechnology;
  onChange: (value: RadioTechnology) => void;
}) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-surface p-1" role="group" aria-label="Radio technology">
      <button
        type="button"
        className={`ep-button ep-button-sm ${value === '5G_SA' ? 'ep-button-primary' : ''}`}
        aria-pressed={value === '5G_SA'}
        onClick={() => onChange('5G_SA')}
        data-testid="technology-5g"
      >
        5G SA — UERANSIM
      </button>
      <button
        type="button"
        className={`ep-button ep-button-sm ${value === 'LTE' ? 'ep-button-primary' : ''}`}
        aria-pressed={value === 'LTE'}
        onClick={() => onChange('LTE')}
        data-testid="technology-lte"
      >
        LTE 4G — srsRAN
      </button>
    </div>
  );
}
