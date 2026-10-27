export function formatTimestampUtc(value: string): string {
  const epochMatch = value.match(/^(\d+)(?:\.(\d+))?Z?$/);
  if (epochMatch) {
    const seconds = Number(epochMatch[1]);
    const milliseconds = Number((epochMatch[2] ?? '').padEnd(3, '0').slice(0, 3));
    if (Number.isFinite(seconds)) return formatDate(new Date(seconds * 1000 + milliseconds));
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : formatDate(parsed);
}

function formatDate(value: Date): string {
  const part = (number: number, width = 2) => String(number).padStart(width, '0');
  return `${value.getUTCFullYear()}-${part(value.getUTCMonth() + 1)}-${part(value.getUTCDate())} ${part(value.getUTCHours())}:${part(value.getUTCMinutes())}:${part(value.getUTCSeconds())}.${part(value.getUTCMilliseconds(), 3)} UTC`;
}
