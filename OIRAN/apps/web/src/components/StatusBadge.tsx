export function StatusBadge({value}:{value:string}){const key=value.toLowerCase().replaceAll('_','-');return <span className={`status status-${key}`}>{value.replaceAll('_',' ')}</span>}
