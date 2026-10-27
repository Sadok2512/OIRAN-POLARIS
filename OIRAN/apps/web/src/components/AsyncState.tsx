import type { ReactNode } from 'react';
export function LoadingState(){return <div className="state-box" role="status"><span className="spinner"/>Loading certified data…</div>}
export function ErrorState({error,retry}:{error:Error;retry:()=>void}){return <div className="state-box error"><strong>Unable to load data</strong><span>{error.message}</span><button className="btn" onClick={retry}>Retry</button></div>}
export function EmptyState({title='No records',children}:{title?:string;children?:ReactNode}){return <div className="state-box"><strong>{title}</strong>{children}</div>}
