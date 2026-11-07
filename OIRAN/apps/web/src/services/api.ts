import type { ApiEnvelope } from '../types/api';

export class ApiError extends Error { constructor(public status:number, public code:string, message:string){super(message)} }

export const AUTH_TOKEN_KEY='oiran.access_token';
export function getAccessToken(){return sessionStorage.getItem(AUTH_TOKEN_KEY)}
export function setAccessToken(token:string|null){if(token)sessionStorage.setItem(AUTH_TOKEN_KEY,token);else sessionStorage.removeItem(AUTH_TOKEN_KEY)}

// 2.9.0 (#9): per-URL ETag cache for GET requests. When a server
// returns an `ETag`, subsequent requests to the same URL carry
// `If-None-Match`; a 304 response reuses the cached body. ANR2
// measured the dataset list at 727 KiB served every 3 s under the old
// contract (~0.87 GiB/h/browser). With this flow a stable list costs
// ~300 B per poll.
interface EtagEntry { etag:string; body:ApiEnvelope<unknown> }
const etagCache = new Map<string, EtagEntry>();

// 2.9.0: per-URL `304` streak counter. The caller can use
// `recommendedPollInterval(path, baseMs)` to grow the polling cadence
// when the server keeps replying "nothing changed", and reset it on
// the next 200.
const unchangedStreaks = new Map<string, number>();
export function recommendedPollInterval(path:string, baseMs:number):number{
  const streak = unchangedStreaks.get(path) ?? 0;
  // Double the interval every 3 consecutive 304s, capped at 10× base.
  const factor = Math.min(10, 1 + Math.floor(streak / 3));
  return baseMs * factor;
}
export function resetPollInterval(path:string){unchangedStreaks.delete(path)}

export async function api<T>(path:string,init:RequestInit={}):Promise<ApiEnvelope<T>>{
  const token=getAccessToken();
  const headers=new Headers(init.headers);
  if(token)headers.set('Authorization',`Bearer ${token}`);
  if(init.body&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');
  const method=(init.method??'GET').toUpperCase();
  const cacheKey=`${method} ${path}`;
  if(method==='GET'){
    const cached=etagCache.get(cacheKey);
    if(cached&&!headers.has('If-None-Match'))headers.set('If-None-Match',cached.etag);
  }
  const response=await fetch(`/api/v1${path}`,{...init,headers});
  if(method==='GET'&&response.status===304){
    const cached=etagCache.get(cacheKey);
    if(cached){
      unchangedStreaks.set(cacheKey,(unchangedStreaks.get(cacheKey)??0)+1);
      return cached.body as ApiEnvelope<T>;
    }
    // ETag advertised on a response we never saw — fall through to a
    // forced re-fetch without `If-None-Match`.
    headers.delete('If-None-Match');
    const retry=await fetch(`/api/v1${path}`,{...init,headers});
    const retryBody=await retry.json().catch(()=>({error:{code:'INVALID_RESPONSE',message:'Invalid API response'}}));
    if(!retry.ok)throw new ApiError(retry.status,retryBody.error?.code??'REQUEST_FAILED',retryBody.error?.message??retry.statusText);
    const etag=retry.headers.get('ETag');
    if(method==='GET'&&etag&&retry.ok)etagCache.set(cacheKey,{etag,body:retryBody});
    unchangedStreaks.delete(cacheKey);
    return retryBody as ApiEnvelope<T>;
  }
  const body=await response.json().catch(()=>({error:{code:'INVALID_RESPONSE',message:'Invalid API response'}}));
  if(!response.ok)throw new ApiError(response.status,body.error?.code??'REQUEST_FAILED',body.error?.message??response.statusText);
  const etag=response.headers.get('ETag');
  if(method==='GET'&&etag)etagCache.set(cacheKey,{etag,body});
  unchangedStreaks.delete(cacheKey);
  return body as ApiEnvelope<T>;
}
export async function downloadExport(sessionId:string,format:'json'|'html'){
  const token=getAccessToken();const headers=new Headers();if(token)headers.set('Authorization',`Bearer ${token}`);
  const response=await fetch(`/api/v1/exports/callflow/${encodeURIComponent(sessionId)}?format=${format}`,{headers});
  if(!response.ok)throw new ApiError(response.status,'EXPORT_FAILED','Export failed');
  const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`OIRAN_5G_E2E_CALLFLOW.${format}`;a.click();URL.revokeObjectURL(url);
}
