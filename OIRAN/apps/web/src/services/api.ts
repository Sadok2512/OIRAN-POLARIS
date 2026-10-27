import type { ApiEnvelope } from '../types/api';

export class ApiError extends Error { constructor(public status:number, public code:string, message:string){super(message)} }

export const AUTH_TOKEN_KEY='oiran.access_token';
export function getAccessToken(){return sessionStorage.getItem(AUTH_TOKEN_KEY)}
export function setAccessToken(token:string|null){if(token)sessionStorage.setItem(AUTH_TOKEN_KEY,token);else sessionStorage.removeItem(AUTH_TOKEN_KEY)}

export async function api<T>(path:string,init:RequestInit={}):Promise<ApiEnvelope<T>>{
  const token=getAccessToken();
  const headers=new Headers(init.headers);
  if(token)headers.set('Authorization',`Bearer ${token}`);
  if(init.body&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');
  const response=await fetch(`/api/v1${path}`,{...init,headers});
  const body=await response.json().catch(()=>({error:{code:'INVALID_RESPONSE',message:'Invalid API response'}}));
  if(!response.ok)throw new ApiError(response.status,body.error?.code??'REQUEST_FAILED',body.error?.message??response.statusText);
  return body as ApiEnvelope<T>;
}
export async function downloadExport(sessionId:string,format:'json'|'html'){
  const token=getAccessToken();const headers=new Headers();if(token)headers.set('Authorization',`Bearer ${token}`);
  const response=await fetch(`/api/v1/exports/callflow/${encodeURIComponent(sessionId)}?format=${format}`,{headers});
  if(!response.ok)throw new ApiError(response.status,'EXPORT_FAILED','Export failed');
  const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`OIRAN_5G_E2E_CALLFLOW.${format}`;a.click();URL.revokeObjectURL(url);
}
