import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import type { ColumnDef } from '@tanstack/react-table';
import { ArrowRight, FileSearch, Filter, ListTree, Lock, Search, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';
import type { ApiEnvelope, AuthState, CallFlowEvent, CaptureContext, Dataset, Session, UeContext } from '../types/api';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState, EmptyState } from '../components/AsyncState';
import { StatusBadge } from '../components/StatusBadge';
import { Pagination } from '../components/Pagination';
import { formatTimestampUtc } from '../utils/time';

type Detail={summary:Session;procedures:{name:string;event_ids:string[];status:string}[];accounting:Record<string,number>;capture_references:string[]};
const duration=(value:string)=>{const ns=Number(value);if(!Number.isFinite(ns))return '—';if(ns<1_000_000_000)return `${(ns/1_000_000).toFixed(1)} ms`;return `${(ns/1_000_000_000).toFixed(3)} s`};
const queryString=(params:URLSearchParams)=>{const value=params.toString();return value?`?${value}`:''};

// 2.10.0 — Catalogue des messages courants par interface. La liste
// peut être étendue sans contrat API : elle est purement UI. Si un
// utilisateur a besoin d'un nom non listé, il peut l'ajouter via
// l'entrée libre.
const MESSAGE_CATALOG: { interface: string; messages: string[] }[] = [
  { interface: 'N2',    messages: ['InitialUEMessage','NGSetupRequest','InitialContextSetupRequest','InitialContextSetupResponse','PDUSessionResourceSetupRequest','PDUSessionResourceSetupResponse','PDUSessionResourceSetupFailure','UEContextReleaseRequest','RegistrationReject'] },
  { interface: 'SBI',   messages: ['Namf_Communication_N1N2MessageTransfer','Nsmf_PDUSession_CreateSMContext','Nsmf_PDUSession_UpdateSMContext','Nudm_SDM_Get','Nausf_UEAuthentication'] },
  { interface: 'N4',    messages: ['PFCP Session Establishment Request','PFCP Session Establishment Response','PFCP Session Modification Request','PFCP Session Deletion Request','PFCP Session Deletion Response','PFCP Association Setup Request'] },
  { interface: 'S1-MME',messages: ['Attach Request','Attach Accept','Attach Reject','InitialUEMessage','UEContextReleaseRequest','PathSwitchRequest'] },
  { interface: 'S11',   messages: ['Create Session Request','Create Session Response','Modify Bearer Request','Delete Session Request'] },
];

type IdentityKind = 'supi_or_imsi' | 'imei_or_pei' | 'guti_or_tmsi' | 's_tmsi';

interface AvailableCause { domain: string; value: string; is_failure: boolean; session_count: number }

async function postFilter(body: Record<string, unknown>): Promise<ApiEnvelope<Session[]> & { meta: { identity_matched_pseudonym?: string; next_cursor?: string|null; limit?: number } }> {
  const envelope = await api<Session[]>('/sessions/filter', { method: 'POST', body: JSON.stringify(body) });
  return envelope as ApiEnvelope<Session[]> & { meta: { identity_matched_pseudonym?: string; next_cursor?: string|null; limit?: number } };
}

export function SessionExplorer(){
  const navigate=useNavigate(),route=useParams();
  const [params,setParams]=useSearchParams();
  const [tab,setTab]=useState('summary'),[sessionPage,setSessionPage]=useState(Number(params.get('page')??1)),[eventPage,setEventPage]=useState(1);
  const captureId=params.get('capture_id')??'',requestedDataset=params.get('dataset_id')??params.get('dataset')??'',datasetScope=params.get('dataset_scope')??'',probeId=params.get('probe_id')??'',technology=params.get('technology')??'';
  const search=params.get('search')??'',ue=params.get('ue')??'',iface=params.get('interface')??'',status=params.get('status')??'';

  // 2.10.0 — Filtres avancés (messages, causes, failures_only,
  // identity). Vivent en state local pour ne JAMAIS entrer dans
  // l'URL (critique pour `identity_value` qui ne doit pas être
  // persistée dans l'historique navigateur).
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [filterMessages, setFilterMessages] = useState<{interface?:string;name:string}[]>([]);
  const [filterCauses, setFilterCauses] = useState<{domain?:string;value:string}[]>([]);
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [identityKind, setIdentityKind] = useState<IdentityKind>('supi_or_imsi');
  const [identityValue, setIdentityValue] = useState('');
  const [identityActive, setIdentityActive] = useState(false);

  const auth = useQuery({queryKey:['auth-me'],queryFn:()=>api<AuthState>('/auth/me').then(x=>x.data)});
  const isOperator = auth.data?.role === 'operator' || auth.data?.role === 'administrator';

  const availableCauses = useQuery({queryKey:['sessions-available-causes'],queryFn:()=>api<{causes:AvailableCause[]}>('/sessions/available_causes').then(x=>x.data?.causes??[])});

  const captureContext=useQuery({queryKey:['capture-context',captureId],queryFn:()=>api<CaptureContext>(`/captures/${encodeURIComponent(captureId)}/context`).then(x=>x.data),enabled:!!captureId});
  const datasetId=requestedDataset||captureContext.data?.dataset?.dataset_id||'';
  const datasets=useQuery({queryKey:['datasets'],queryFn:()=>api<Dataset[]>('/datasets?page_size=100').then(x=>x.data)});
  const ues=useQuery({queryKey:['ues'],queryFn:()=>api<UeContext[]>('/ues?page_size=100').then(x=>x.data)});
  useEffect(()=>{if(!requestedDataset&&captureContext.data?.dataset?.dataset_id){const next=new URLSearchParams(params);next.delete('dataset');next.delete('dataset_scope');next.set('dataset_id',captureContext.data.dataset.dataset_id);setParams(next,{replace:true})}},[captureContext.data?.dataset?.dataset_id,requestedDataset,params,setParams]);

  // Mode "advanced": dès qu'un filtre avancé est non vide, bascule
  // sur POST /sessions/filter. Sinon, GET /sessions legacy.
  const advancedActive = filterMessages.length > 0 || filterCauses.length > 0 || failuresOnly || identityActive;

  const sessionQuery=new URLSearchParams({page:String(sessionPage),page_size:'25',sort:'start_timestamp',order:'asc'});if(search)sessionQuery.set('search',search);if(datasetId)sessionQuery.set('dataset_id',datasetId);if(datasetScope)sessionQuery.set('dataset_kind',datasetScope);if(ue)sessionQuery.set('ue_id',ue);if(technology)sessionQuery.set('technology',technology);if(iface)sessionQuery.set('interface',iface);if(status)sessionQuery.set('status',status);
  const contextResolved=!captureId||!!datasetId;

  const sessions=useQuery({queryKey:['sessions',sessionQuery.toString(),contextResolved],queryFn:()=>api<Session[]>(`/sessions?${sessionQuery}`).then(x=>x),enabled:contextResolved && !advancedActive});

  // 2.10.0 — POST /sessions/filter : NE SÉRIALISE JAMAIS
  // identity_value dans queryKey (ce qui le ferait entrer dans la
  // react-query cache clé, lisible via devtools). On hash le value
  // via sa longueur + kind — ça suffit à invalider la query quand
  // la valeur change, SANS fuiter la valeur.
  const identityCacheToken = identityActive
    ? `${identityKind}:${identityValue.length}:${identityValue.length === 0 ? '0' : '1'}`
    : 'none';
  // 2.10.1 (revue devmat) : la pagination est curseur-based sur
  // la clé canonique `(anchor_capture_id, first_packet_number,
  // session_id)`. On n'envoie PLUS `page`/`page_size` au serveur.
  // Le curseur reste en state local (jamais dans l'URL — on garde
  // l'invariant anti-fuite pour l'identity flow).
  const [filterCursor, setFilterCursor] = useState<string | undefined>(undefined);
  useEffect(() => { setFilterCursor(undefined); /* reset on filter change */ }, [failuresOnly, JSON.stringify(filterMessages), JSON.stringify(filterCauses), identityCacheToken]);
  const filteredSessions = useQuery({
    queryKey: ['sessions-filter', filterCursor ?? '', failuresOnly, JSON.stringify(filterMessages), JSON.stringify(filterCauses), identityCacheToken, contextResolved],
    enabled: contextResolved && advancedActive,
    queryFn: () => postFilter({
      messages: filterMessages,
      causes: filterCauses,
      failures_only: failuresOnly,
      identity: identityActive && identityValue.length > 0 ? { kind: identityKind, value: identityValue } : undefined,
      limit: 25,
      cursor: filterCursor,
    }),
  });

  const activeData = advancedActive ? filteredSessions.data : sessions.data;
  const activeLoading = advancedActive ? filteredSessions.isLoading : sessions.isLoading;
  const activeError = advancedActive ? filteredSessions.error : sessions.error;

  const selectedId=route.sessionId??activeData?.data[0]?.session_id;
  const selectedBelongs=!selectedId||activeData?.data.some(session=>session.session_id===selectedId);
  const detail=useQuery({queryKey:['session',selectedId],queryFn:()=>api<Detail>(`/sessions/${selectedId}`).then(x=>x.data),enabled:!!selectedId&&selectedBelongs});
  const events=useQuery({queryKey:['session-events',selectedId,eventPage,tab],queryFn:()=>api<CallFlowEvent[]>(`/sessions/${selectedId}/events?page=${eventPage}&page_size=12&association=${tab==='background'?'BACKGROUND':'SESSION'}`),enabled:!!selectedId&&selectedBelongs&&(tab==='messages'||tab==='background')});
  const update=(key:string,value:string,clearCapture=false)=>{const next=new URLSearchParams(params);value?next.set(key,value):next.delete(key);next.delete('dataset');next.delete('page');next.delete('session_id');if(clearCapture){next.delete('capture_id');next.delete('probe_id')}setSessionPage(1);setEventPage(1);setParams(next)};
  const updateDataset=(value:string)=>{const next=new URLSearchParams(params);next.delete('dataset');next.delete('dataset_id');next.delete('dataset_scope');next.delete('capture_id');next.delete('probe_id');next.delete('page');next.delete('session_id');if(value.startsWith('scope:'))next.set('dataset_scope',value.slice(6));else if(value)next.set('dataset_id',value);setSessionPage(1);setEventPage(1);setParams(next)};
  const contextParams=useMemo(()=>{const next=new URLSearchParams(params);next.delete('page');next.delete('search');return next},[params]);
  const openSession=(session:Session)=>{const next=new URLSearchParams(contextParams);next.set('dataset_id',session.dataset_id);next.set('session_id',session.session_id);if(!next.get('technology'))next.set('technology',session.technology);navigate(`/investigation/sessions/${encodeURIComponent(session.session_id)}${queryString(next)}`)};
  const openCallFlow=(session:Session)=>{const next=new URLSearchParams(contextParams);next.set('dataset_id',session.dataset_id);next.set('session_id',session.session_id);if(!next.get('technology'))next.set('technology',session.technology);navigate(`/investigation/callflow/${encodeURIComponent(session.session_id)}${queryString(next)}`)};
  const toggleMessage = (ifc: string, name: string) => {
    setFilterMessages(prev => {
      const existing = prev.findIndex(m => m.name === name && m.interface === ifc);
      if (existing >= 0) return prev.filter((_, i) => i !== existing);
      return [...prev, { interface: ifc, name }];
    });
    setSessionPage(1);
  };
  const toggleCause = (c: AvailableCause) => {
    setFilterCauses(prev => {
      const existing = prev.findIndex(x => x.value === c.value && x.domain === c.domain);
      if (existing >= 0) return prev.filter((_, i) => i !== existing);
      return [...prev, { domain: c.domain, value: c.value }];
    });
    setSessionPage(1);
  };
  const applyIdentity = () => {
    if (!isOperator) return;
    if (identityValue.length === 0) { setIdentityActive(false); return; }
    setIdentityActive(true);
    setSessionPage(1);
  };
  const clearIdentity = () => {
    setIdentityValue('');
    setIdentityActive(false);
    setSessionPage(1);
  };

  const columns=useMemo<ColumnDef<Session>[]>(()=>[
    {accessorKey:'session_id',header:'Session ID',cell:i=><span className="mono strong">{i.getValue<string>()}</span>},
    {accessorKey:'ue_pseudonym',header:'UE'},
    {accessorKey:'technology',header:'Tech'},
    {accessorKey:'serving_node',header:'Serving Node',cell:i=><span className="compact">{i.getValue<string>()??'NOT AVAILABLE'}</span>},
    {accessorKey:'procedure',header:'Procedure',cell:i=><span className="compact">{i.getValue<string>()}</span>},
    {accessorKey:'pdu_session_id',header:'PDU ID',cell:i=><span className="mono">{i.getValue<string>()}</span>},
    {accessorKey:'start_timestamp',header:'Start Time (UTC)',cell:i=><span className="mono compact" title={i.getValue<string>()}>{formatTimestampUtc(i.getValue<string>())}</span>},
    {accessorKey:'duration_ns',header:'Duration',cell:i=>duration(i.getValue<string>())},
    {accessorKey:'interfaces',header:'Interfaces',cell:i=><div className="chips">{i.getValue<string[]>().map(x=><span key={x}>{x}</span>)}</div>},
    {accessorKey:'message_count',header:'Messages'},
    {accessorKey:'correlation_status',header:'Correlation',cell:i=><StatusBadge value={i.getValue<string>()}/>},
    {id:'decode',header:'Decode Status',cell:i=><span>{i.row.original.decode_completeness.decoded}/{i.row.original.message_count}</span>},
    {id:'action',header:'',cell:i=><button className="link-btn" onClick={event=>{event.stopPropagation();openCallFlow(i.row.original)}}>Call Flow <ArrowRight size={13}/></button>}
  ],[contextParams]);
  if(activeLoading||datasets.isLoading||ues.isLoading||captureContext.isLoading)return <LoadingState/>;
  const error=activeError||datasets.error||ues.error||captureContext.error;if(error)return <ErrorState error={error as Error} retry={()=>{void (advancedActive ? filteredSessions.refetch() : sessions.refetch());void datasets.refetch();void ues.refetch();void captureContext.refetch()}}/>;
  if(captureId&&captureContext.data?.resolution==='DATASET_UNAVAILABLE')return <DatasetUnavailable captureId={captureId} reason={captureContext.data.capture.error??captureContext.data.reason}/>;
  const selectedDataset=datasets.data?.find(item=>item.dataset_id===datasetId);
  const hasObservedLte=datasets.data?.some(item=>item.technology==='LTE')??false;
  const zeroSession=!!datasetId&&activeData?.data.length===0;
  const totalCount = activeData?.meta.total ?? 0;
  return <div className="page-stack">
    <section className="page-intro"><div><p className="eyebrow">INVESTIGATION · UTC</p><h1>Session Explorer</h1><p>Automatically discovered UE contexts and independently reconstructed PDU sessions.</p></div>{selectedId&&selectedBelongs&&<button className="btn primary" onClick={()=>{const session=activeData?.data.find(item=>item.session_id===selectedId);if(session)openCallFlow(session)}}>Open Call Flow <ArrowRight size={15}/></button>}</section>
    {(captureId||datasetId||datasetScope)&&<section className="context-strip"><div><FileSearch/><span><small>Capture</small><b className="mono">{captureId||'NOT SPECIFIED'}</b></span></div><div><ListTree/><span><small>Dataset</small><b className="mono">{datasetId||`ALL ${datasetScope||'DATASETS'}`}</b></span></div>{probeId&&<div><span><small>Probe</small><b className="mono">{probeId}</b></span></div>}<div><span><small>Sessions</small><b>{totalCount}</b></span></div><StatusBadge value={(selectedDataset?.dataset_kind??datasetScope)||'DATASET_CONTEXT'}/></section>}
    <section className="filterbar">
      <label className="search-box wide"><Search/><input aria-label="Search sessions" value={search} onChange={e=>update('search',e.target.value)} placeholder="Session ID, UE or procedure"/></label>
      <select aria-label="Dataset filter" value={datasetId||(datasetScope?`scope:${datasetScope}`:'')} onChange={e=>updateDataset(e.target.value)}><option value="">All datasets</option><option value="scope:HISTORICAL">Historical datasets</option><option value="scope:CAPTURED_LIVE">Live captures</option><option value="scope:RECOVERED">Recovered datasets</option><option value="scope:DERIVED">Derived datasets</option><option value="scope:EVIDENCE">Admitted evidence</option>{(['HISTORICAL','CAPTURED_LIVE','RECOVERED','DERIVED','EVIDENCE'] as const).map(kind=><optgroup label={kind==='CAPTURED_LIVE'?'Live capture datasets':`${kind[0]}${kind.slice(1).toLowerCase()} datasets`} key={kind}>{datasets.data?.filter(item=>item.dataset_kind===kind).map(item=><option value={item.dataset_id} key={item.dataset_id}>{item.display_name} · {item.session_count} session{item.session_count===1?'':'s'}</option>)}</optgroup>)}</select>
      <select aria-label="UE filter" value={ue} onChange={e=>update('ue',e.target.value)}><option value="">All UE contexts</option>{ues.data?.map(item=><option value={item.ue_context_id} key={item.ue_context_id}>{item.ue_pseudonym}</option>)}</select>
      <select aria-label="Technology filter" value={technology} onChange={e=>update('technology',e.target.value)}><option value="">All technologies</option><option value="5G SA">5G SA</option><option value="LTE">{hasObservedLte?'LTE · observed dataset':'LTE · no observed dataset'}</option><option value="UNKNOWN">Unknown / not observed</option></select>
      <select aria-label="Interface filter" value={iface} onChange={e=>update('interface',e.target.value)}><option value="">All interfaces</option><option value="N2">N2</option><option value="SBI">SBI</option><option value="N4">N4</option><option value="N3">N3</option><option value="S1-MME">S1-MME</option><option value="S11">S11</option><option value="S1-U">S1-U</option></select>
      <select aria-label="Session status" value={status} onChange={e=>update('status',e.target.value)}><option value="">All statuses</option><option value="ACTIVE_WITH_USER_PLANE">Active with user plane</option><option value="INCOMPLETE">Incomplete</option><option value="RELEASED">Released</option></select>
      <button type="button" className={`btn ${advancedOpen?'primary':''}`} aria-expanded={advancedOpen} onClick={()=>setAdvancedOpen(v=>!v)}><Filter size={14}/> Advanced {advancedActive && <span className="chip">active</span>}</button>
    </section>
    {advancedOpen && <section className="panel advanced-filters" aria-label="Advanced session filters">
      <div className="advanced-group">
        <h3>Messages</h3>
        <p className="muted small">Any session containing at least one of the selected messages. AND-combined with the other filters.</p>
        {MESSAGE_CATALOG.map(group => <div className="chip-row" key={group.interface}>
          <b className="chip-row-label">{group.interface}</b>
          {group.messages.map(name => {
            const active = filterMessages.some(m => m.name === name && m.interface === group.interface);
            return <button type="button" key={`${group.interface}:${name}`} className={`chip toggle ${active?'on':''}`} onClick={()=>toggleMessage(group.interface, name)}>{name}</button>;
          })}
        </div>)}
      </div>
      <div className="advanced-group">
        <h3>Causes <small className="muted">(counts come from the live dataset)</small></h3>
        <label className="toggle-inline"><input type="checkbox" checked={failuresOnly} onChange={e=>{setFailuresOnly(e.target.checked);setSessionPage(1)}}/> Failures only</label>
        <div className="chip-row">{(availableCauses.data??[]).map(cause => {
          const active = filterCauses.some(c => c.value === cause.value && c.domain === cause.domain);
          return <button type="button" key={`${cause.domain}:${cause.value}`} className={`chip toggle ${active?'on':''} ${cause.is_failure?'failure':''}`} onClick={()=>toggleCause(cause)}>{cause.domain} · {cause.value} <span className="count">{cause.session_count}</span></button>;
        })}{(availableCauses.data??[]).length === 0 && <span className="muted">No causes observed in the current dataset.</span>}</div>
      </div>
      <div className="advanced-group identity-group">
        <h3>Identity lookup <Lock size={13}/> <small className="muted">operator-only</small></h3>
        {!isOperator ? <p className="muted"><ShieldAlert size={14}/> Sign in as an operator to search by SUPI/IMSI, IMEI/PEI, 5G-GUTI/TMSI or S-TMSI. The value you type is never sent to the server as an unauthenticated viewer.</p> : <>
          <p className="muted small">The value you type is <b>pseudonymized server-side</b> with the same keyed HMAC the decoders use, then compared against session pseudonyms. The raw value never enters the URL, logs, response or browser history. 5G-GUTI/5G-S-TMSI are <b>short-lived</b> — a re-registration will rotate them.</p>
          <div className="identity-row">
            <select aria-label="Identity kind" value={identityKind} onChange={e=>setIdentityKind(e.target.value as IdentityKind)}>
              <option value="supi_or_imsi">5G SUPI / IMSI</option>
              <option value="imei_or_pei">IMEI / PEI</option>
              <option value="guti_or_tmsi">5G-GUTI / 5G-S-TMSI (ephemeral)</option>
              <option value="s_tmsi">S-TMSI (LTE, ephemeral)</option>
            </select>
            <input aria-label="Identity value" type="password" autoComplete="off" spellCheck={false} placeholder="Identity value" value={identityValue} onChange={e=>setIdentityValue(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')applyIdentity()}} />
            <button type="button" className="btn primary" onClick={applyIdentity} disabled={identityValue.length === 0}>Match</button>
            {identityActive && <button type="button" className="btn ghost" onClick={clearIdentity}>Clear</button>}
          </div>
          {identityActive && (filteredSessions.data?.meta as { identity_matched_pseudonym?: string } | undefined)?.identity_matched_pseudonym && <p className="muted small">Pseudonym matched: <code>{(filteredSessions.data!.meta as { identity_matched_pseudonym?: string }).identity_matched_pseudonym}</code> · {totalCount} session{totalCount===1?'':'s'} match. (Zero is a valid answer — it means no capture observed this identity.)</p>}
        </>}
      </div>
    </section>}
    <section className="panel session-table-panel">{zeroSession?<ZeroSession captureId={captureId} datasetId={datasetId}/>:activeData?.data.length?<><DataTable data={activeData.data} columns={columns} onRowClick={openSession} selectedId={selectedId} getId={item=>item.session_id}/>{advancedActive ? (() => {
      const nextCursor = (filteredSessions.data?.meta as { next_cursor?: string|null } | undefined)?.next_cursor ?? null;
      return <div className="pagination"><span className="muted">Canonical order (capture_id, first_packet_number, session_id) · cursor-based. {totalCount} session{totalCount===1?'':'s'} match.</span>{filterCursor && <button className="btn" onClick={()=>setFilterCursor(undefined)}>First page</button>}{nextCursor && <button className="btn primary" onClick={()=>setFilterCursor(nextCursor)}>Next page</button>}</div>;
    })() : <Pagination page={activeData.meta.page??1} totalPages={activeData.meta.total_pages??1} onChange={value=>{setSessionPage(value);const next=new URLSearchParams(params);next.set('page',String(value));setParams(next)}}/>}</>:<EmptyState title={advancedActive?'No sessions match the advanced filters':'No sessions match these filters'}/>}</section>
    {selectedId&&!selectedBelongs&&<section className="state-box error"><strong>Session outside the selected dataset</strong><span>OIRAN will not switch to another dataset automatically.</span></section>}
    {selectedId&&selectedBelongs&&<section className="panel details"><div className="panel-head"><div><h2>{selectedId}</h2><p>Session-associated events stay separate from dataset background.</p></div>{detail.data&&<StatusBadge value={detail.data.summary.correlation_status}/>}</div><div className="tabs page-tabs">{['summary','procedures','messages','correlation','provenance','background'].map(value=><button key={value} className={tab===value?'active':''} onClick={()=>{setTab(value);setEventPage(1)}}>{value}</button>)}</div>{detail.isLoading?<LoadingState/>:detail.data&&<SessionTab tab={tab} detail={detail.data} events={events.data} loading={events.isLoading} page={eventPage} setPage={setEventPage}/>}</section>}
  </div>;
}

function ZeroSession({captureId,datasetId}:{captureId:string;datasetId:string}){const context=new URLSearchParams({dataset_id:datasetId});if(captureId)context.set('capture_id',captureId);return <div className="context-empty"><ListTree/><div><h2>{captureId?'No reconstructed sessions in this capture.':'No reconstructed sessions in this dataset.'}</h2><p>The dataset remains available for packet and decoded-event inspection. OIRAN will not substitute a historical session.</p><div className="header-actions"><Link className="btn primary" to={`/analysis/packets?${context}&view=packets`}>View Packets</Link><Link className="btn" to={`/analysis/packets?${context}&view=decoded`}>View Decoded Events</Link>{captureId&&<Link className="btn" to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}>View Capture Details</Link>}</div></div></div>}

function DatasetUnavailable({captureId,reason}:{captureId:string;reason:string}){return <div className="page-stack"><section className="page-intro"><div><p className="eyebrow">INVESTIGATION</p><h1>Session Explorer</h1></div></section><section className="panel context-empty error"><FileSearch/><div><h2>Dataset unavailable for this capture.</h2><p>{reason}</p><p>Recovery requires an authorized offline recovery operation; OIRAN will not substitute another dataset.</p><Link className="btn" to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}>View Capture Details</Link></div></section></div>}

function SessionTab({tab,detail,events,loading,page,setPage}:{tab:string;detail:Detail;events:ApiEnvelope<CallFlowEvent[]>|undefined;loading:boolean;page:number;setPage:(n:number)=>void}){
  if(tab==='summary')return <div className="detail-grid"><dl className="detail-list"><dt>UE pseudonym</dt><dd>{detail.summary.ue_pseudonym||'UNKNOWN'}</dd><dt>PDU Session ID</dt><dd>{detail.summary.pdu_session_id??'UNKNOWN'}</dd><dt>Last observed state</dt><dd>{detail.summary.state==='ACTIVE_WITH_USER_PLANE'?'PDU Active':detail.summary.state}</dd><dt>Technology</dt><dd>{detail.summary.technology}</dd><dt>Serving node</dt><dd>{detail.summary.serving_node??'UNKNOWN'}</dd><dt>Interfaces</dt><dd>{detail.summary.interfaces.join(' · ')||'UNKNOWN'}</dd></dl><dl className="detail-list"><dt>Start (UTC)</dt><dd className="mono">{formatTimestampUtc(detail.summary.start_timestamp)}</dd><dt>Duration</dt><dd>{duration(detail.summary.duration_ns)}</dd><dt>Session events</dt><dd>{detail.summary.message_count}</dd><dt>Background events</dt><dd>{detail.summary.background_event_count??'UNKNOWN'}</dd><dt>Fully decoded</dt><dd>{detail.summary.decode_completeness.decoded??'UNKNOWN'}</dd><dt>Partial</dt><dd>{detail.summary.decode_completeness.partial??'UNKNOWN'}</dd></dl></div>;
  if(tab==='procedures')return <div className="procedure-list">{detail.procedures.filter(x=>x.name!=='Background / Lifecycle').map(x=><article key={x.name}><StatusBadge value={x.status}/><div><b>{x.name}</b><p>{x.event_ids.length} observed events</p></div></article>)}</div>;
  if(tab==='correlation')return <div className="evidence-summary"><StatusBadge value={detail.summary.correlation_status}/><p>Session-scoped evidence is available in Correlation Studio.</p></div>;
  if(tab==='provenance')return <div className="capture-refs">{detail.capture_references.map(x=><code key={x}>{x}</code>)}</div>;
  if(tab==='messages'||tab==='background'){if(loading)return <LoadingState/>;return <><div className="message-list">{events?.data.map(e=><article key={e.event_id}><span className="mono time">{formatTimestampUtc(e.timestamp)}</span><StatusBadge value={e.decoding_status}/><div><b>{e.message_name}</b><small>{e.protocol} · {e.interface} · packet {e.packet_references[0]?.packet_number}</small></div></article>)}</div><Pagination page={page} totalPages={events?.meta.total_pages??1} onChange={setPage}/></>}
  return null;
}
