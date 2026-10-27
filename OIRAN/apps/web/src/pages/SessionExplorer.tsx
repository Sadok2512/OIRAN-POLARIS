import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import type { ColumnDef } from '@tanstack/react-table';
import { ArrowRight, FileSearch, ListTree, Search } from 'lucide-react';
import { api } from '../services/api';
import type { ApiEnvelope, CallFlowEvent, CaptureContext, Dataset, Session, UeContext } from '../types/api';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState, EmptyState } from '../components/AsyncState';
import { StatusBadge } from '../components/StatusBadge';
import { Pagination } from '../components/Pagination';
import { formatTimestampUtc } from '../utils/time';

type Detail={summary:Session;procedures:{name:string;event_ids:string[];status:string}[];accounting:Record<string,number>;capture_references:string[]};
const duration=(value:string)=>{const ns=Number(value);if(!Number.isFinite(ns))return '—';if(ns<1_000_000_000)return `${(ns/1_000_000).toFixed(1)} ms`;return `${(ns/1_000_000_000).toFixed(3)} s`};
const queryString=(params:URLSearchParams)=>{const value=params.toString();return value?`?${value}`:''};

export function SessionExplorer(){
  const navigate=useNavigate(),route=useParams();
  const [params,setParams]=useSearchParams();
  const [tab,setTab]=useState('summary'),[sessionPage,setSessionPage]=useState(Number(params.get('page')??1)),[eventPage,setEventPage]=useState(1);
  const captureId=params.get('capture_id')??'',requestedDataset=params.get('dataset_id')??params.get('dataset')??'',datasetScope=params.get('dataset_scope')??'',probeId=params.get('probe_id')??'',technology=params.get('technology')??'';
  const search=params.get('search')??'',ue=params.get('ue')??'',iface=params.get('interface')??'',status=params.get('status')??'';
  const captureContext=useQuery({queryKey:['capture-context',captureId],queryFn:()=>api<CaptureContext>(`/captures/${encodeURIComponent(captureId)}/context`).then(x=>x.data),enabled:!!captureId});
  const datasetId=requestedDataset||captureContext.data?.dataset?.dataset_id||'';
  const datasets=useQuery({queryKey:['datasets'],queryFn:()=>api<Dataset[]>('/datasets?page_size=100').then(x=>x.data)});
  const ues=useQuery({queryKey:['ues'],queryFn:()=>api<UeContext[]>('/ues?page_size=100').then(x=>x.data)});
  useEffect(()=>{if(!requestedDataset&&captureContext.data?.dataset?.dataset_id){const next=new URLSearchParams(params);next.delete('dataset');next.delete('dataset_scope');next.set('dataset_id',captureContext.data.dataset.dataset_id);setParams(next,{replace:true})}},[captureContext.data?.dataset?.dataset_id,requestedDataset,params,setParams]);
  const sessionQuery=new URLSearchParams({page:String(sessionPage),page_size:'25',sort:'start_timestamp',order:'asc'});if(search)sessionQuery.set('search',search);if(datasetId)sessionQuery.set('dataset_id',datasetId);if(datasetScope)sessionQuery.set('dataset_kind',datasetScope);if(ue)sessionQuery.set('ue_id',ue);if(technology)sessionQuery.set('technology',technology);if(iface)sessionQuery.set('interface',iface);if(status)sessionQuery.set('status',status);
  const contextResolved=!captureId||!!datasetId;
  const sessions=useQuery({queryKey:['sessions',sessionQuery.toString(),contextResolved],queryFn:()=>api<Session[]>(`/sessions?${sessionQuery}`).then(x=>x),enabled:contextResolved});
  const selectedId=route.sessionId??sessions.data?.data[0]?.session_id;
  const selectedBelongs=!selectedId||sessions.data?.data.some(session=>session.session_id===selectedId);
  const detail=useQuery({queryKey:['session',selectedId],queryFn:()=>api<Detail>(`/sessions/${selectedId}`).then(x=>x.data),enabled:!!selectedId&&selectedBelongs});
  const events=useQuery({queryKey:['session-events',selectedId,eventPage,tab],queryFn:()=>api<CallFlowEvent[]>(`/sessions/${selectedId}/events?page=${eventPage}&page_size=12&association=${tab==='background'?'BACKGROUND':'SESSION'}`),enabled:!!selectedId&&selectedBelongs&&(tab==='messages'||tab==='background')});
  const update=(key:string,value:string,clearCapture=false)=>{const next=new URLSearchParams(params);value?next.set(key,value):next.delete(key);next.delete('dataset');next.delete('page');next.delete('session_id');if(clearCapture){next.delete('capture_id');next.delete('probe_id')}setSessionPage(1);setEventPage(1);setParams(next)};
  const updateDataset=(value:string)=>{const next=new URLSearchParams(params);next.delete('dataset');next.delete('dataset_id');next.delete('dataset_scope');next.delete('capture_id');next.delete('probe_id');next.delete('page');next.delete('session_id');if(value.startsWith('scope:'))next.set('dataset_scope',value.slice(6));else if(value)next.set('dataset_id',value);setSessionPage(1);setEventPage(1);setParams(next)};
  const contextParams=useMemo(()=>{const next=new URLSearchParams(params);next.delete('page');next.delete('search');return next},[params]);
  const openSession=(session:Session)=>{const next=new URLSearchParams(contextParams);next.set('dataset_id',session.dataset_id);next.set('session_id',session.session_id);if(!next.get('technology'))next.set('technology',session.technology);navigate(`/investigation/sessions/${encodeURIComponent(session.session_id)}${queryString(next)}`)};
  const openCallFlow=(session:Session)=>{const next=new URLSearchParams(contextParams);next.set('dataset_id',session.dataset_id);next.set('session_id',session.session_id);if(!next.get('technology'))next.set('technology',session.technology);navigate(`/investigation/callflow/${encodeURIComponent(session.session_id)}${queryString(next)}`)};
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
  if(sessions.isLoading||datasets.isLoading||ues.isLoading||captureContext.isLoading)return <LoadingState/>;
  const error=sessions.error||datasets.error||ues.error||captureContext.error;if(error)return <ErrorState error={error as Error} retry={()=>{void sessions.refetch();void datasets.refetch();void ues.refetch();void captureContext.refetch()}}/>;
  if(captureId&&captureContext.data?.resolution==='DATASET_UNAVAILABLE')return <DatasetUnavailable captureId={captureId} reason={captureContext.data.capture.error??captureContext.data.reason}/>;
  const selectedDataset=datasets.data?.find(item=>item.dataset_id===datasetId);
  const zeroSession=!!datasetId&&sessions.data?.data.length===0;
  return <div className="page-stack">
    <section className="page-intro"><div><p className="eyebrow">INVESTIGATION · UTC</p><h1>Session Explorer</h1><p>Automatically discovered UE contexts and independently reconstructed PDU sessions.</p></div>{selectedId&&selectedBelongs&&<button className="btn primary" onClick={()=>{const session=sessions.data?.data.find(item=>item.session_id===selectedId);if(session)openCallFlow(session)}}>Open Call Flow <ArrowRight size={15}/></button>}</section>
    {(captureId||datasetId||datasetScope)&&<section className="context-strip"><div><FileSearch/><span><small>Capture</small><b className="mono">{captureId||'NOT SPECIFIED'}</b></span></div><div><ListTree/><span><small>Dataset</small><b className="mono">{datasetId||`ALL ${datasetScope||'DATASETS'}`}</b></span></div>{probeId&&<div><span><small>Probe</small><b className="mono">{probeId}</b></span></div>}<div><span><small>Sessions</small><b>{sessions.data?.meta.total??0}</b></span></div><StatusBadge value={(selectedDataset?.dataset_kind??datasetScope)||'DATASET_CONTEXT'}/></section>}
    <section className="filterbar">
      <label className="search-box wide"><Search/><input aria-label="Search sessions" value={search} onChange={e=>update('search',e.target.value)} placeholder="Session ID, UE or procedure"/></label>
      <select aria-label="Dataset filter" value={datasetId||(datasetScope?`scope:${datasetScope}`:'')} onChange={e=>updateDataset(e.target.value)}><option value="">All datasets</option><option value="scope:HISTORICAL">Historical datasets</option><option value="scope:CAPTURED_LIVE">Live captures</option><option value="scope:RECOVERED">Recovered datasets</option><option value="scope:DERIVED">Derived datasets</option>{(['HISTORICAL','CAPTURED_LIVE','RECOVERED','DERIVED'] as const).map(kind=><optgroup label={kind==='CAPTURED_LIVE'?'Live capture datasets':`${kind[0]}${kind.slice(1).toLowerCase()} datasets`} key={kind}>{datasets.data?.filter(item=>item.dataset_kind===kind).map(item=><option value={item.dataset_id} key={item.dataset_id}>{item.display_name} · {item.session_count} session{item.session_count===1?'':'s'}</option>)}</optgroup>)}</select>
      <select aria-label="UE filter" value={ue} onChange={e=>update('ue',e.target.value)}><option value="">All UE contexts</option>{ues.data?.map(item=><option value={item.ue_context_id} key={item.ue_context_id}>{item.ue_pseudonym}</option>)}</select>
      <select aria-label="Technology filter" value={technology} onChange={e=>update('technology',e.target.value)}><option value="">All technologies</option><option value="5G SA">5G SA</option></select>
      <select aria-label="Interface filter" value={iface} onChange={e=>update('interface',e.target.value)}><option value="">All interfaces</option><option value="N2">N2</option><option value="SBI">SBI</option><option value="N4">N4</option><option value="N3">N3</option></select>
      <select aria-label="Session status" value={status} onChange={e=>update('status',e.target.value)}><option value="">All statuses</option><option value="ACTIVE_WITH_USER_PLANE">Active with user plane</option><option value="INCOMPLETE">Incomplete</option><option value="RELEASED">Released</option></select>
    </section>
    <section className="panel session-table-panel">{zeroSession?<ZeroSession captureId={captureId} datasetId={datasetId}/>:sessions.data?.data.length?<><DataTable data={sessions.data.data} columns={columns} onRowClick={openSession} selectedId={selectedId} getId={item=>item.session_id}/><Pagination page={sessions.data.meta.page??1} totalPages={sessions.data.meta.total_pages??1} onChange={value=>{setSessionPage(value);const next=new URLSearchParams(params);next.set('page',String(value));setParams(next)}}/></>:<EmptyState title="No sessions match these filters"/>}</section>
    {selectedId&&!selectedBelongs&&<section className="state-box error"><strong>Session outside the selected dataset</strong><span>OIRAN will not switch to another dataset automatically.</span></section>}
    {selectedId&&selectedBelongs&&<section className="panel details"><div className="panel-head"><div><h2>{selectedId}</h2><p>Session-associated events stay separate from dataset background.</p></div>{detail.data&&<StatusBadge value={detail.data.summary.correlation_status}/>}</div><div className="tabs page-tabs">{['summary','procedures','messages','correlation','provenance','background'].map(value=><button key={value} className={tab===value?'active':''} onClick={()=>{setTab(value);setEventPage(1)}}>{value}</button>)}</div>{detail.isLoading?<LoadingState/>:detail.data&&<SessionTab tab={tab} detail={detail.data} events={events.data} loading={events.isLoading} page={eventPage} setPage={setEventPage}/>}</section>}
  </div>;
}

function ZeroSession({captureId,datasetId}:{captureId:string;datasetId:string}){const context=new URLSearchParams({dataset_id:datasetId});if(captureId)context.set('capture_id',captureId);return <div className="context-empty"><ListTree/><div><h2>{captureId?'No reconstructed sessions in this capture.':'No reconstructed sessions in this dataset.'}</h2><p>The dataset remains available for packet and decoded-event inspection. OIRAN will not substitute a historical session.</p><div className="header-actions"><Link className="btn primary" to={`/analysis/packets?${context}&view=packets`}>View Packets</Link><Link className="btn" to={`/analysis/packets?${context}&view=decoded`}>View Decoded Events</Link>{captureId&&<Link className="btn" to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}>View Capture Details</Link>}</div></div></div>}

function DatasetUnavailable({captureId,reason}:{captureId:string;reason:string}){return <div className="page-stack"><section className="page-intro"><div><p className="eyebrow">INVESTIGATION</p><h1>Session Explorer</h1></div></section><section className="panel context-empty error"><FileSearch/><div><h2>Dataset unavailable for this capture.</h2><p>{reason}</p><p>Recovery requires an authorized offline recovery operation; OIRAN will not substitute another dataset.</p><Link className="btn" to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}>View Capture Details</Link></div></section></div>}

function SessionTab({tab,detail,events,loading,page,setPage}:{tab:string;detail:Detail;events:ApiEnvelope<CallFlowEvent[]>|undefined;loading:boolean;page:number;setPage:(n:number)=>void}){
  if(tab==='summary')return <div className="detail-grid"><dl className="detail-list"><dt>UE pseudonym</dt><dd>{detail.summary.ue_pseudonym}</dd><dt>PDU Session ID</dt><dd>{detail.summary.pdu_session_id}</dd><dt>Last observed state</dt><dd>{detail.summary.state==='ACTIVE_WITH_USER_PLANE'?'PDU Active':detail.summary.state}</dd><dt>Technology</dt><dd>{detail.summary.technology}</dd><dt>Serving node</dt><dd>{detail.summary.serving_node??'NOT AVAILABLE'}</dd><dt>Interfaces</dt><dd>{detail.summary.interfaces.join(' · ')}</dd></dl><dl className="detail-list"><dt>Start (UTC)</dt><dd className="mono">{formatTimestampUtc(detail.summary.start_timestamp)}</dd><dt>Duration</dt><dd>{duration(detail.summary.duration_ns)}</dd><dt>Session events</dt><dd>{detail.summary.message_count}</dd><dt>Background events</dt><dd>{detail.summary.background_event_count}</dd><dt>Fully decoded</dt><dd>{detail.summary.decode_completeness.decoded}</dd><dt>Partial</dt><dd>{detail.summary.decode_completeness.partial}</dd></dl></div>;
  if(tab==='procedures')return <div className="procedure-list">{detail.procedures.filter(x=>x.name!=='Background / Lifecycle').map(x=><article key={x.name}><StatusBadge value={x.status}/><div><b>{x.name}</b><p>{x.event_ids.length} observed events</p></div></article>)}</div>;
  if(tab==='correlation')return <div className="evidence-summary"><StatusBadge value={detail.summary.correlation_status}/><p>Session-scoped evidence is available in Correlation Studio.</p></div>;
  if(tab==='provenance')return <div className="capture-refs">{detail.capture_references.map(x=><code key={x}>{x}</code>)}</div>;
  if(tab==='messages'||tab==='background'){if(loading)return <LoadingState/>;return <><div className="message-list">{events?.data.map(e=><article key={e.event_id}><span className="mono time">{formatTimestampUtc(e.timestamp)}</span><StatusBadge value={e.decoding_status}/><div><b>{e.message_name}</b><small>{e.protocol} · {e.interface} · packet {e.packet_references[0]?.packet_number}</small></div></article>)}</div><Pagination page={page} totalPages={events?.meta.total_pages??1} onChange={setPage}/></>}
  return null;
}
