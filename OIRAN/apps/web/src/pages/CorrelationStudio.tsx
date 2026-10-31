import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import type { ColumnDef } from '@tanstack/react-table';
import { Braces, GitMerge, Link2, Network } from 'lucide-react';
import { api } from '../services/api';
import type { CallFlow, CorrelationEdge, Dataset, Session, UeContext } from '../types/api';
import { LoadingState, ErrorState, EmptyState } from '../components/AsyncState';
import { MetricStrip } from '../components/MetricStrip';
import { DataTable } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';

type Rule={rule_id:string;version:string;classification:string;read_only:boolean;description:string};
type Correlations={status:CallFlow['correlation_status'];edges:CorrelationEdge[]};

export function CorrelationStudio(){
  const navigate=useNavigate(),{sessionId}=useParams();
  const [selected,setSelected]=useState<CorrelationEdge>(),[tab,setTab]=useState('correlated'),[dataset,setDataset]=useState(''),[ue,setUe]=useState(''),[iface,setIface]=useState('');
  const datasets=useQuery({queryKey:['datasets'],queryFn:()=>api<Dataset[]>('/datasets?page_size=100').then(x=>x.data)});
  const ues=useQuery({queryKey:['ues'],queryFn:()=>api<UeContext[]>('/ues?page_size=100').then(x=>x.data)});
  const sessionParams=new URLSearchParams({page_size:'100'});if(dataset)sessionParams.set('dataset_id',dataset);if(ue)sessionParams.set('ue_id',ue);
  const sessions=useQuery({queryKey:['correlation-sessions',sessionParams.toString()],queryFn:()=>api<Session[]>(`/sessions?${sessionParams}`).then(x=>x.data)});
  const activeSession=sessionId??sessions.data?.[0]?.session_id;
  const flow=useQuery({queryKey:['callflow',activeSession],queryFn:()=>api<CallFlow>(`/sessions/${activeSession}/callflow`).then(x=>x.data),enabled:!!activeSession});
  const correlations=useQuery({queryKey:['session-correlations',activeSession],queryFn:()=>api<Correlations>(`/sessions/${activeSession}/correlations`).then(x=>x.data),enabled:!!activeSession});
  const rules=useQuery({queryKey:['rules'],queryFn:()=>api<Rule[]>('/correlation/rules').then(x=>x.data)});
  const edgeData=(correlations.data?.edges??[]).filter(edge=>!iface||edge.source_interface===iface||edge.target_interface===iface);
  const columns=useMemo<ColumnDef<CorrelationEdge>[]>(()=>[
    {accessorKey:'source_event_id',header:'Source event',cell:item=><span className="mono compact">{item.getValue<string>()}</span>},
    {accessorKey:'target_event_id',header:'Target event',cell:item=><span className="mono compact">{item.getValue<string>()}</span>},
    {id:'pair',header:'Interface pair',cell:item=><div className="interface-pair"><span>{item.row.original.source_interface}</span><Link2/><span>{item.row.original.target_interface}</span></div>},
    {accessorKey:'rule_id',header:'Rule',cell:item=><span className="mono compact">{item.getValue<string>()}</span>},
    {accessorKey:'confidence',header:'Confidence',cell:item=><StatusBadge value={item.getValue<string>()}/>},
    {id:'action',header:'',cell:()=> <span className="link-btn">Inspect</span>}
  ],[]);
  if(datasets.isLoading||ues.isLoading||sessions.isLoading||rules.isLoading||(activeSession&&(flow.isLoading||correlations.isLoading)))return <LoadingState/>;
  const error=datasets.error||ues.error||sessions.error||flow.error||correlations.error||rules.error;if(error)return <ErrorState error={error as Error} retry={()=>{void datasets.refetch();void ues.refetch();void sessions.refetch();void flow.refetch();void correlations.refetch();void rules.refetch()}}/>;
  if(!activeSession)return <EmptyState title="No reconstructed sessions">Select another dataset or UE context.</EmptyState>;
  const exact=edgeData.filter(edge=>edge.confidence==='EXACT').length,strong=edgeData.filter(edge=>edge.confidence==='STRONG').length,possible=edgeData.filter(edge=>edge.confidence==='POSSIBLE'||edge.confidence==='UNKNOWN').length;
  return <div className="page-stack">
    <section className="page-intro"><div><p className="eyebrow">INVESTIGATION</p><h1>Correlation Studio</h1><p>Session-scoped evidence generated exclusively by the Rust correlation engine.</p></div><StatusBadge value={`E2E_${flow.data?.correlation_status.E2E}`}/></section>
    <section className="filterbar"><select aria-label="Correlation dataset" value={dataset} onChange={event=>{setDataset(event.target.value);setSelected(undefined)}}><option value="">All datasets</option>{datasets.data?.map(item=><option value={item.dataset_id} key={item.dataset_id}>{item.display_name}</option>)}</select><select aria-label="Correlation UE" value={ue} onChange={event=>{setUe(event.target.value);setSelected(undefined)}}><option value="">All UE contexts</option>{ues.data?.map(item=><option value={item.ue_context_id} key={item.ue_context_id}>{item.ue_pseudonym}</option>)}</select><select aria-label="Correlation session" value={activeSession} onChange={event=>{navigate(`/investigation/correlation/${event.target.value}`);setSelected(undefined)}}>{sessions.data?.map(item=><option value={item.session_id} key={item.session_id}>{item.session_id} · PDU {item.pdu_session_id}</option>)}</select><select aria-label="Correlation interface" value={iface} onChange={event=>setIface(event.target.value)}><option value="">All interfaces</option><option>N2</option><option>N4</option><option>N3</option><option>S1-MME</option><option>S11</option><option>S1-U</option></select></section>
    <MetricStrip items={[{label:'Reconstructed sessions',value:sessions.data?.length??0},{label:'Correlation edges',value:edgeData.length},{label:'Exact links',value:exact,tone:'good'},{label:'Strong links',value:strong},{label:'Possible / Unknown',value:possible}]}/>
    <section className="correlation-grid"><div className="panel graph-panel"><div className="panel-head"><div><h2>Cross-interface graph</h2><p>Graph for <span className="mono">{activeSession}</span>.</p></div><Network/></div><CorrelationGraph edges={edgeData} selected={selected?.edge_id} onSelect={setSelected}/></div><div className="panel evidence-panel"><div className="panel-head"><div><h2>Evidence Inspector</h2><p>Rule-backed packet evidence.</p></div><GitMerge/></div>{selected?<EdgeInspector edge={selected}/>:<EmptyState title="Select a graph or table edge"/>}</div></section>
    <section className="panel"><div className="tabs page-tabs">{['correlated','unmatched','ambiguous','background'].map(value=><button className={tab===value?'active':''} onClick={()=>setTab(value)} key={value}>{value}{value==='correlated'?` (${edgeData.length})`:value==='background'?` (${flow.data?.accounting.background_events})`:' (0)'}</button>)}</div>{tab==='correlated'?<DataTable data={edgeData} columns={columns} onRowClick={setSelected} selectedId={selected?.edge_id} getId={edge=>edge.edge_id}/>:tab==='background'?<div className="state-box"><strong>{flow.data?.accounting.background_events} background events</strong><span>Visible in this session’s Call Flow using “All capture events”.</span></div>:<EmptyState title={`No ${tab} correlations`}>The engine did not conceal or force unresolved relationships.</EmptyState>}</section>
    <section className="panel"><div className="panel-head"><div><h2>Correlation rules</h2><p>Read-only rule registry supplied by the backend.</p></div><Braces/></div><div className="rule-grid">{rules.data?.map(rule=><article key={rule.rule_id}><div><StatusBadge value={rule.classification}/><span className="mono">v{rule.version}</span></div><h3>{rule.rule_id}</h3><p>{rule.description}</p><small>Read-only · replay unavailable in S4.1</small></article>)}</div></section>
  </div>;
}

function CorrelationGraph({edges,selected,onSelect}:{edges:CorrelationEdge[];selected?:string;onSelect:(edge:CorrelationEdge)=>void}){
  const nodes=[{id:'UE',x:80,y:115,label:'UE Context'},{id:'N2',x:245,y:70,label:'N2 · NGAP'},{id:'PDU',x:410,y:115,label:'PDU Session'},{id:'N4',x:575,y:70,label:'N4 · PFCP'},{id:'TUNNEL',x:740,y:115,label:'GTP-U Tunnel'},{id:'N3',x:905,y:70,label:'N3 · GTP-U'}];
  const n2n4=edges.find(edge=>edge.source_interface==='N2'&&edge.target_interface==='N4'),n4n3=edges.find(edge=>edge.source_interface==='N4'&&edge.target_interface==='N3');
  const lines=[{a:1,b:2,edge:n2n4},{a:2,b:3,edge:n2n4},{a:3,b:4,edge:n4n3},{a:4,b:5,edge:n4n3}];
  return <svg className="correlation-graph" viewBox="0 0 990 220" aria-label="N2 N4 N3 correlation graph"><defs><marker id="cg-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z"/></marker></defs>{lines.map((line,index)=>line.edge&&<g key={index} className={selected===line.edge.edge_id?'edge selected':'edge'} onClick={()=>onSelect(line.edge!)}><line x1={nodes[line.a].x} y1={nodes[line.a].y} x2={nodes[line.b].x} y2={nodes[line.b].y} markerEnd="url(#cg-arrow)"/><text x={(nodes[line.a].x+nodes[line.b].x)/2} y={(nodes[line.a].y+nodes[line.b].y)/2-9}>{line.edge.confidence}</text></g>)}{nodes.map(node=><g className="graph-node" key={node.id}><rect x={node.x-63} y={node.y-25} width="126" height="50" rx="9"/><text x={node.x} y={node.y+4} textAnchor="middle">{node.label}</text></g>)}</svg>;
}

function EdgeInspector({edge}:{edge:CorrelationEdge}){return <div className="edge-inspector"><StatusBadge value={edge.confidence}/><dl className="detail-list"><dt>Evidence type</dt><dd>{edge.evidence_type??'UNKNOWN'}</dd><dt>Scope</dt><dd>{edge.scope||'Not specified'}</dd><dt>Source</dt><dd className="mono">{edge.source_event_id}</dd><dt>Target</dt><dd className="mono">{edge.target_event_id}</dd><dt>Interfaces</dt><dd>{edge.source_interface} ↔ {edge.target_interface}</dd><dt>Rule</dt><dd className="mono">{edge.rule_id} v{edge.rule_version}</dd><dt>Evidence</dt><dd>{edge.evidence_description}</dd><dt>Limitations</dt><dd>{edge.limitations?.join(' · ')||'None recorded'}</dd><dt>Packets</dt><dd>{edge.packet_references.map(packet=>`${packet.source_file} #${packet.packet_number}`).join(' · ')}</dd></dl><h3>Matching identifiers</h3><div className="chips">{edge.matching_identifiers.map(identifier=><span key={identifier}>{identifier}</span>)}</div></div>}
