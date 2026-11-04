import type { Confidence, CorrelationEdge, CorrelationStatusMap } from '../types/api';

export type CorrelationUiStatus='CORRELATED'|'NOT_CORRELATED'|'NO_DATA'|'MISSING_KEY'|'AMBIGUOUS'|'NOT_EVALUATED'|'UNSUPPORTED';
export type BridgeKey='N2_SBI'|'SBI_N4'|'N4_N3'|'S1_MME_S11'|'S11_S1_U'|'E2E';

export interface BridgeAssessment {
  key:BridgeKey;
  label:string;
  status:CorrelationUiStatus;
  rawStatus:Confidence|string|null;
  reason:string;
  edges:CorrelationEdge[];
  evidenceIds:string[];
  dsn:string[];
  matchingIdentifiers:string[];
}

type BridgeDefinition={key:Exclude<BridgeKey,'E2E'>;label:string;interfaces:[string,string]};
const FIVE_G_BRIDGES:BridgeDefinition[]=[
  {key:'N2_SBI',label:'N2 ↔ SBI',interfaces:['N2','SBI']},
  {key:'SBI_N4',label:'SBI ↔ N4',interfaces:['SBI','N4']},
  {key:'N4_N3',label:'N4 ↔ N3',interfaces:['N4','N3']},
];
const LTE_BRIDGES:BridgeDefinition[]=[
  {key:'S1_MME_S11',label:'S1-MME ↔ S11',interfaces:['S1-MME','S11']},
  {key:'S11_S1_U',label:'S11 ↔ S1-U',interfaces:['S11','S1-U']},
];

const samePair=(edge:CorrelationEdge,[left,right]:[string,string])=>(edge.source_interface===left&&edge.target_interface===right)||(edge.source_interface===right&&edge.target_interface===left);
const missingKeyPattern=/\b(missing|absent|unresolved)\b.{0,40}\b(key|identifier|teid|seid|pdu.?session|context)\b/i;
const unique=(values:string[])=>[...new Set(values)];

function assessBridge(definition:BridgeDefinition,interfaces:string[],status:CorrelationStatusMap,edges:CorrelationEdge[],supported=true):BridgeAssessment{
  const pairEdges=edges.filter(edge=>samePair(edge,definition.interfaces));
  // Keep this string-compatible for forward API statuses such as an explicit
  // NOT_CORRELATED without weakening the current backend Confidence type.
  const rawStatus:string|null=status[definition.key]??null;
  const missing=definition.interfaces.filter(required=>!interfaces.includes(required));
  const evidenceIds=unique(pairEdges.flatMap(edge=>[edge.edge_id,edge.source_event_id,edge.target_event_id]));
  // DSN means Data Source Node: an immutable source-file/packet coordinate,
  // not a DNS name and not a correlation claim.
  const dsn=unique(pairEdges.flatMap(edge=>edge.packet_references.map(packet=>`${packet.source_file}#${packet.packet_number}`)));
  const matchingIdentifiers=unique(pairEdges.flatMap(edge=>edge.matching_identifiers));
  const base={key:definition.key,label:definition.label,rawStatus,edges:pairEdges,evidenceIds,dsn,matchingIdentifiers};
  if(!supported)return {...base,status:'UNSUPPORTED',reason:'This correlation bridge is not supported for the reported session technology.'};
  if(missing.length)return {...base,status:'NO_DATA',reason:`Required interface${missing.length>1?'s':''} not observed: ${missing.join(', ')}.`};
  if(rawStatus==='EXACT'||rawStatus==='STRONG'){
    if(pairEdges.some(edge=>edge.confidence==='EXACT'||edge.confidence==='STRONG'))return {...base,status:'CORRELATED',reason:`Engine reported ${rawStatus}; ${pairEdges.length} rule-backed edge${pairEdges.length===1?'':'s'} available.`};
    return {...base,status:'NOT_EVALUATED',reason:`Engine reported ${rawStatus}, but the correlation endpoint returned no matching evidence edge.`};
  }
  if(rawStatus==='POSSIBLE'||pairEdges.some(edge=>edge.confidence==='POSSIBLE'))return {...base,status:'AMBIGUOUS',reason:'Only a possible association is available; the evidence is not unique enough to correlate.'};
  const diagnosticText=pairEdges.flatMap(edge=>[edge.evidence_description,...(edge.limitations??[])]).join(' ');
  if(missingKeyPattern.test(diagnosticText))return {...base,status:'MISSING_KEY',reason:'The engine evidence explicitly reports a missing correlation key or identifier.'};
  if(rawStatus==='NOT_CORRELATED')return {...base,status:'NOT_CORRELATED',reason:'The engine explicitly reported that the bridge is not correlated.'};
  return {...base,status:'NOT_EVALUATED',reason:'Both interfaces are observed, but the engine supplied neither a conclusive status nor a rule-backed edge.'};
}

function assessE2e(bridges:BridgeAssessment[],rawStatus:Confidence|string|null):BridgeAssessment{
  const base={key:'E2E' as const,label:'E2E',rawStatus,edges:bridges.flatMap(bridge=>bridge.edges),evidenceIds:unique(bridges.flatMap(bridge=>bridge.evidenceIds)),dsn:unique(bridges.flatMap(bridge=>bridge.dsn)),matchingIdentifiers:unique(bridges.flatMap(bridge=>bridge.matchingIdentifiers))};
  if(bridges.every(bridge=>bridge.status==='CORRELATED')&&(rawStatus==='EXACT'||rawStatus==='STRONG'))return {...base,status:'CORRELATED',reason:`All ${bridges.length} required bridges are correlated and the engine reported E2E ${rawStatus}.`};
  const precedence:CorrelationUiStatus[]=['NOT_CORRELATED','MISSING_KEY','AMBIGUOUS','NO_DATA','UNSUPPORTED'];
  const blocker=precedence.find(candidate=>bridges.some(bridge=>bridge.status===candidate));
  if(blocker)return {...base,status:blocker,reason:`E2E is not proven because at least one required bridge is ${blocker}.`};
  return {...base,status:'NOT_EVALUATED',reason:'E2E is not proven: at least one required bridge has not been conclusively evaluated.'};
}

export function assessCorrelations(technology:string,interfaces:string[],status:CorrelationStatusMap,edges:CorrelationEdge[]):BridgeAssessment[]{
  const normalized=technology.toUpperCase();
  const isLte=normalized.includes('LTE'),isFiveG=normalized.includes('5G')||normalized.includes('NR');
  const definitions=isLte?LTE_BRIDGES:FIVE_G_BRIDGES;
  const bridges=definitions.map(definition=>assessBridge(definition,interfaces,status,edges,isLte||isFiveG));
  return [...bridges,assessE2e(bridges,status.E2E??null)];
}
