import { describe, expect, it } from 'vitest';
import { assessCorrelations } from '../correlation/statusMapping';
import type { CorrelationEdge, CorrelationStatusMap } from '../types/api';

const packet={source_file:'capture://n2.pcapng',packet_number:17,byte_offset:0,interface_id:0,captured_length:100,original_length:100};
const edge=(id:string,left:string,right:string,confidence:'EXACT'|'STRONG'|'POSSIBLE'|'UNKNOWN'='STRONG'):CorrelationEdge=>({
  edge_id:id,source_event_id:`${id}-source`,target_event_id:`${id}-target`,source_interface:left,target_interface:right,
  matching_identifiers:[`pdu_session_id=${id}`],rule_id:`${id}-rule`,rule_version:'1',evidence_description:'Rule-backed context association',
  packet_references:[{...packet,source_file:`capture://${left.toLowerCase()}.pcapng`}],confidence,
});

describe('correlation UI status mapping',()=>{
  it('maps a complete real-shaped 5G bridge set to CORRELATED only with rule-backed edges',()=>{
    const status:CorrelationStatusMap={N2_SBI:'STRONG',SBI_N4:'STRONG',N4_N3:'EXACT',E2E:'STRONG'};
    const result=assessCorrelations('5G SA',['N2','SBI','N4','N3'],status,[edge('n2-sbi','N2','SBI'),edge('sbi-n4','SBI','N4'),edge('n4-n3','N4','N3','EXACT')]);
    expect(result.map(item=>[item.key,item.status])).toEqual([['N2_SBI','CORRELATED'],['SBI_N4','CORRELATED'],['N4_N3','CORRELATED'],['E2E','CORRELATED']]);
    expect(result[0].evidenceIds).toContain('n2-sbi');
    expect(result[0].dsn).toEqual(['capture://n2.pcapng#17']);
  });

  it('does not promote an engine confidence when its evidence endpoint has no edge',()=>{
    // 2.8.0: N2_SBI rawStatus=STRONG without a matching edge keeps the
    // conflict label NOT_EVALUATED (engine lied, no edge). SBI_N4 and
    // N4_N3 rawStatus=UNKNOWN WITHOUT edges surface as OPEN — both
    // interfaces are observed, no correlation key has fired, and the
    // UI must NOT mask the link.
    const result=assessCorrelations('5G SA',['N2','SBI','N4','N3'],{N2_SBI:'STRONG',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'EXACT'},[]);
    expect(result.find(item=>item.key==='N2_SBI')?.status).toBe('NOT_EVALUATED');
    expect(result.find(item=>item.key==='SBI_N4')?.status).toBe('OPEN');
    expect(result.find(item=>item.key==='N4_N3')?.status).toBe('OPEN');
    // E2E inherits OPEN as a blocker — a correlated E2E chain needs
    // every required bridge to be CORRELATED; an OPEN bridge keeps
    // the chain visibly unproven with its reason, never silently
    // promoted.
    expect(result.find(item=>item.key==='E2E')?.status).toBe('OPEN');
    expect(result.find(item=>item.key==='SBI_N4')?.reason).toContain('open');
  });

  it('distinguishes NO_DATA, AMBIGUOUS and MISSING_KEY without inventing a negative result',()=>{
    const noData=assessCorrelations('5G SA',['N2','N4'],{N2_SBI:'UNKNOWN',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},[]);
    expect(noData.find(item=>item.key==='N2_SBI')?.status).toBe('NO_DATA');
    const possible=edge('possible','N2','SBI','POSSIBLE');
    const ambiguous=assessCorrelations('5G SA',['N2','SBI','N4','N3'],{N2_SBI:'POSSIBLE',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},[possible]);
    expect(ambiguous.find(item=>item.key==='N2_SBI')?.status).toBe('AMBIGUOUS');
    const missing={...edge('missing','SBI','N4','UNKNOWN'),limitations:['Missing TEID correlation key']};
    const keyed=assessCorrelations('5G SA',['N2','SBI','N4','N3'],{N2_SBI:'UNKNOWN',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},[missing]);
    expect(keyed.find(item=>item.key==='SBI_N4')?.status).toBe('MISSING_KEY');
  });

  it('selects the LTE bridge contract instead of evaluating unsupported 5G bridges',()=>{
    const result=assessCorrelations('LTE',['S1-MME','S11','S1-U'],{S1_MME_S11:'UNKNOWN',S11_S1_U:'UNKNOWN',E2E:'UNKNOWN'},[]);
    expect(result.map(item=>item.key)).toEqual(['S1_MME_S11','S11_S1_U','E2E']);
    // 2.8.0: without an engine confidence and without edges, both
    // observed LTE bridges are OPEN — not NOT_EVALUATED — so the UI
    // surfaces them with their reason rather than hiding them.
    expect(result.every(item=>item.status==='OPEN')).toBe(true);
  });

  it('uses UNSUPPORTED for an unrecognized technology instead of guessing 5G',()=>{
    const result=assessCorrelations('UNKNOWN',['N2','SBI','N4','N3'],{N2_SBI:'UNKNOWN',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},[]);
    expect(result.slice(0,3).every(item=>item.status==='UNSUPPORTED')).toBe(true);
    expect(result.at(-1)?.status).toBe('UNSUPPORTED');
  });
});
