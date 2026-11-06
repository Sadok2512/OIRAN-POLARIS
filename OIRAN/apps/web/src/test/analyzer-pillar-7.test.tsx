import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { assessCorrelations } from '../correlation/statusMapping';
import type { CallFlow, CorrelationEdge } from '../types/api';
import { CallFlowViewer, n3Aggregate, n3AggregateLabel as labelOf, type N3Aggregate } from '../pages/CallFlowViewer';
import { api } from '../services/api';

void labelOf;
void (null as unknown as N3Aggregate);

vi.mock('../services/api',()=>({api:vi.fn(),downloadExport:vi.fn()}));

const packet=(nr:number)=>({source_file:'capture://n3.pcapng',packet_number:nr,byte_offset:nr*96,interface_id:0,captured_length:96,original_length:96});

describe('OIRAN 2.8.0 analyzer pillar 7',()=>{
  describe('SBI↔N2 / SBI↔N4 tunnel-match bridges',()=>{
    it('exposes matched_rules and both EXACT bridges when 2.8.0 edges are present',()=>{
      const sbiN2:CorrelationEdge={edge_id:'sbi-n2',source_event_id:'sbi','target_event_id':'ngap',source_interface:'SBI',target_interface:'N2',matching_identifiers:['endpoint_ip=10.77.22.13','teid=0xb3b5'],rule_id:'sbi-n2-tunnel-match',rule_version:'2.0.0',evidence_description:'SBI n2SmInfo tunnel matches N2 setup tunnel',packet_references:[packet(1)],confidence:'EXACT',evidence_type:'EXACT_TUNNEL_MATCH',scope:'tunnel-only',limitations:['Does not prove UE identity'],matched_rules:['ngap-sbi-context-association','sbi-n2-tunnel-match']};
      const sbiN4:CorrelationEdge={edge_id:'sbi-n4',source_event_id:'sbi','target_event_id':'pfcp',source_interface:'SBI',target_interface:'N4',matching_identifiers:['endpoint_ip=10.77.22.13','teid=0xb3b5'],rule_id:'sbi-n4-tunnel-match',rule_version:'2.0.0',evidence_description:'SBI n2SmInfo tunnel matches N4 Created-PDR F-TEID',packet_references:[packet(2)],confidence:'EXACT',evidence_type:'EXACT_TUNNEL_MATCH',scope:'tunnel-only',limitations:[],matched_rules:['sbi-n4-tunnel-match']};
      const n4N3:CorrelationEdge={edge_id:'n4-n3',source_event_id:'pfcp','target_event_id':'gtpu',source_interface:'N4',target_interface:'N3',matching_identifiers:['endpoint_ip=10.77.22.13','teid=0xb3b5'],rule_id:'pfcp-outer-header-matches-gtpu-tunnel',rule_version:'2.0.0',evidence_description:'',packet_references:[packet(3)],confidence:'EXACT',evidence_type:'EXACT_TUNNEL_MATCH',scope:'tunnel-only',matched_rules:['n4-n3-discovered-teid-endpoint','pfcp-outer-header-matches-gtpu-tunnel']};
      const result=assessCorrelations('5G SA',['N2','SBI','N4','N3'],{N2_SBI:'EXACT',SBI_N4:'EXACT',N4_N3:'EXACT',E2E:'EXACT'},[sbiN2,sbiN4,n4N3]);
      const n2sbi=result.find(b=>b.key==='N2_SBI');
      const sbin4=result.find(b=>b.key==='SBI_N4');
      const n4n3=result.find(b=>b.key==='N4_N3');
      const e2e=result.find(b=>b.key==='E2E');
      expect(n2sbi?.status).toBe('CORRELATED');
      expect(sbin4?.status).toBe('CORRELATED');
      expect(n4n3?.status).toBe('CORRELATED');
      expect(e2e?.status).toBe('CORRELATED');
      // 2.8.0: matched_rules preserved and union-ed per bridge.
      expect(n2sbi?.matchedRules).toEqual(expect.arrayContaining(['ngap-sbi-context-association','sbi-n2-tunnel-match']));
      expect(sbin4?.matchedRules).toEqual(['sbi-n4-tunnel-match']);
      expect(n4n3?.matchedRules).toEqual(expect.arrayContaining(['n4-n3-discovered-teid-endpoint','pfcp-outer-header-matches-gtpu-tunnel']));
      // E2E union surfaces every observed rule across the chain.
      expect(e2e?.matchedRules).toEqual(expect.arrayContaining(['sbi-n2-tunnel-match','sbi-n4-tunnel-match','pfcp-outer-header-matches-gtpu-tunnel']));
    });

    it('surfaces an OPEN bridge with its reason instead of hiding it',()=>{
      // 2.8.0 contract: both interfaces observed, no correlation edge
      // → OPEN (NEVER hidden). The reason is the human-facing text
      // operators must see.
      const result=assessCorrelations('5G SA',['N2','SBI','N4','N3'],{N2_SBI:'UNKNOWN',SBI_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},[]);
      const sbiN4=result.find(b=>b.key==='SBI_N4');
      expect(sbiN4?.status).toBe('OPEN');
      expect(sbiN4?.reason).toMatch(/open — never inferred from timestamps/i);
      expect(sbiN4?.matchedRules).toEqual([]);
    });
  });

  describe('N3 aggregate rendering',()=>{
    const aggregateEvent={event_id:'n3-agg-1',timestamp:'1792872460.000000000Z',timestamp_ns:'1792872460000000000',interface:'N3',protocol:'GTP-U',message_name:'G-PDU',source_participant:'gNB',destination_participant:'UPF',direction:'RAN_TO_CORE',decoded_ie_tree:[{id:null,name:'teid',length:4,value:'0xb3b5',raw_sha256:null,status:'DECODED' as const},{id:null,name:'tunnel_endpoint_ip',length:4,value:'10.77.22.13',raw_sha256:null,status:'DECODED' as const},{id:null,name:'aggregate_packet_count',length:0,value:'1247',raw_sha256:null,status:'DECODED' as const},{id:null,name:'qfi',length:1,value:'5',raw_sha256:null,status:'DECODED' as const}],decoding_status:'DECODED' as const,semantic_status:'NORMAL' as const,association:'SESSION' as const,procedure_group:'User Plane',packet_references:[{source_file:'capture://n3.pcapng',packet_number:120,byte_offset:0,interface_id:0,captured_length:96,original_length:96},{source_file:'capture://n3.pcapng',packet_number:1366,byte_offset:0,interface_id:0,captured_length:96,original_length:96}],capture_id:'cap',decoder_name:'live-probe-n3-flow-aggregator',decoder_version:'0.4.14',raw_payload_reference:'n3-flow-aggregate:cap:0xb3b5:120-1366',errors:[]};

    it('extracts gtpu_frame_count + TEID + IP + canonical first/last packet',()=>{
      const aggregate=n3Aggregate(aggregateEvent);
      expect(aggregate).not.toBeNull();
      expect(aggregate?.gtpuFrameCount).toBe(1247);
      expect(aggregate?.teid).toBe('0xb3b5');
      expect(aggregate?.endpointIp).toBe('10.77.22.13');
      expect(aggregate?.firstPacket).toBe(120);
      expect(aggregate?.lastPacket).toBe(1366);
      expect(aggregate?.qfi).toBe('5');
    });

    it('renders ONE aggregate row with gtpu_frame_count, TEID and first→last frame, not one row per G-PDU',async()=>{
      const flow:CallFlow={callflow_id:'cf',session_id:'n3-agg-session',technology:'5G SA',start_timestamp:aggregateEvent.timestamp,end_timestamp:aggregateEvent.timestamp,participants:[{id:'gnb',role:'gNB',addresses:['10.0.0.1']},{id:'upf',role:'UPF',addresses:['10.0.0.2']}],interfaces:['N3'],procedures:[{id:'user-plane',name:'User Plane',event_ids:[aggregateEvent.event_id],status:'OBSERVED'}],events:[aggregateEvent],correlation_edges:[],correlation_status:{N2_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},decoder_versions:{},schema_version:'1.0.0',capture_references:[],accounting:{source_events:1,session_events:1,background_events:0,unmatched_events:0,duplicate_events:0,extra_events:0},unresolved_fields:0};
      const summary={session_id:flow.session_id,dataset_id:'dataset-a',ue_context_id:'ue-a',technology:'5G SA',ue_pseudonym:'UE-A',pdu_session_id:'1',procedure:'PDU',start_timestamp:flow.start_timestamp,end_timestamp:flow.end_timestamp,duration_ns:'0',interfaces:['N3'],message_count:1,source_event_count:1,background_event_count:0,correlation_status:'UNKNOWN' as const,decode_completeness:{decoded:1,partial:0,unresolved_fields:0},state:'ACTIVE'};
      vi.mocked(api).mockImplementation(async(path?:string)=>{
        if(path===undefined)return {data:[],meta:{}} as never;
        if(path===`/sessions/${flow.session_id}`)return {data:{summary},meta:{}} as never;
        if(path===`/sessions/${flow.session_id}/callflow?limit=100`)return {data:flow,meta:{}} as never;
        if(path===`/sessions/${flow.session_id}/correlations`)return {data:{status:flow.correlation_status,edges:[]},meta:{}} as never;
        throw new Error(`unexpected path ${path}`);
      });
      const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
      render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/investigation/callflow/${flow.session_id}?dataset_id=dataset-a`]}><Routes><Route path="/investigation/callflow/:sessionId" element={<CallFlowViewer/>}/></Routes></MemoryRouter></QueryClientProvider>);
      const row=await screen.findByTestId('flow-event-n3-aggregate');
      expect(row.textContent).toContain('1247 frames');
      expect(row.textContent).toContain('#120→#1366');
      expect(row.textContent).toContain('TEID=0xb3b5');
      expect(row.textContent).toContain('10.77.22.13');
      // Inspector exposes the same aggregate context when the row is selected.
      await userEvent.click(row);
      const summaryIe=await screen.findByTestId('n3-aggregate-summary');
      expect(summaryIe.textContent).toContain('1247 frames');
    });
  });

  describe('callflow pagination keeps canonical (capture_id, seq, event_id) order',()=>{
    const makeEvent=(id:string,packetNumber:number)=>({event_id:id,timestamp:'1.0Z',timestamp_ns:`${packetNumber}`,interface:'N2',protocol:'NGAP',message_name:'InitialUEMessage',source_participant:'gNB',destination_participant:'AMF',direction:'RAN_TO_CORE',decoded_ie_tree:[],decoding_status:'DECODED' as const,semantic_status:'NORMAL' as const,association:'SESSION' as const,procedure_group:'UE Registration',packet_references:[{source_file:'capture://n2.pcapng',packet_number:packetNumber,byte_offset:0,interface_id:0,captured_length:1,original_length:1}],capture_id:'cap-A',decoder_name:'decoder-ngap',decoder_version:'1',raw_payload_reference:'sha256:x',errors:[]});
    const page=(events:ReturnType<typeof makeEvent>[],cursor:string|null,nextCursor:string|null):CallFlow=>({callflow_id:'cf',session_id:'paged',technology:'5G SA',start_timestamp:'1.0Z',end_timestamp:'1.0Z',participants:[{id:'gnb',role:'gNB',addresses:['10.0.0.1']},{id:'amf',role:'AMF',addresses:['10.0.0.2']}],interfaces:['N2'],procedures:[{id:'reg',name:'UE Registration',event_ids:events.map(event=>event.event_id),status:'OBSERVED'}],events,correlation_edges:[],correlation_status:{N2_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},decoder_versions:{},schema_version:'1.0.0',capture_references:[],accounting:{source_events:4,session_events:4,background_events:0,unmatched_events:0,duplicate_events:0,extra_events:0},unresolved_fields:0,pagination:{cursor,limit:2,next_cursor:nextCursor,returned_events:events.length,total_events:4}});
    beforeEach(()=>{
      const summary={session_id:'paged',dataset_id:'dataset-a',ue_context_id:'ue-a',technology:'5G SA',ue_pseudonym:'UE-A',pdu_session_id:'1',procedure:'PDU',start_timestamp:'1.0Z',end_timestamp:'1.0Z',duration_ns:'0',interfaces:['N2'],message_count:4,source_event_count:4,background_event_count:0,correlation_status:'UNKNOWN' as const,decode_completeness:{decoded:4,partial:0,unresolved_fields:0},state:'ACTIVE'};
      vi.mocked(api).mockImplementation(async(path?:string)=>{
        if(path===undefined)return {data:[],meta:{}} as never;
        if(path==='/sessions/paged')return {data:{summary},meta:{}} as never;
        if(path==='/sessions/paged/callflow?limit=100')return {data:page([makeEvent('evt-A-001',1),makeEvent('evt-A-002',2)],null,'evt-A-002'),meta:{}} as never;
        if(path==='/sessions/paged/callflow?limit=100&cursor=evt-A-002')return {data:page([makeEvent('evt-A-003',3),makeEvent('evt-A-004',4)],'evt-A-002',null),meta:{}} as never;
        if(path==='/sessions/paged/correlations')return {data:{status:{N2_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},edges:[]},meta:{}} as never;
        throw new Error(`unexpected path ${path}`);
      });
    });

    it('walks the cursor in canonical order without loss or duplicate',async()=>{
      const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
      render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/investigation/callflow/paged?dataset_id=dataset-a']}><Routes><Route path="/investigation/callflow/:sessionId" element={<CallFlowViewer/>}/></Routes></MemoryRouter></QueryClientProvider>);
      expect(await screen.findByText(/1–2 of 4 observed/)).toBeVisible();
      await userEvent.click(screen.getByRole('button',{name:'Next'}));
      expect(await screen.findByText(/3–4 of 4 observed/)).toBeVisible();
      // No duplicate: page 2's first event is strictly after the cursor.
      expect(vi.mocked(api)).toHaveBeenCalledWith('/sessions/paged/callflow?limit=100&cursor=evt-A-002');
      // Previous returns to page 1, still ordered by (capture_id, packet, event_id).
      await userEvent.click(screen.getByRole('button',{name:'Previous'}));
      expect(await screen.findByText(/1–2 of 4 observed/)).toBeVisible();
    });
  });
});
