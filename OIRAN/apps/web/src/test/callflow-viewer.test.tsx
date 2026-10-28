import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CallFlowViewer } from '../pages/CallFlowViewer';
import { api } from '../services/api';

vi.mock('../services/api',()=>({api:vi.fn(),downloadExport:vi.fn()}));

const packet={source_file:'capture://N2.pcapng',packet_number:7,byte_offset:128,interface_id:0,captured_length:96,original_length:96};
const event=(event_id:string,protocol:string,iface:string,source:string,destination:string,message_name:string,procedure_group:string)=>({event_id,timestamp:'1792872460.866283311Z',timestamp_ns:'1792872460866283311',interface:iface,protocol,message_name,source_participant:source,destination_participant:destination,direction:`${source}_TO_${destination}`,decoded_ie_tree:[{id:85,name:'RAN UE NGAP ID',length:4,value:'42',raw_sha256:null,status:'DECODED'}],decoding_status:'DECODED',semantic_status:'NORMAL',association:'SESSION',procedure_group,packet_references:[packet],capture_id:'cap-certified',decoder_name:`decoder-${protocol.toLowerCase()}`,decoder_version:'1.0.0',raw_payload_reference:'sha256:payload',errors:[]});
const events=[event('ng-up','NGAP','N2','gNB','AMF','InitialUEMessage','UE Registration'),event('ng-down','NGAP','N2','AMF','gNB','DownlinkNASTransport','UE Registration'),event('pfcp','PFCP','N4','SMF','UPF','PFCP Session Establishment Request','PFCP Session'),event('gtpu','GTP-U','N3','gNB','UPF','G-PDU','User Plane'),event('unknown','NGAP','N2','UNKNOWN','AMF','Unresolved NGAP','UE Registration')];
const flow={callflow_id:'cf-s1',session_id:'s1',technology:'5G SA',start_timestamp:events[0].timestamp,end_timestamp:events[0].timestamp,participants:[{id:'gnb',role:'gNB',addresses:['10.0.0.1']},{id:'amf',role:'AMF',addresses:['10.0.0.2']},{id:'smf',role:'SMF',addresses:['10.0.0.3']},{id:'upf',role:'UPF',addresses:['10.0.0.4']}],interfaces:['N2','N4','N3'],procedures:[{id:'registration',name:'UE Registration',event_ids:['ng-up','ng-down','unknown'],status:'OBSERVED'},{id:'pfcp',name:'PFCP Session',event_ids:['pfcp'],status:'OBSERVED'},{id:'user-plane',name:'User Plane',event_ids:['gtpu'],status:'OBSERVED'}],events,correlation_edges:[{edge_id:'tunnel',source_event_id:'ng-up',target_event_id:'pfcp',source_interface:'N2',target_interface:'N4',matching_identifiers:['endpoint_ip=10.77.22.13','teid=0xb3b5'],rule_id:'ngap-pfcp-exact-tunnel',rule_version:'2.0.0',evidence_description:'Unique tunnel tuple',packet_references:[packet],confidence:'EXACT',evidence_type:'EXACT_TUNNEL_MATCH',scope:'tunnel-only',limitations:['Does not prove UE identity']}],correlation_status:{N2_N4:'EXACT',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},decoder_versions:{},schema_version:'1.0.0',capture_references:['cap-certified'],accounting:{source_events:5,session_events:5,background_events:0,unmatched_events:0,duplicate_events:0,extra_events:0},unresolved_fields:0};
const summary={session_id:'s1',dataset_id:'dataset-a',ue_context_id:'ue-a',technology:'5G SA',ue_pseudonym:'UE-A',pdu_session_id:'1',serving_node:'gNB 10.0.0.1',procedure:'Registration',start_timestamp:events[0].timestamp,end_timestamp:events[0].timestamp,duration_ns:'0',interfaces:['N2','N4','N3'],message_count:5,source_event_count:5,background_event_count:0,correlation_status:'STRONG',decode_completeness:{decoded:5,partial:0,unresolved_fields:0},state:'ACTIVE_WITH_USER_PLANE'};

describe('directional Call Flow viewer',()=>{
  beforeEach(()=>vi.mocked(api).mockImplementation(async(path?:string)=>{
    if(path===undefined)return {data:[],meta:{}} as never;
    if(path==='/sessions/s1')return {data:{summary},meta:{}} as never;
    if(path==='/sessions/s1/callflow')return {data:flow,meta:{}} as never;
    throw new Error(`unexpected path ${path}`);
  }));
  const renderFlow=()=>{const client=new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/investigation/callflow/s1?dataset_id=dataset-a&capture_id=cap-certified&probe_id=probe-a']}><Routes><Route path="/investigation/callflow/:sessionId" element={<CallFlowViewer/>}/></Routes></MemoryRouter></QueryClientProvider>)};

  it('renders evidence-backed directions, dynamic participants and data flow',async()=>{
    renderFlow();
    expect(await screen.findByLabelText('InitialUEMessage, NGAP, gNB to AMF')).toBeVisible();
    expect(screen.getByLabelText('DownlinkNASTransport, NGAP, AMF to gNB')).toBeVisible();
    expect(screen.getByLabelText('PFCP Session Establishment Request, PFCP, SMF to UPF')).toBeVisible();
    expect(screen.getByText('DATA · G-PDU')).toBeVisible();
    expect(screen.getAllByText('gNB').length).toBeGreaterThan(0);
    expect(screen.queryByText('MME')).not.toBeInTheDocument();
    expect(screen.getByText(/DIRECTION UNRESOLVED/)).toBeVisible();
  });

  it('synchronizes arrow and message-row selection with the inspector',async()=>{
    renderFlow();
    const arrow=await screen.findByLabelText('InitialUEMessage, NGAP, gNB to AMF');
    await userEvent.click(arrow);
    expect(screen.getByRole('heading',{name:'InitialUEMessage'})).toBeVisible();
    expect(arrow).toHaveClass('selected');
    await userEvent.click(screen.getAllByRole('button',{name:/DownlinkNASTransport/})[1]);
    expect(screen.getByRole('heading',{name:'DownlinkNASTransport'})).toBeVisible();
    expect(screen.getAllByText('2026-10-24 20:07:40.866 UTC')[0]).toBeVisible();
  });

  it('exposes decoded fields and exact packet provenance without fake raw bytes',async()=>{
    renderFlow();
    await userEvent.click(await screen.findByLabelText('InitialUEMessage, NGAP, gNB to AMF'));
    await userEvent.click(screen.getByRole('tab',{name:/Decoded Fields/}));
    expect(screen.getAllByText('RAN UE NGAP ID')[0]).toBeVisible();
    await userEvent.click(screen.getByRole('tab',{name:'Raw Hex'}));
    expect(screen.getByText('Raw bytes not available in this event model')).toBeVisible();
    await userEvent.click(screen.getByRole('tab',{name:'Provenance'}));
    expect(screen.getByText('probe-a')).toBeVisible();
    expect(screen.getByRole('link',{name:'Open exact packet'})).toHaveAttribute('href',expect.stringContaining('packet_number=7'));
  });

  it('separates exact tunnel evidence from complete session identity',async()=>{
    renderFlow();
    await userEvent.click(await screen.findByLabelText('InitialUEMessage, NGAP, gNB to AMF'));
    await userEvent.click(screen.getByRole('tab',{name:/Correlation Evidence/}));
    expect(screen.getByText(/EXACT_TUNNEL_MATCH/)).toBeVisible();
    expect(screen.getByText('Scope: tunnel-only')).toBeVisible();
    expect(screen.getByText(/Does not prove UE identity/)).toBeVisible();
    expect(screen.getAllByText('E2E UNKNOWN').length).toBeGreaterThan(0);
  });

  it('keeps Download frame and PCAP slice locked (LOT 3 — route not served yet)',async()=>{
    renderFlow();
    const frame=await screen.findByTestId('callflow-download-frame');
    const slice=screen.getByTestId('callflow-pcap-slice');
    expect(frame).toBeDisabled();
    expect(slice).toBeDisabled();
    expect(frame.getAttribute('title')).toMatch(/\/captures\/:id\/download.*404/);
    expect(slice.getAttribute('title')).toMatch(/\/captures\/:id\/download.*404/);
  });
});

// Identity IEs are filtered BEFORE the inspector renders. We use a dedicated
// fixture where one of the IEs is an IMSI; the banner must appear and the
// tree must not contain the identity node.
describe('Call Flow viewer — identity IEs withheld (LOT 3)',()=>{
  const identityPacket={source_file:'capture://N2.pcapng',packet_number:7,byte_offset:128,interface_id:0,captured_length:96,original_length:96};
  const identityEvent={
    event_id:'ngap-with-imsi',timestamp:'1792872460.866283311Z',timestamp_ns:'1792872460866283311',
    interface:'N2',protocol:'NGAP',message_name:'IdentityResponse',
    source_participant:'gNB',destination_participant:'AMF',direction:'gNB_TO_AMF',
    decoded_ie_tree:[
      {id:85,name:'RAN UE NGAP ID',length:4,value:'42',raw_sha256:null,status:'DECODED'},
      {id:200,name:'IMSI',length:9,value:'208990000000001',raw_sha256:null,status:'DECODED'},
      {id:201,name:'5G-GUTI',length:11,value:'guti-raw',raw_sha256:null,status:'DECODED',children:[{id:202,name:'mcc',length:2,value:'208',raw_sha256:null,status:'DECODED'}]},
    ],
    decoding_status:'DECODED',semantic_status:'NORMAL',association:'SESSION',procedure_group:'UE Registration',
    packet_references:[identityPacket],capture_id:'cap-certified',decoder_name:'decoder-ngap',decoder_version:'1.0.0',
    raw_payload_reference:'sha256:payload',errors:[],
  };
  const identityFlow={
    callflow_id:'cf-identity',session_id:'identity',technology:'5G SA',
    start_timestamp:identityEvent.timestamp,end_timestamp:identityEvent.timestamp,
    participants:[{id:'gnb',role:'gNB',addresses:['10.0.0.1']},{id:'amf',role:'AMF',addresses:['10.0.0.2']}],
    interfaces:['N2'],procedures:[{id:'reg',name:'UE Registration',event_ids:['ngap-with-imsi'],status:'OBSERVED'}],
    events:[identityEvent],correlation_edges:[],correlation_status:{N2_N4:'UNKNOWN',N4_N3:'UNKNOWN',E2E:'UNKNOWN'},
    decoder_versions:{},schema_version:'1.0.0',capture_references:['cap-certified'],
    accounting:{source_events:1,session_events:1,background_events:0,unmatched_events:0,duplicate_events:0,extra_events:0},
    unresolved_fields:0,
  };
  const identitySummary={session_id:'identity',dataset_id:'dataset-a',ue_context_id:'ue-a',technology:'5G SA',ue_pseudonym:'UE-A',pdu_session_id:'1',serving_node:'gNB 10.0.0.1',procedure:'Registration',start_timestamp:identityEvent.timestamp,end_timestamp:identityEvent.timestamp,duration_ns:'0',interfaces:['N2'],message_count:1,source_event_count:1,background_event_count:0,correlation_status:'STRONG',decode_completeness:{decoded:1,partial:0,unresolved_fields:0},state:'ACTIVE_WITH_USER_PLANE'};

  beforeEach(()=>vi.mocked(api).mockImplementation(async(path?:string)=>{
    if(path===undefined)return {data:[],meta:{}} as never;
    if(path==='/sessions/identity')return {data:{summary:identitySummary},meta:{}} as never;
    if(path==='/sessions/identity/callflow')return {data:identityFlow,meta:{}} as never;
    throw new Error(`unexpected path ${path}`);
  }));

  const render1=()=>{const client=new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/investigation/callflow/identity?dataset_id=dataset-a&capture_id=cap-certified&probe_id=probe-a']}><Routes><Route path="/investigation/callflow/:sessionId" element={<CallFlowViewer/>}/></Routes></MemoryRouter></QueryClientProvider>)};

  it('shows the "N identity IEs withheld" banner and does not render the identity node',async()=>{
    render1();
    await userEvent.click(await screen.findByLabelText('IdentityResponse, NGAP, gNB to AMF'));
    await userEvent.click(screen.getByRole('tab',{name:/Decoded Fields/}));
    // IMSI (1) + 5G-GUTI parent (1) + its mcc child (1) = 3 identity IEs.
    // The banner may render in several tab panels — any of them is fine.
    const banners=screen.getAllByTestId('identity-withheld-banner');
    expect(banners.length).toBeGreaterThan(0);
    expect(banners[0].textContent).toMatch(/3 identity IEs withheld/);
    // Non-identity IE still shows up; identity IEs are filtered out.
    expect(screen.getAllByText('RAN UE NGAP ID')[0]).toBeVisible();
    expect(screen.queryByText('IMSI')).toBeNull();
    expect(screen.queryByText('5G-GUTI')).toBeNull();
  });

  it('mentions the withholding on the Raw Hex tab, and no raw bytes are ever shown',async()=>{
    render1();
    await userEvent.click(await screen.findByLabelText('IdentityResponse, NGAP, gNB to AMF'));
    await userEvent.click(screen.getByRole('tab',{name:'Raw Hex'}));
    expect(screen.getByText('Raw bytes not available in this event model')).toBeVisible();
    expect(screen.getByText(/Identity IEs are withheld; this message is shown without hex/)).toBeVisible();
  });
});
