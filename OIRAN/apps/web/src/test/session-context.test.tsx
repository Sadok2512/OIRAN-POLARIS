import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionExplorer } from '../pages/SessionExplorer';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn() }));

const dataset = { dataset_id:'dataset-zero', display_name:'dataset-zero', dataset_kind:'RECOVERED', source:'OFFLINE_RECOVERY', technology:'5G SA', ingestion_status:'COMPLETED', ingestion_generation:1, session_count:0, ue_context_count:0, event_count:20, background_event_count:20, unmatched_event_count:0, duplicate_observation_count:0, error_count:0, read_only:true, capture_id:'cap-zero', captures:[], decoder_versions:{} };
const renderExplorer=(url:string)=>{const client=new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[url]}><Routes><Route path="/investigation/sessions" element={<SessionExplorer/>}/><Route path="/investigation/sessions/:sessionId" element={<SessionExplorer/>}/></Routes></MemoryRouter></QueryClientProvider>)};

describe('capture dataset session context',()=>{
  beforeEach(()=>vi.mocked(api).mockImplementation(async(path?:string)=>{
    if(path===undefined)return {data:[],meta:{}} as never;
    if(path==='/datasets?page_size=100')return {data:[dataset],meta:{}} as never;
    if(path==='/ues?page_size=100')return {data:[],meta:{}} as never;
    if(path==='/captures/cap-zero/context')return {data:{capture:{capture_id:'cap-zero',name:'cap',dataset_id:'dataset-zero',dataset_kind:'RECOVERED'},dataset,resolution:'NO_RECONSTRUCTED_SESSIONS',session_ids:[],reason:'no session evidence'},meta:{}} as never;
    if(path.includes('/sessions?')&&path.includes('dataset_id=dataset-zero'))return {data:[],meta:{page:1,total_pages:0,total:0}} as never;
    throw new Error(`unexpected path ${path}`);
  }));

  it('shows the exact zero-session state without historical fallback',async()=>{
    renderExplorer('/investigation/sessions?capture_id=cap-zero&dataset_id=dataset-zero&probe_id=probe-a');
    expect(await screen.findByText('No reconstructed sessions in this capture.')).toBeVisible();
    expect(screen.getByRole('link',{name:'View Packets'})).toHaveAttribute('href',expect.stringContaining('capture_id=cap-zero'));
    expect(vi.mocked(api)).not.toHaveBeenCalledWith(expect.stringMatching(/^\/sessions\?page=1&page_size=25&sort=start_timestamp&order=asc$/));
  });

  it('shows dataset unavailable and never requests unrelated sessions',async()=>{
    vi.mocked(api).mockImplementation(async(path?:string)=>{
      if(path===undefined)return {data:[],meta:{}} as never;
      if(path==='/datasets?page_size=100'||path==='/ues?page_size=100')return {data:[],meta:{}} as never;
      if(path==='/captures/cap-failed/context')return {data:{capture:{capture_id:'cap-failed',name:'failed',state:'FAILED',error:'decoder failed'},dataset:null,resolution:'DATASET_UNAVAILABLE',session_ids:[],reason:'missing'},meta:{}} as never;
      throw new Error(`unexpected path ${path}`);
    });
    renderExplorer('/investigation/sessions?capture_id=cap-failed');
    expect(await screen.findByText('Dataset unavailable for this capture.')).toBeVisible();
    expect(screen.getByText('decoder failed')).toBeVisible();
    expect(vi.mocked(api).mock.calls.some(([path])=>String(path).startsWith('/sessions?'))).toBe(false);
  });

  it('keeps dataset categories explicit and queries the selected scope',async()=>{
    vi.mocked(api).mockImplementation(async(path?:string)=>{
      if(path===undefined)return {data:[],meta:{}} as never;
      if(path==='/datasets?page_size=100')return {data:[
        {...dataset,dataset_id:'historical-a',display_name:'Historical A',dataset_kind:'HISTORICAL'},
        {...dataset,dataset_id:'live-a',display_name:'Live A',dataset_kind:'CAPTURED_LIVE'},
        dataset,
      ],meta:{}} as never;
      if(path==='/ues?page_size=100')return {data:[],meta:{}} as never;
      if(path?.includes('/sessions?')&&path.includes('dataset_kind=CAPTURED_LIVE'))return {data:[],meta:{page:1,total_pages:0,total:0}} as never;
      if(path?.includes('/sessions?')&&path.includes('dataset_kind=RECOVERED'))return {data:[],meta:{page:1,total_pages:0,total:0}} as never;
      throw new Error(`unexpected path ${path}`);
    });
    renderExplorer('/investigation/sessions?dataset_scope=CAPTURED_LIVE');
    const selector=await screen.findByLabelText('Dataset filter');
    expect(selector).toHaveValue('scope:CAPTURED_LIVE');
    expect(screen.getByRole('option',{name:'Historical datasets'})).toBeVisible();
    expect(screen.getByRole('option',{name:'Live captures'})).toBeVisible();
    expect(screen.getByRole('option',{name:'Recovered datasets'})).toBeVisible();
    await userEvent.selectOptions(selector,'scope:RECOVERED');
    expect(await screen.findByText('ALL RECOVERED')).toBeVisible();
    expect(vi.mocked(api).mock.calls.some(([path])=>String(path).includes('dataset_kind=RECOVERED'))).toBe(true);
  });
});
