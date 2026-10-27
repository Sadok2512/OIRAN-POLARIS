//! Dependency-free standalone HTML renderer for the canonical Call Flow model.

use callflow_schema::CallFlow;

pub const VERSION: &str = "0.1.0";

pub fn render(flow: &CallFlow) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string(flow)?;
    let safe_json = json
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    Ok(TEMPLATE.replace("__CALLFLOW_JSON__", &safe_json))
}

const TEMPLATE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OIRAN 5G E2E Call Flow</title>
<style>
:root{--navy:#10233e;--muted:#64748b;--line:#dce4ee;--blue:#1769e0;--blue2:#e9f2ff;--green:#16835b;--green2:#e9f8f1;--amber:#b46b09;--amber2:#fff7e7;--red:#c63d4f;--red2:#fff0f2;--bg:#f4f7fb;--panel:#fff;--zoom:1}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--navy);font:13px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}.topbar{height:62px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 24px;gap:20px;position:sticky;top:0;z-index:20}.brand{font-weight:800;letter-spacing:.08em;color:var(--blue)}.brand span{color:var(--navy);font-weight:650;letter-spacing:0}.session-title{font-size:14px;font-weight:700;white-space:nowrap}.meta{display:flex;gap:8px;align-items:center;margin-left:auto}.badge{padding:4px 9px;border:1px solid #cbd8e7;border-radius:999px;background:#f9fbfd;font-size:11px;font-weight:700}.badge.strong{color:var(--green);background:var(--green2);border-color:#b9e8d2}.layout{display:grid;grid-template-columns:minmax(700px,1fr) 370px;height:calc(100vh - 62px)}main{min-width:0;display:flex;flex-direction:column}.summary{display:grid;grid-template-columns:repeat(5,minmax(100px,1fr));gap:10px;padding:14px 18px 8px}.stat{background:#fff;border:1px solid var(--line);border-radius:9px;padding:10px 12px;box-shadow:0 1px 2px #10233e08}.stat b{display:block;font-size:17px}.stat span{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.08em}.toolbar{display:flex;align-items:center;gap:8px;padding:8px 18px}.toolbar input,.toolbar select{height:32px;border:1px solid #cbd7e5;border-radius:7px;background:#fff;padding:0 9px;color:var(--navy)}.toolbar input{width:220px}.toolbtn{height:32px;border:1px solid #cbd7e5;border-radius:7px;background:#fff;color:var(--navy);padding:0 10px}.toolbtn.primary{background:var(--blue);color:#fff;border-color:var(--blue)}.diagram-wrap{margin:0 18px 18px;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:auto;box-shadow:0 5px 18px #10233e0b}.diagram{min-width:780px;transform-origin:top left;font-size:calc(12px * var(--zoom))}.lifeline-head{display:grid;grid-template-columns:repeat(4,1fr);position:sticky;top:0;background:#fff;border-bottom:1px solid var(--line);z-index:6}.actor{text-align:center;padding:12px 4px;font-weight:750}.actor small{display:block;color:var(--muted);font-weight:500}.proc{border-bottom:1px solid #edf1f6}.proc summary{position:sticky;top:43px;z-index:5;background:#f8fafc;padding:7px 12px;font-weight:750;color:#3c526d;cursor:pointer}.flow-body{position:relative;background-image:linear-gradient(90deg,transparent 12.42%,#dfe7f0 12.5%,transparent 12.58%,transparent 37.42%,#dfe7f0 37.5%,transparent 37.58%,transparent 62.42%,#dfe7f0 62.5%,transparent 62.58%,transparent 87.42%,#dfe7f0 87.5%,transparent 87.58%)}.flow-row{height:58px;position:relative;border-top:1px solid #f2f5f8}.flow-row:hover{background:#f7fbff}.flow-row.selected{background:#edf5ff}.arrow{position:absolute;top:28px;height:2px;background:var(--blue);min-width:3px}.arrow:after{content:"";position:absolute;right:-1px;top:-4px;border-left:7px solid var(--blue);border-top:5px solid transparent;border-bottom:5px solid transparent}.arrow.reverse:after{left:-1px;right:auto;border-left:0;border-right:7px solid var(--blue)}.arrow.success{background:var(--green)}.arrow.success:after{border-left-color:var(--green)}.arrow.success.reverse:after{border-right-color:var(--green)}.arrow.partial{background:var(--amber)}.arrow.partial:after{border-left-color:var(--amber)}.arrow.partial.reverse:after{border-right-color:var(--amber)}.arrow.failure{background:var(--red)}.arrow.failure:after{border-left-color:var(--red)}.arrow.failure.reverse:after{border-right-color:var(--red)}.dot{position:absolute;width:8px;height:8px;border-radius:50%;background:#fff;border:2px solid currentColor;top:-3px}.label{position:absolute;top:5px;transform:translateX(-50%);background:#fff;padding:1px 7px;border:1px solid #dbe5f0;border-radius:5px;white-space:nowrap;max-width:46%;overflow:hidden;text-overflow:ellipsis;box-shadow:0 1px 2px #10233e12}.label b{font-size:11px}.label small{display:block;color:var(--muted);font-size:9px}.row-status{position:absolute;left:8px;top:19px;font-size:9px;font-weight:800;padding:2px 5px;border-radius:4px;background:var(--blue2);color:var(--blue)}.row-status.partial{background:var(--amber2);color:var(--amber)}aside{background:#fff;border-left:1px solid var(--line);overflow:auto;resize:horizontal;direction:rtl;min-width:300px;max-width:620px}.inspector{direction:ltr;padding:18px}.empty{color:var(--muted);padding:40px 10px;text-align:center}.inspect-head{display:flex;justify-content:space-between;gap:8px;align-items:start}.inspect-head h2{font-size:16px;margin:0 0 4px}.section{border-top:1px solid var(--line);padding-top:12px;margin-top:14px}.section h3{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 8px}.kv{display:grid;grid-template-columns:115px 1fr;gap:5px 8px}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}.ie{border:1px solid #e0e7ef;border-radius:6px;padding:7px;margin:5px 0;background:#fbfcfe}.ie-name{font-weight:700}.ie-value{color:#405873;word-break:break-word}.pill{font-size:9px;font-weight:800;padding:2px 6px;border-radius:999px;background:var(--blue2);color:var(--blue)}.pill.partial{background:var(--amber2);color:var(--amber)}.evidence{border-left:3px solid var(--blue);padding:6px 9px;margin:6px 0;background:#f8fbff}.hidden{display:none!important}@media(max-width:1000px){.layout{grid-template-columns:1fr}.layout aside{position:fixed;right:0;top:62px;bottom:0;width:370px;z-index:15;box-shadow:-8px 0 25px #10233e22}.summary{grid-template-columns:repeat(3,1fr)}}
</style></head><body>
<header class="topbar"><div class="brand">OIRAN <span>vProbe</span></div><div class="session-title" id="sessionTitle"></div><div class="meta"><span class="badge">5G SA</span><span class="badge strong" id="corrBadge"></span></div></header>
<div class="layout"><main><div class="summary" id="summary"></div><div class="toolbar"><input id="search" placeholder="Search messages…"><select id="iface"><option value="">All interfaces</option></select><select id="protocol"><option value="">All protocols</option></select><label><input id="background" type="checkbox"> Background</label><button class="toolbtn" id="zoomOut">−</button><button class="toolbtn" id="zoomIn">+</button><button class="toolbtn primary" id="export">Export JSON</button></div><div class="diagram-wrap"><div class="diagram" id="diagram"><div class="lifeline-head" id="actors"></div><div id="groups"></div></div></div></main><aside><div class="inspector" id="inspector"><div class="empty">Select a message to inspect decoded fields, evidence and packet provenance.</div></div></aside></div>
<script id="callflow-data" type="application/json">__CALLFLOW_JSON__</script>
<script>
(()=>{'use strict';const data=JSON.parse(document.getElementById('callflow-data').textContent);const actors=['gNB','AMF','SMF','UPF'];const pos=Object.fromEntries(actors.map((x,i)=>[x,i]));let selected=null,zoom=1;
const el=id=>document.getElementById(id), txt=(tag,value,cls)=>{const n=document.createElement(tag);n.textContent=value??'';if(cls)n.className=cls;return n};
el('sessionTitle').textContent=data.session_id;el('corrBadge').textContent=`E2E ${data.correlation_status.E2E}`;
const stats=[['Session messages',data.accounting.session_events],['Source events',data.accounting.source_events],['Interfaces',data.interfaces.length],['Correlation edges',data.correlation_edges.length],['Unresolved IEs',data.unresolved_fields]];for(const[s,v]of stats){const d=txt('div','', 'stat');d.append(txt('b',String(v)));d.append(txt('span',s));el('summary').append(d)}
for(const a of actors){const d=txt('div',a,'actor');const p=data.participants.find(x=>x.role===a);d.append(txt('small',p?p.addresses.join(' · '):'not observed'));el('actors').append(d)}
for(const i of data.interfaces){const o=txt('option',i);o.value=i;el('iface').append(o)}for(const p of [...new Set(data.events.map(x=>x.protocol))]){const o=txt('option',p);o.value=p;el('protocol').append(o)}
const evidenceFor=id=>data.correlation_edges.filter(x=>x.source_event_id===id||x.target_event_id===id);
function row(event){const r=txt('div','',`flow-row event ${event.association.toLowerCase()}`);r.dataset.id=event.event_id;r.dataset.interface=event.interface;r.dataset.protocol=event.protocol;r.dataset.name=event.message_name.toLowerCase();if(event.association!=='SESSION')r.classList.add('hidden');
let s=pos[event.source_participant],t=pos[event.destination_participant];if(s===undefined)s=0;if(t===undefined)t=3;const left=12.5+Math.min(s,t)*25,right=12.5+Math.max(s,t)*25;const a=txt('div','',`arrow ${s>t?'reverse ':''}${event.semantic_status.toLowerCase()}`);a.style.left=`${left}%`;a.style.width=`${Math.max(1,right-left)}%`;const ds=txt('span','', 'dot');ds.style.left='-3px';a.append(ds);const label=txt('button','', 'label');label.type='button';label.style.left=`${(left+right)/2}%`;label.append(txt('b',event.message_name));label.append(txt('small',`${event.timestamp.split('Z')[0]} · ${event.protocol}/${event.interface}`));label.onclick=()=>inspect(event,r);r.append(a,label);const st=txt('span',event.decoding_status,`row-status ${event.decoding_status==='DECODED'?'':'partial'}`);r.append(st);return r}
function render(){el('groups').replaceChildren();const groups=new Map;for(const e of data.events){if(!groups.has(e.procedure_group))groups.set(e.procedure_group,[]);groups.get(e.procedure_group).push(e)}for(const[name,events]of groups){const d=document.createElement('details');d.className='proc';d.open=name!=='Background / Lifecycle';d.append(txt('summary',`${name} · ${events.length}`));const b=txt('div','', 'flow-body');events.forEach(e=>b.append(row(e)));d.append(b);el('groups').append(d)}applyFilters()}
function inspect(e,rowEl){document.querySelectorAll('.selected').forEach(x=>x.classList.remove('selected'));rowEl.classList.add('selected');selected=e.event_id;const p=el('inspector');p.replaceChildren();const h=txt('div','', 'inspect-head');const title=txt('div');title.append(txt('h2',e.message_name),txt('span',`${e.protocol} · ${e.interface}`,`pill ${e.decoding_status==='DECODED'?'':'partial'}`));h.append(title,txt('span',e.decoding_status,`pill ${e.decoding_status==='DECODED'?'':'partial'}`));p.append(h);
const overview=section('Overview');const dl=txt('dl','', 'kv');for(const[k,v]of [['Timestamp',e.timestamp],['Path',`${e.source_participant} → ${e.destination_participant}`],['Direction',e.direction],['Association',e.association],['Decoder',`${e.decoder_name} ${e.decoder_version}`]]){dl.append(txt('dt',k),txt('dd',v))}overview.append(dl);p.append(overview);
const ies=section('Information Elements');if(!e.decoded_ie_tree.length)ies.append(txt('div','No decoded IEs','empty'));for(const ie of e.decoded_ie_tree){const d=txt('div','', 'ie');d.append(txt('div',ie.name,'ie-name'));d.append(txt('div',ie.value??`raw sha256: ${ie.raw_sha256??'unavailable'}`,'ie-value'));d.append(txt('span',ie.status,`pill ${ie.status==='DECODED'?'':'partial'}`));ies.append(d)}p.append(ies);
const raw=section('Raw Payload Reference');raw.append(txt('div',e.raw_payload_reference,'ie-value'));p.append(raw);const ev=section('Correlation Evidence');const edges=evidenceFor(e.event_id);if(!edges.length)ev.append(txt('div','No cross-interface edge for this event','empty'));for(const x of edges){const d=txt('div','', 'evidence');d.append(txt('b',`${x.confidence} · ${x.rule_id}`),txt('div',x.evidence_description),txt('small',x.matching_identifiers.join(' · ')));ev.append(d)}p.append(ev);
const prov=section('Packet Provenance');for(const x of e.packet_references){const d=txt('div','', 'ie');d.append(txt('b',`Packet ${x.packet_number}`),txt('div',x.source_file,'ie-value'),txt('small',`offset ${x.byte_offset} · captured ${x.captured_length}/${x.original_length}`));prov.append(d)}p.append(prov)}
function section(name){const s=txt('section','', 'section');s.append(txt('h3',name));return s}
function applyFilters(){const q=el('search').value.toLowerCase(),i=el('iface').value,p=el('protocol').value,bg=el('background').checked;document.querySelectorAll('.event').forEach(r=>{const e=data.events.find(x=>x.event_id===r.dataset.id);const ok=(!q||r.dataset.name.includes(q))&&(!i||r.dataset.interface===i)&&(!p||r.dataset.protocol===p)&&(bg||e.association==='SESSION');r.classList.toggle('hidden',!ok)})}
['search','iface','protocol','background'].forEach(id=>el(id).addEventListener('input',applyFilters));el('zoomIn').onclick=()=>{zoom=Math.min(1.5,zoom+.1);document.documentElement.style.setProperty('--zoom',zoom)};el('zoomOut').onclick=()=>{zoom=Math.max(.7,zoom-.1);document.documentElement.style.setProperty('--zoom',zoom)};el('export').onclick=()=>{const b=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='OIRAN_5G_E2E_CALLFLOW.json';a.click();URL.revokeObjectURL(a.href)};render();})();
</script></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use callflow_schema::{CallFlow, EventAccounting};
    use std::collections::BTreeMap;

    fn flow(id: &str) -> CallFlow {
        CallFlow {
            callflow_id: id.into(),
            session_id: id.into(),
            technology: "5G SA".into(),
            start_timestamp: "".into(),
            end_timestamp: "".into(),
            participants: vec![],
            interfaces: vec![],
            procedures: vec![],
            events: vec![],
            correlation_edges: vec![],
            correlation_status: BTreeMap::new(),
            decoder_versions: BTreeMap::new(),
            schema_version: "1".into(),
            capture_references: vec![],
            accounting: EventAccounting {
                source_events: 0,
                session_events: 0,
                background_events: 0,
                unmatched_events: 0,
                duplicate_events: 0,
                extra_events: 0,
            },
            unresolved_fields: 0,
        }
    }
    #[test]
    fn dangerous_strings_cannot_close_json_script() {
        let html = render(&flow("</script><script>alert(1)</script>")).unwrap();
        assert!(!html.contains("</script><script>alert(1)"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }
    #[test]
    fn standalone_has_no_remote_dependencies() {
        let html = render(&flow("safe")).unwrap();
        assert!(!html.contains("https://"));
        assert!(html.contains("Export JSON"));
        assert!(html.contains("Correlation Evidence"));
    }
}
