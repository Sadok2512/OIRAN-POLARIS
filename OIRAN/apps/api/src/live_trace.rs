//! Bounded live-trace registry and SSE transport.
//!
//! Clear lookup values are used only to resolve the root-only identity vault.
//! They are deliberately absent from records, audit entries and errors.

use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

const MAX_TRACES: usize = 10;
const MAX_EVENTS: usize = 2_000;

#[derive(Clone, Serialize)]
pub(crate) struct LiveTrace {
    trace_id: String,
    key_type: String,
    subscriber_pseudonyms: Vec<String>,
    interfaces: Vec<String>,
    created_at: u64,
    expires_at: u64,
    armed: bool,
    messages: u64,
    markers: u64,
}

#[derive(Clone)]
struct BufferedEvent {
    id: u64,
    kind: String,
    payload: Value,
}
struct TraceState {
    trace: LiveTrace,
    next_id: u64,
    events: VecDeque<BufferedEvent>,
    tx: broadcast::Sender<BufferedEvent>,
    keys: HashSet<String>,
    throughput_second: u64,
    ul_bytes: u64,
    dl_bytes: u64,
}
pub(crate) struct LiveTraceRegistry {
    traces: Mutex<HashMap<String, TraceState>>,
    reader_running: AtomicBool,
    audit: Mutex<VecDeque<Value>>,
}

impl LiveTraceRegistry {
    pub(crate) fn new() -> Self {
        Self {
            traces: Mutex::new(HashMap::new()),
            reader_running: AtomicBool::new(false),
            audit: Mutex::new(VecDeque::new()),
        }
    }
    fn audit(&self, entry: Value) { let mut audit=self.audit.lock().unwrap(); audit.push_front(entry); while audit.len()>500 { audit.pop_back(); } }
    fn purge(map: &mut HashMap<String, TraceState>) {
        let now = epoch_seconds();
        map.retain(|_, state| state.trace.expires_at > now);
    }
    #[cfg(test)]
    pub(crate) fn append(&self, trace_id: &str, kind: &str, payload: Value) -> bool {
        let mut traces = self.traces.lock().unwrap();
        let Some(state) = traces.get_mut(trace_id) else {
            return false;
        };
        state.next_id += 1;
        let item = BufferedEvent {
            id: state.next_id,
            kind: kind.into(),
            payload,
        };
        state.events.push_back(item.clone());
        while state.events.len() > MAX_EVENTS {
            state.events.pop_front();
        }
        if kind == "message" {
            state.trace.messages += 1;
        }
        if kind == "marker" {
            state.trace.markers += 1;
        }
        let _ = state.tx.send(item);
        true
    }

    fn route_normalized(&self, event: &event_schema::NormalizedEvent) {
        let value = serde_json::from_str(&event.to_json()).unwrap_or(Value::Null);
        let encoded = value.to_string();
        let mut traces = self.traces.lock().unwrap();
        Self::purge(&mut traces);
        for state in traces.values_mut() {
            if !state.trace.interfaces.is_empty() && !state.trace.interfaces.iter().any(|item|item.eq_ignore_ascii_case(&event.interface)) { continue; }
            let matched = state
                .trace
                .subscriber_pseudonyms
                .iter()
                .any(|key| encoded.contains(key))
                || state.keys.iter().any(|key| encoded.contains(key));
            if !matched {
                continue;
            }
            state.trace.armed = false;
            if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
                for id in ids {
                    if let Some(v) = id.get("value").and_then(Value::as_str) {
                    if v.len() >= 3 && v.parse::<std::net::IpAddr>().is_err() {
                            state.keys.insert(v.to_owned());
                        }
                    }
                }
            }
            if matches!(
                event.message_name.as_str(),
                "UE Context Release Complete"
                    | "PDU Session Release Complete"
                    | "Delete Session Response"
                    | "Detach Accept"
            ) {
                state.keys.clear();
            }
            state.next_id += 1;
            state.trace.messages += 1;
            let packet = event
                .packet_references
                .first()
                .map(|p| p.packet_number)
                .unwrap_or(0);
            let payload = json!({"interface":event.interface,"protocol":event.protocol.as_str(),"message_name":event.message_name,"direction":event.direction.as_str(),"source":value.get("source_endpoint"),"destination":value.get("destination_endpoint"),"capture_id":event.capture_id,"packet_number":packet,"event_id":event.event_id,"decoded_ie_tree":value.get("information_elements")});
            let item = BufferedEvent {
                id: state.next_id,
                kind: "message".into(),
                payload,
            };
            state.events.push_back(item.clone());
            while state.events.len() > MAX_EVENTS {
                state.events.pop_front();
            }
            let _ = state.tx.send(item);
            let second=event.timestamp.seconds.max(0) as u64;
            if event.protocol.as_str()=="GTP-U" { if state.throughput_second!=0 && state.throughput_second!=second { state.next_id+=1; let rate=BufferedEvent{id:state.next_id,kind:"throughput".into(),payload:json!({"second":state.throughput_second,"ul_bytes_s":state.ul_bytes,"dl_bytes_s":state.dl_bytes})}; state.events.push_back(rate.clone());let _=state.tx.send(rate);state.ul_bytes=0;state.dl_bytes=0;} state.throughput_second=second; let bytes=event.packet_references.first().map(|p|u64::from(p.original_length)).unwrap_or(0); if event.direction.as_str()=="UPLINK"{state.ul_bytes+=bytes}else if event.direction.as_str()=="DOWNLINK"{state.dl_bytes+=bytes} }
            if let Some(procedure)=event.procedure.as_deref(){state.next_id+=1;let update=BufferedEvent{id:state.next_id,kind:"procedure".into(),payload:json!({"procedure":procedure,"phase":"update","event_id":event.event_id})};state.events.push_back(update.clone());let _=state.tx.send(update);}
            state.next_id+=1;let info=BufferedEvent{id:state.next_id,kind:"ue_info".into(),payload:json!({"technology":if event.interface.starts_with('S'){"LTE"}else{"5G"},"keys":state.keys})};state.events.push_back(info.clone());let _=state.tx.send(info);
            while state.events.len()>MAX_EVENTS{state.events.pop_front();}
        }
    }
}

fn start_reader(state: AppState) {
    if state
        .inner
        .live_traces
        .reader_running
        .swap(true, Ordering::SeqCst)
    {
        return;
    }
    tokio::spawn(async move {
        let mut seen = HashSet::new();
        loop {
            {
                let mut traces = state.inner.live_traces.traces.lock().unwrap();
                LiveTraceRegistry::purge(&mut traces);
                if traces.is_empty() {
                    state
                        .inner
                        .live_traces
                        .reader_running
                        .store(false, Ordering::SeqCst);
                    break;
                }
            }
            let source =
                std::env::var_os("OIRAN_CONTINUOUS_IMPORT_SOURCE").map(std::path::PathBuf::from);
            if let Some(root) =
                source.filter(|p| p.starts_with("/var/lib/docker/volumes/oiran_lab_pcap/_data"))
            {
                let state2 = state.clone();
                let mut prior = seen;
                seen = tokio::task::spawn_blocking(move || {
                    let key = match event_schema::PseudonymKey::load_or_generate(
                        &event_schema::PseudonymKey::resolve_default_path(),
                    ) {
                        Ok(k) => k,
                        Err(_) => return prior,
                    };
                    for interface in [
                        "N2", "N4", "N3", "SBI", "S1-MME", "S11", "S5-C", "S5-U", "S1-U", "Sxab",
                        "S6a", "IMS",
                    ] {
                        let directory=match interface {"S1-MME"=>"s1mme","S1-U"=>"s1u","S5-C"=>"s5c","S5-U"=>"s5u",other=>other};
                        let dir = root.join(directory.to_ascii_lowercase());
                        let Ok(entries) = fs::read_dir(dir) else {
                            continue;
                        };
                        let Some(path)=entries.flatten().map(|entry|entry.path()).filter(|path|path.extension().and_then(|v|v.to_str())==Some("pcapng")).max_by_key(|path|path.metadata().and_then(|m|m.modified()).ok()) else{continue};
                        let capture_id = format!("sha256:{}",sha256_hex(path.to_string_lossy().as_bytes()));
                            let config = oiran_decode::DecodeConfig {
                                input: path,
                                capture_id,
                                interface: interface.into(),
                                endpoints: HashMap::new(),
                            };
                            let _ =
                                oiran_decode::decode_capture_streaming(&config, &key, |event| {
                                    if prior.insert(event.event_id.clone()) {
                                        state2.inner.live_traces.route_normalized(&event);
                                    }
                                    Ok(())
                                });
                        if prior.len()>200_000 { prior.clear(); }
                    }
                    prior
                })
                .await
                .unwrap_or_default();
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    });
}

#[derive(Deserialize)]
pub(crate) struct CreateTrace {
    key_type: String,
    value: String,
    duration_s: u64,
    #[serde(default)]
    interfaces: Vec<String>,
}
#[derive(Deserialize)]
pub(crate) struct Marker {
    label: String,
}

fn allowed_key(value: &str) -> bool {
    matches!(
        value,
        "imsi" | "tmsi" | "s_tmsi" | "m_tmsi" | "imei" | "msisdn" | "pseudonym"
    )
}
fn live_ok(data: Value) -> Response {
    Json(json!({"data":data,"meta":{"api_version":API_VERSION}})).into_response()
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateTrace>,
) -> Response {
    let role = role_from_headers(&state, &headers);
    if !allowed_key(&input.key_type)
        || input.value.trim().is_empty()
        || input.duration_s == 0
        || input.duration_s > 3600
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "LIVE_TRACE_INVALID",
            "invalid trace request",
        );
    }
    if input.key_type != "pseudonym" && !role.can_control() {
        return api_error(
            StatusCode::FORBIDDEN,
            "OPERATOR_REQUIRED",
            "operator role required for clear identity lookup",
        );
    }
    if require_csrf(&state, &headers).is_err() {
        return require_csrf(&state, &headers).unwrap_err();
    }
    let mut armed = false;
    let pseudonyms = if input.key_type == "pseudonym" {
        vec![input.value.trim().to_owned()]
    } else {
        match state
            .inner
            .identity_vault
            .pseudonyms_for_value(input.value.trim())
        {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                armed = true;
                match event_schema::PseudonymKey::load_or_generate(
                    &event_schema::PseudonymKey::resolve_default_path(),
                ) {
                    Ok(key) => vec![pseudonym_subscriber_text(
                        &key,
                        input.value.trim().as_bytes(),
                    )],
                    Err(_) => {
                        return api_error(
                            StatusCode::NOT_IMPLEMENTED,
                            "PSEUDONYM_KEY_UNAVAILABLE",
                            "identity trace cannot be armed",
                        )
                    }
                }
            }
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "IDENTITY_VAULT_FAILED",
                    "identity lookup failed",
                )
            }
        }
    };
    let now = epoch_seconds();
    let digest = sha256_hex(format!("{}:{}:{}", now, input.key_type, input.value).as_bytes());
    let trace_id = format!("trace-{}", &digest[..16]);
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    LiveTraceRegistry::purge(&mut traces);
    if traces.len() >= MAX_TRACES {
        return api_error(
            StatusCode::CONFLICT,
            "LIVE_TRACE_LIMIT",
            "maximum active traces reached",
        );
    }
    let (tx, _) = broadcast::channel(MAX_EVENTS);
    let trace = LiveTrace {
        trace_id: trace_id.clone(),
        key_type: input.key_type,
        subscriber_pseudonyms: pseudonyms.clone(),
        interfaces: input.interfaces,
        created_at: now,
        expires_at: now + input.duration_s,
        armed,
        messages: 0,
        markers: 0,
    };
    traces.insert(
        trace_id.clone(),
        TraceState {
            trace: trace.clone(),
            next_id: 0,
            events: VecDeque::new(),
            tx,
            keys: HashSet::new(), throughput_second:0, ul_bytes:0, dl_bytes:0,
        },
    );
    drop(traces);
    state.inner.live_traces.audit(json!({"action":"live_trace.create","actor_role":role.name(),"key_type":trace.key_type,"duration_s":input.duration_s,"at_epoch_s":now}));
    start_reader(state);
    live_ok(serde_json::to_value(trace).unwrap())
}

fn require_csrf(state: &AppState, headers: &HeaderMap) -> Result<Role, Response> {
    let role = role_from_headers(state, headers);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(bearer) = bearer else {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "valid CSRF proof required",
        ));
    };
    let expected = sha256_hex(format!("oiran-csrf-v1:{bearer}").as_bytes());
    if headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "valid CSRF proof required",
        ));
    }
    Ok(role)
}

pub(crate) async fn list(State(state): State<AppState>) -> Response {
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    LiveTraceRegistry::purge(&mut traces);
    live_ok(json!(traces.values().map(|s| &s.trace).collect::<Vec<_>>()))
}
pub(crate) async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let role=match require_csrf(&state,&headers){Ok(role)=>role,Err(e)=>return e};
    let removed = state
        .inner
        .live_traces
        .traces
        .lock()
        .unwrap()
        .remove(&id);
    let Some(removed)=removed else {
        return api_error(
            StatusCode::NOT_FOUND,
            "LIVE_TRACE_NOT_FOUND",
            "trace not found",
        );
    };
    state.inner.live_traces.audit(json!({"action":"live_trace.delete","actor_role":role.name(),"key_type":removed.trace.key_type,"at_epoch_s":epoch_seconds()}));
    live_ok(json!({"trace_id":id,"deleted":true}))
}

pub(crate) async fn audit(State(state):State<AppState>,headers:HeaderMap)->Response { if let Err(e)=require_operator(&state,&headers){return e}; live_ok(json!(state.inner.live_traces.audit.lock().unwrap().iter().cloned().collect::<Vec<_>>())) }
pub(crate) async fn marker(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(marker): Json<Marker>,
) -> Response {
    if let Err(e) = require_csrf(&state, &headers) {
        return e;
    };
    if marker.label.trim().is_empty() || marker.label.len() > 120 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "MARKER_INVALID",
            "marker label is invalid",
        );
    };
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    let Some(s) = traces.get_mut(&id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "LIVE_TRACE_NOT_FOUND",
            "trace not found",
        );
    };
    s.next_id += 1;
    s.trace.markers += 1;
    let item = BufferedEvent {
        id: s.next_id,
        kind: "marker".into(),
        payload: json!({"label":marker.label,"created_at":epoch_seconds()}),
    };
    s.events.push_back(item.clone());
    let _ = s.tx.send(item.clone());
    live_ok(json!({"event_id":item.id}))
}

pub(crate) async fn stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let role=role_from_headers(&state,&headers);
    let after = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let (replay, rx) = {
        let traces = state.inner.live_traces.traces.lock().unwrap();
        let Some(s) = traces.get(&id) else {
            return api_error(
                StatusCode::NOT_FOUND,
                "LIVE_TRACE_NOT_FOUND",
                "trace not found",
            );
        };
        if s.trace.key_type != "pseudonym" && !role.can_control() { return api_error(StatusCode::FORBIDDEN,"OPERATOR_REQUIRED","operator role required for identity trace"); }
        (
            s.events
                .iter()
                .filter(|e| e.id > after)
                .cloned()
                .collect::<VecDeque<_>>(),
            s.tx.subscribe(),
        )
    };
    let replay = tokio_stream::iter(replay.into_iter().map(Ok));
    let live = BroadcastStream::new(rx).filter_map(|v| v.ok().map(Ok));
    let output = replay
        .chain(live)
        .map(|item: Result<BufferedEvent, Infallible>| {
            item.map(|e| {
                Event::default()
                    .id(e.id.to_string())
                    .event(e.kind)
                    .json_data(e.payload)
                    .unwrap()
            })
        });
    Sse::new(output)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("heartbeat"),
        )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(expires_at: u64, armed: bool, keys: Vec<String>) -> TraceState {
        let (tx, _) = broadcast::channel(MAX_EVENTS);
        TraceState { trace: LiveTrace { trace_id:"t".into(), key_type:"pseudonym".into(), subscriber_pseudonyms:keys, interfaces:vec![], created_at:0, expires_at, armed, messages:0, markers:0 }, next_id:0, events:VecDeque::new(), tx, keys:HashSet::new(), throughput_second:0, ul_bytes:0, dl_bytes:0 }
    }
    #[test]
    fn bounded_buffer() {
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert("t".into(), state(u64::MAX,true,vec![]));
        for n in 0..2100 {
            r.append("t", "message", json!({"n":n}));
        }
        assert_eq!(r.traces.lock().unwrap()["t"].events.len(), 2000);
        assert_eq!(
            r.traces.lock().unwrap()["t"].events.front().unwrap().id,
            101
        );
    }

    #[test]
    fn expiration_and_last_event_id_are_deterministic() {
        let r=LiveTraceRegistry::new(); r.traces.lock().unwrap().insert("old".into(),state(1,true,vec![])); r.traces.lock().unwrap().insert("t".into(),state(u64::MAX,true,vec![]));
        for n in 0..4 { r.append("t","message",json!({"n":n})); }
        let mut traces=r.traces.lock().unwrap(); LiveTraceRegistry::purge(&mut traces); assert!(!traces.contains_key("old"));
        let replay=traces["t"].events.iter().filter(|event|event.id>2).map(|event|event.id).collect::<Vec<_>>(); assert_eq!(replay,vec![3,4]);
    }

    #[test]
    fn growing_pcapng_emits_complete_packets_before_partial_tail() {
        let source=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let bytes=fs::read(&source).unwrap(); assert!(bytes.len()>64); let path=std::env::temp_dir().join(format!("oiran-live-partial-{}.pcapng",std::process::id())); fs::write(&path,&bytes[..bytes.len()-7]).unwrap();
        let config=oiran_decode::DecodeConfig{input:path.clone(),capture_id:format!("sha256:{}","a".repeat(64)),interface:"N2".into(),endpoints:HashMap::new()}; let key=event_schema::PseudonymKey::from_bytes([7;32]); let mut partial=Vec::new(); let _=oiran_decode::decode_capture_streaming(&config,&key,|event|{partial.push(event);Ok(())}); assert!(!partial.is_empty());
        fs::write(&path,&bytes).unwrap(); let mut complete=0; oiran_decode::decode_capture_streaming(&config,&key,|_|{complete+=1;Ok(())}).unwrap(); assert!(complete>=partial.len()); let _=fs::remove_file(path);
    }

    #[test]
    fn armed_trace_starts_only_on_decoder_key_and_learns_correlations() {
        let source=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng"); let config=oiran_decode::DecodeConfig{input:source,capture_id:format!("sha256:{}","b".repeat(64)),interface:"N2".into(),endpoints:HashMap::new()}; let key=event_schema::PseudonymKey::from_bytes([9;32]); let mut events=Vec::new(); oiran_decode::decode_capture_streaming(&config,&key,|event|{events.push(event);Ok(())}).unwrap();
        let first=events.iter().find(|event|!event.session_identifiers.is_empty()).unwrap(); let root=first.session_identifiers[0].value.clone(); let r=LiveTraceRegistry::new(); r.traces.lock().unwrap().insert("t".into(),state(u64::MAX,true,vec![root])); r.route_normalized(first); let traces=r.traces.lock().unwrap(); assert!(!traces["t"].trace.armed); assert_eq!(traces["t"].trace.messages,1); assert!(!traces["t"].keys.is_empty());
    }
}
