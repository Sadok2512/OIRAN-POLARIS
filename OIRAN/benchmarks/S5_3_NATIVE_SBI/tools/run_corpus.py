#!/usr/bin/env python3
"""Immutable S5.3 corpus replay and packet-aligned HTTP/2/SBI parity."""
from __future__ import annotations
import csv, hashlib, io, json, pathlib, re, subprocess

WORKSPACE = pathlib.Path(__file__).resolve().parents[3]
BASELINE = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2"
CORPUS = BASELINE / "corpus"
ROOT = WORKSPACE / "benchmarks/S5_3_NATIVE_SBI"
RAW, RESULTS = ROOT / "raw", ROOT / "results"
OIRAN = WORKSPACE / "target/release/oiran-decode"
DISCOVER = WORKSPACE / "target/release/examples/discover_jsonl"
TSHARK = BASELINE / "tools/tshark"
ENDPOINTS = ["172.22.0.23=gNB", "172.22.0.10=AMF", "172.22.0.35=SCP", "172.22.0.7=SMF", "172.22.0.8=UPF"]

def ident(path): return "__".join(path.relative_to(CORPUS).with_suffix("").parts)
def sanitize(value):
    value = re.sub(r"(?:imsi|suci)-[A-Za-z0-9_-]+", "subscriber-[REDACTED]", value or "")
    return re.sub(r"subscriber-psn-[0-9a-f]+", "subscriber-[REDACTED]", value)
def split(value): return [part for part in (value or "").split(";") if part]
def epoch_ns(value):
    sec, dot, frac = value.partition("."); return int(sec or 0) * 1_000_000_000 + int((frac[:9]).ljust(9, "0") or 0)

def tshark_inventory(capture, dataset):
    fields = ["frame.number","frame.time_epoch","tcp.stream","http2.type","http2.streamid","http2.header.name","http2.header.value"]
    cmd=[str(TSHARK),"-r",str(capture),"-d","tcp.port==7777,http2","-Y","http2","-T","fields","-E","separator=|","-E","occurrence=a","-E","aggregator=;"]
    for field in fields: cmd += ["-e",field]
    run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True)
    rows=[]; frame_count=0; by_request={}
    for line in run.stdout.splitlines():
        cols=(line.split("|")+[""]*len(fields))[:len(fields)]; row=dict(zip(fields,cols)); rows.append(row); frame_count += len(split(row["http2.type"]))
        names=split(row["http2.header.name"]); values=split(row["http2.header.value"]); headers={name:value for name,value in zip(names,values) if name != "<unknown>"}
        method=headers.get(":method"); path=headers.get(":path"); streams=split(row["http2.streamid"])
        if method and path and streams:
            by_request[(int(row["frame.number"]),int(streams[0]))]={"method":method,"path":sanitize(path),"timestamp_ns":epoch_ns(row["frame.time_epoch"])}
    safe=RAW/f"{dataset}.tshark_http2.csv"
    with safe.open("w",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=["frame_number","tcp_stream","http2_stream_ids","http2_frame_types","method","sanitized_path"]); writer.writeheader()
        for row in rows:
            names=split(row["http2.header.name"]); values=split(row["http2.header.value"]); headers={name:value for name,value in zip(names,values) if name != "<unknown>"}
            writer.writerow({"frame_number":row["frame.number"],"tcp_stream":row["tcp.stream"],"http2_stream_ids":row["http2.streamid"],"http2_frame_types":row["http2.type"],"method":headers.get(":method", ""),"sanitized_path":sanitize(headers.get(":path", ""))})
    return frame_count, by_request

def main():
    RAW.mkdir(parents=True,exist_ok=True); RESULTS.mkdir(parents=True,exist_ok=True)
    subprocess.run(["cargo","build","--release","-q","-p","oiran-decode"],cwd=WORKSPACE,check=True)
    subprocess.run(["cargo","build","--release","-q","-p","session-engine","--example","discover_jsonl"],cwd=WORKSPACE,check=True)
    before=subprocess.run(["sha256sum","-c","SHA256SUMS"],cwd=CORPUS,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (RAW/"sha256_before.txt").write_text(before.stdout)
    if before.returncode: raise SystemExit("corpus SHA256 preflight failed")
    captures=sorted([*CORPUS.rglob("*.pcap"),*CORPUS.rglob("*.pcapng")]); inventory=[]; parity=[]; totals={"tcp_streams":0,"http2_streams":0,"sbi_transactions":0,"operations":0,"http2_frames_oiran":0,"http2_frames_tshark":0,"fields_comparable":0,"fields_exact":0,"fields_mismatch":0,"fields_unresolved":0}; multi=None
    for capture in captures:
        dataset=ident(capture); digest=hashlib.sha256(capture.read_bytes()).hexdigest(); output=RAW/f"{dataset}.events.jsonl"; interface=capture.stem if capture.stem in {"N2","N3","N4"} else "N2"
        cmd=[str(OIRAN),"--input",str(capture),"--capture-id",f"sha256:{digest}","--interface",interface,"--output",str(output)]
        for endpoint in ENDPOINTS: cmd += ["--endpoint",endpoint]
        run=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True); (RAW/f"{dataset}.oiran.stdout").write_text(run.stdout); (RAW/f"{dataset}.oiran.stderr").write_text(run.stderr)
        metrics=dict(token.split("=",1) for token in run.stdout.split() if "=" in token); events=[json.loads(line) for line in output.read_text().splitlines() if line]; sbi=[event for event in events if event["protocol"]=="SBI-HTTP2"]
        tshark_frames, tshark_requests=tshark_inventory(capture,dataset)
        for event in sbi:
            meta=event.get("sbi") or {}; packet=event["packet_references"][0]["packet_number"]; stream=meta.get("http2_stream_id"); reference=tshark_requests.get((packet,stream)); actual_uri=sanitize(meta.get("request_uri") or "")
            checks=[]
            if reference:
                checks += [stream is not None, event["timestamp"]["seconds"]*1_000_000_000+event["timestamp"]["nanoseconds"]==reference["timestamp_ns"]]
                if meta.get("http_method"): checks.append(meta["http_method"]==reference["method"])
                if actual_uri: checks.append(actual_uri==reference["path"])
            comparable=len(checks); exact=sum(checks); unresolved=(4-comparable) if reference else 4
            totals["fields_comparable"] += comparable; totals["fields_exact"] += exact; totals["fields_mismatch"] += comparable-exact; totals["fields_unresolved"] += unresolved
            parity.append({"dataset":dataset,"packet_number":packet,"http2_stream_id":stream,"operation":event["message_name"],"method":meta.get("http_method") or "","sanitized_uri":actual_uri,"tshark_aligned":reference is not None,"fields_comparable":comparable,"fields_exact":exact,"fields_mismatched":comparable-exact,"fields_unresolved":unresolved,"classification":"EXACT" if comparable and exact==comparable and unresolved==0 else ("PARTIAL" if comparable else "NOT_COMPARABLE")})
        discovery=json.loads(subprocess.run([str(DISCOVER),str(output)],stdout=subprocess.PIPE,check=True).stdout); (RAW/f"{dataset}.discovery.json").write_text(json.dumps(discovery,indent=2)+"\n")
        if dataset=="LAB_TESTBED__multi-imsi": multi=discovery
        row={"dataset":dataset,"sha256":digest,"packets":int(metrics.get("packets",0)),"tcp_streams":int(metrics.get("tcp_connections",0)),"http2_frames_oiran":int(metrics.get("http2_frames",0)),"http2_frames_tshark":tshark_frames,"http2_streams":int(metrics.get("http2_streams",0)),"sbi_transactions":len(sbi),"sbi_operations_decoded":sum(event["message_name"]!="UnsupportedSbiOperation" for event in sbi),"partial_transactions":sum(event["decoding_status"]!="DECODED" for event in sbi),"ue_contexts":len(discovery["ue_contexts"]),"pdu_sessions":len(discovery["pdu_sessions"])}; inventory.append(row)
        for key in ["tcp_streams","http2_streams","sbi_transactions"]: totals[key]+=row[key]
        totals["operations"]+=row["sbi_operations_decoded"]; totals["http2_frames_oiran"]+=row["http2_frames_oiran"]; totals["http2_frames_tshark"]+=row["http2_frames_tshark"]
    with (RESULTS/"S5_3_RESULTS.csv").open("w",newline="") as handle: writer=csv.DictWriter(handle,fieldnames=list(inventory[0])); writer.writeheader(); writer.writerows(inventory)
    with (RESULTS/"sbi_parity.csv").open("w",newline="") as handle: writer=csv.DictWriter(handle,fieldnames=list(parity[0])); writer.writeheader(); writer.writerows(parity)
    contexts=[session["ue_context_id"] for session in (multi or {}).get("pdu_sessions",[])]; summary={"corpus_files":len(captures),"corpus_packets":sum(row["packets"] for row in inventory),"corpus_sha256_integrity":"PASS",**totals,"multi_imsi":{"ue_contexts":len((multi or {}).get("ue_contexts",[])),"pdu_sessions":len((multi or {}).get("pdu_sessions",[])),"pfcp_sessions":len((multi or {}).get("pfcp_sessions",[])),"gtpu_tunnels":len((multi or {}).get("gtpu_tunnels",[])),"cross_ue_contamination":"NONE_OBSERVED" if len(contexts)==len(set(contexts)) else "DETECTED"},"inventory":inventory}
    (RESULTS/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    after=subprocess.run(["sha256sum","-c","SHA256SUMS"],cwd=CORPUS,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT); (RAW/"sha256_after.txt").write_text(after.stdout); return after.returncode
if __name__=="__main__": raise SystemExit(main())
