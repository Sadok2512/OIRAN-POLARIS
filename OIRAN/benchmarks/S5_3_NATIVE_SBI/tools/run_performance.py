#!/usr/bin/env python3
"""One warm-up plus five bounded full-corpus S5.3 measurements."""
from __future__ import annotations
import hashlib,json,pathlib,statistics,subprocess,tempfile
W=pathlib.Path(__file__).resolve().parents[3]; C=W/"benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus"; O=W/"target/release/oiran-decode"; OUT=W/"benchmarks/S5_3_NATIVE_SBI/results/performance.json"
def one(index,warmup):
    elapsed=0.; peak=0; transactions=0
    with tempfile.TemporaryDirectory(prefix="oiran-s5-3-") as temp:
        for n,capture in enumerate(sorted([*C.rglob("*.pcap"),*C.rglob("*.pcapng")])):
            digest=hashlib.sha256(capture.read_bytes()).hexdigest(); output=pathlib.Path(temp)/f"{n}.jsonl"; interface=capture.stem if capture.stem in {"N2","N3","N4"} else "N2"
            run=subprocess.run(["/usr/bin/time","-f","__METRIC__%e|%M",str(O),"--input",str(capture),"--capture-id",f"sha256:{digest}","--interface",interface,"--output",str(output)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,check=True)
            for line in run.stderr.splitlines():
                if line.startswith("__METRIC__"): seconds,rss=line[10:].split("|"); elapsed+=float(seconds); peak=max(peak,int(rss))
            transactions+=sum(json.loads(line).get("protocol")=="SBI-HTTP2" for line in output.read_text().splitlines())
    return {"iteration":index,"warmup":warmup,"seconds":elapsed,"peak_rss_kib":peak,"sbi_transactions":transactions}
def main():
    runs=[one(0,True)]+[one(i,False) for i in range(1,6)]; measured=runs[1:]; median=statistics.median(run["seconds"] for run in measured); result={"method":{"warmup_runs":1,"measured_runs":5,"files":13,"packets":4205},"median_total_seconds":median,"median_packets_per_second":4205/median,"median_sbi_transactions_per_second":statistics.median(run["sbi_transactions"]/run["seconds"] for run in measured),"peak_rss_kib":max(run["peak_rss_kib"] for run in measured),"runs":runs}; OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(result,indent=2)+"\n")
if __name__=="__main__": main()
