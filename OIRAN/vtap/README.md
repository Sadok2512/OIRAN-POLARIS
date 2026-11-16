# POLARIS vTAP 2.21.1 (P1b) — SBI TLS visible sans clé

Agent eBPF `polaris-vtap` : uprobes sur `SSL_write`/`SSL_read` (+ `_ex`, `SSL_set_fd`) de la libssl des
conteneurs Open5GS. Le HTTP/2 en clair est rejoué en pcap TCP normal (handshake synthétique, seq/ack
cohérents dans les deux sens) : `vtap_SBI_<UTC>.pcap` + manifeste `vtap_SBI_<UTC>.vtap.json`. Le décodeur
SBI actuel le lit sans changement.

## Build (lab, basse priorité, jamais pendant un test de Sadok)

```bash
cd OIRAN/vtap
nice -n 19 ionice -c3 cargo test -j 2                                   # hors ligne, sans clang ni root
nice -n 19 ionice -c3 cargo build --release --locked -j 2 --features ebpf
# Rust ≥ 1.83 (lock aligné). clang facultatif : absent → objet précompilé bpf/prebuilt/vtap.bpf.o,
# accepté seulement si bpf/vtap.bpf.c == bpf/prebuilt/vtap.bpf.c (sinon VTAP_PREBUILT_STALE).
```

## Lancement (root : CAP_BPF + CAP_PERFMON + accès /proc/<pid>/fd)

```bash
# tracefs absent → l'agent le monte lui-même (log VTAP_TRACEFS_MOUNTED).
sudo ./target/release/polaris-vtap --out-dir /var/lib/oiran/vtap --probe-id lab-vtap --rotate-seconds 300
```

Logs JSON sur stderr : `VTAP_START`, `VTAP_UPROBE_ATTACHED` (une ligne par symbole et par libssl),
`VTAP_SYMBOL_MISSING` (symbole `_ex` absent : non bloquant), `VTAP_FILE_CLOSED` (compteurs + open_items),
`VTAP_FATAL` (`VTAP_NO_TARGET` si aucun `open5gs-*` ne mappe libssl, c'est-à-dire que le TLS SBI n'est pas actif).

Décodage d'un fichier fermé :

```bash
oiran-decode --input vtap_SBI_….pcap --capture-id sha256:$(sha256sum vtap_SBI_….pcap | cut -c1-64) \
  --interface SBI --output out.jsonl --probe-id lab-vtap --probe-type vtap --timestamp-source ebpf_monotonic
```

`polaris.toml` :

```toml
[[probes]]
id = "lab-vtap"
engine = "vtap"
probe_type = "vtap"
out_dir = "/var/lib/oiran/vtap"
interfaces = [ { label = "SBI", device = "vtap", decoder = "sbi" } ]
```

## OUVERT (déclaré, jamais masqué)

- **HPACK** : une connexion ouverte AVANT l'agent n'a pas sa table dynamique, d'où `hpack_context = mid_stream`
  au manifeste et `HPACK_MID_STREAM` dans open_items. Il faut redémarrer les NF Open5GS APRÈS le lancement de l'agent.
- HPACK entre deux fichiers rotatés : même limite que le chemin dumpcap (décodage par fichier).
- IPv6 non supporté (compté `unsupported_family`). Pas de FIN synthétique (fin par timeout d'inactivité).
- x86_64 uniquement. Câblage dans le watcher continu : avec le wiring 2.20.2 (`VtapSource` non câblée, comme `PcapRotatingSource`).
