#!/usr/bin/env bash
# 2.20.1 — bench O1 : `LiveInterfaceSource` AF_PACKET TPACKET_V3 +
# PACKET_FANOUT taux de perte à 100/500/1000 Mbit/s.
#
# Design doc §5.4 O1 — critère de recette R1.e : `drop_ratio ≤ 1e-4`
# à 1 Gbit/s sur 60 s.
#
# Usage :
#   sudo ./measure.sh <iface_or_bridge> <probe_id> [duration_s] [target_mbps]
# Exemple :
#   sudo ./measure.sh br-oiran-n2 lab-vprobe 60 1000
#
# Pré-requis :
#   * CAP_NET_RAW (sudo ou setcap cap_net_raw+ep sur le binaire).
#   * `pktgen_sample01_simple.sh` disponible (kernel samples/pktgen/).
#   * Un veth générateur côté opposé pour injecter le trafic.
#
# Mesure :
#   * `rx_packets`, `tp_drops` lus via `PACKET_STATISTICS` (TPACKET_V3).
#   * `drop_ratio = tp_drops / (rx_packets + tp_drops)`.
#   * Snapshot toutes les 1 s, agrégation finale.
#
# Sortie JSON :
#   {
#     "probe_id": "...",
#     "interface": "br-oiran-n2",
#     "target_mbps": 1000,
#     "duration_s": 60,
#     "rx_packets": N,
#     "tp_drops": D,
#     "drop_ratio": D / (N + D),
#     "r1e_passed": (drop_ratio <= 1e-4)
#   }
#
# Jamais d'identité en clair dans la sortie — seulement des
# compteurs numériques. Le fichier résultat vit uniquement dans
# `/tmp/oiran-bench-live-rx-drops/` jusqu'à archivage explicite.

set -euo pipefail

if [[ "${1:-}" == "" || "${2:-}" == "" ]]; then
  echo "usage: $0 <interface_device> <probe_id> [duration_s=60] [target_mbps=1000]" >&2
  exit 64
fi

iface="$1"
probe_id="$2"
duration_s="${3:-60}"
target_mbps="${4:-1000}"

out_dir="/tmp/oiran-bench-live-rx-drops"
mkdir -p "$out_dir"
out_file="$out_dir/${probe_id}-${iface}-${target_mbps}mbps-$(date +%s).json"

# 1. Lance la sonde live en mode bench (dedicated CLI option à ajouter
#    au binaire ; en 2.20.1 ce script est le contrat d'appel, le
#    binaire exposera `oiran-live-probe --bench-rx-drops <iface>`).
#    Pour l'instant on utilise un one-shot via l'API Rust `live-probe`
#    (test ignoré en CI, exécuté manuellement).
#
# 2. Lance pktgen en parallèle pour atteindre target_mbps.
#    Formule : pps = (mbps * 1_000_000) / 8 / avg_packet_size
#    avec avg_packet_size = 1500 octets (jumbo désactivé).
pps=$(( target_mbps * 1000000 / 8 / 1500 ))

echo "[oiran-bench] iface=$iface probe=$probe_id target=${target_mbps}Mbps pps=$pps duration=${duration_s}s"
echo "[oiran-bench] out=$out_file"

# Placeholder : l'appel réel au binaire bench (ou test rust)
# doit être branché ici. Le binaire fait :
#  - LiveInterfaceSource::new(...).try_open()
#  - boucle 1 Hz : packet_statistics_v3() → write snapshot
#  - fin à `duration_s` : écrit `out_file`
#
# Exemple d'appel (futur) :
#   cargo run --release --bin oiran-live-probe-bench -- \
#     --iface "$iface" --probe-id "$probe_id" \
#     --duration "$duration_s" --target-mbps "$target_mbps" \
#     --output "$out_file"

cat > "$out_file" <<EOF
{
  "probe_id": "$probe_id",
  "interface": "$iface",
  "target_mbps": $target_mbps,
  "duration_s": $duration_s,
  "pps": $pps,
  "status": "SCAFFOLD_ONLY_2_20_1",
  "note": "binaire bench à câbler dans un lot suivant — le trait LiveInterfaceSource expose déjà packet_statistics_v3()"
}
EOF

echo "[oiran-bench] scaffold emitted ; binaire bench à implémenter"
cat "$out_file"
