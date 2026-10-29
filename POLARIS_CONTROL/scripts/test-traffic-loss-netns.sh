#!/usr/bin/env bash
set -euo pipefail

# Manual, privileged offline regression for POLARIS traffic primitives.
# It creates only disposable network namespaces and never reaches the lab.
IPERF3_PATH="${POLARIS_IPERF3_PATH:-/opt/polaris-control/libexec/iperf3}"
RATE="${POLARIS_TEST_IPERF3_RATE:-5M}"
NS_A="polaris174a"
NS_B="polaris174b"
VETH_A="p174a"
VETH_B="p174b"
ARTIFACT_DIR="$(mktemp -d /tmp/polaris-0.17.4-netns.XXXXXX)"

cleanup() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"
ip -n "$NS_A" address add 198.18.44.1/30 dev "$VETH_A"
ip -n "$NS_B" address add 198.18.44.2/30 dev "$VETH_B"
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up
set_directional_loss() {
  local direction="$1"
  if [[ "$direction" == "ul" ]]; then
    ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem loss 8%
    ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem loss 0%
  else
    ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem loss 0%
    ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem loss 8%
  fi
}

run_iperf() {
  local direction="$1" client_ns="$2" client_ip="$3" client_dev="$4"
  local server_ns="$5" server_ip="$6" port="$7"
  set_directional_loss "$direction"
  ip netns exec "$server_ns" "$IPERF3_PATH" -s -1 -J -B "$server_ip" -p "$port" \
    >"$ARTIFACT_DIR/iperf-${direction}-server.json" 2>"$ARTIFACT_DIR/iperf-${direction}-server.err" &
  local server_pid=$!
  sleep 0.2
  ip netns exec "$client_ns" "$IPERF3_PATH" -c "$server_ip" -p "$port" \
    -n 1048576 -b "$RATE" --get-server-output -w 64K -J \
    -B "$client_ip" --bind-dev "$client_dev" \
    >"$ARTIFACT_DIR/iperf-${direction}-client.json"
  wait "$server_pid"
  python3 - "$direction" "$ARTIFACT_DIR/iperf-${direction}-client.json" <<'PY'
import json,sys
direction,path=sys.argv[1:]
report=json.load(open(path)); server=report['server_output_json']
sent=report['end']['sum_sent']['bytes']; received=server['end']['sum_received']['bytes']
print(f'IPERF_{direction.upper()}_SENT={sent}')
print(f'IPERF_{direction.upper()}_RECEIVED={received}')
print(f'IPERF_{direction.upper()}_EQUAL={str(sent == received).lower()}')
if sent != received: raise SystemExit(1)
PY
}

run_transfer() {
  local direction="$1" client_ns="$2" client_ip="$3" client_dev="$4"
  local server_ns="$5" server_ip="$6" port="$7"
  set_directional_loss "$direction"
  head -c 1048576 /dev/urandom >"$ARTIFACT_DIR/transfer-${direction}-source.bin"
  ip netns exec "$server_ns" python3 -c 'import hashlib,json,socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));s.listen(1);c,_=s.accept();h=hashlib.sha256();n=0
with open(sys.argv[3],"wb") as f:
 while True:
  d=c.recv(65536)
  if not d: break
  f.write(d);h.update(d);n+=len(d)
c.close();s.close();print(json.dumps({"bytes":n,"sha256":h.hexdigest()}))' \
    "$server_ip" "$port" "$ARTIFACT_DIR/transfer-${direction}-received.bin" \
    >"$ARTIFACT_DIR/transfer-${direction}-receiver.json" &
  local receiver_pid=$!
  sleep 0.2
  ip netns exec "$client_ns" python3 -c 'import hashlib,json,socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,(sys.argv[3]+"\0").encode());s.bind((sys.argv[2],0));s.connect((sys.argv[4],int(sys.argv[5])));h=hashlib.sha256();n=0
with open(sys.argv[1],"rb") as f:
 while True:
  d=f.read(65536)
  if not d: break
  s.sendall(d);h.update(d);n+=len(d)
s.shutdown(socket.SHUT_WR);s.close();print(json.dumps({"bytes":n,"sha256":h.hexdigest()}))' \
    "$ARTIFACT_DIR/transfer-${direction}-source.bin" "$client_ip" "$client_dev" "$server_ip" "$port" \
    >"$ARTIFACT_DIR/transfer-${direction}-sender.json"
  wait "$receiver_pid"
  python3 - "$direction" "$ARTIFACT_DIR/transfer-${direction}-sender.json" "$ARTIFACT_DIR/transfer-${direction}-receiver.json" <<'PY'
import json,sys
direction,sender_path,receiver_path=sys.argv[1:]
sender=json.load(open(sender_path)); receiver=json.load(open(receiver_path))
print(f'TRANSFER_{direction.upper()}_SENT={sender["bytes"]}')
print(f'TRANSFER_{direction.upper()}_RECEIVED={receiver["bytes"]}')
print(f'TRANSFER_{direction.upper()}_SHA256={sender["sha256"]}')
print(f'TRANSFER_{direction.upper()}_SHA256_EQUAL={str(sender["sha256"] == receiver["sha256"]).lower()}')
if sender['bytes'] != 1048576 or receiver['bytes'] != 1048576 or sender['sha256'] != receiver['sha256']:
 raise SystemExit(1)
PY
}

run_iperf ul "$NS_A" 198.18.44.1 "$VETH_A" "$NS_B" 198.18.44.2 53174
run_iperf dl "$NS_B" 198.18.44.2 "$VETH_B" "$NS_A" 198.18.44.1 53175
run_transfer ul "$NS_A" 198.18.44.1 "$VETH_A" "$NS_B" 198.18.44.2 53176
run_transfer dl "$NS_B" 198.18.44.2 "$VETH_B" "$NS_A" 198.18.44.1 53177
printf 'LOSS_PERCENT=8\nRATE=%s\nARTIFACT_DIR=%s\n' "$RATE" "$ARTIFACT_DIR"
