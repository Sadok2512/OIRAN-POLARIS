# Four-Plane Capture Architecture

The fixed profile maps NG-C to `br-oiran-n2` SCTP/38412, SBI to `br-oiran-sbi` TCP/7777, N4 to `br-oiran-n4` UDP/8805 and NG-U to `br-oiran-n3` UDP/2152. One capture job owns all selected plane writers, a shared group ID and a bounded total storage reservation. Each plane exposes its own timestamps, counters, storage, decode state, dataset reference and hashes. Empty or partial planes remain explicit.
