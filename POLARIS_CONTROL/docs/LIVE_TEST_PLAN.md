# Controlled live-test plan — approval required

1. Reconfirm port, CPU, RAM, disk, inode, ETV/OTV, Open5GS, UERANSIM, and capture health.
2. Register one sanitized existing UE profile by exact basename.
3. Allocate one controller-owned scenario ID and exact process handle.
4. Start one synthetic UE only; never restart Open5GS.
5. Observe Registration and one PDU Session.
6. Send exactly five 64-byte UDP datagrams at 1 packet/s to `10.77.22.1`.
7. Gracefully stop only the exact owned UE handle with a timeout.
8. Record audit history and revalidate all protected services.

Maximum intended duration: 5 minutes. Abort on disk monitor failure, >=85% affected filesystem use, memory/CPU pressure, lifecycle ambiguity, or any protected-service degradation. Rollback stops only the registered owned process; it never uses broad process matching.
