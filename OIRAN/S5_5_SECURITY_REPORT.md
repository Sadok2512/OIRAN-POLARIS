# Security Report

The API remains unprivileged. Acquisition remains in the dedicated Unix-socket helper with peer credentials, exact job ownership, fixed interface allowlists and native AF_PACKET. The change adds no public listener, Docker socket, shell execution, arbitrary filter, path control or legacy tcpdump fallback. Disk/resource gates and Viewer/Operator authorization remain enforced.
