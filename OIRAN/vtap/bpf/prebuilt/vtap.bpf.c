// SPDX-License-Identifier: GPL-2.0
// POLARIS vTAP 2.21.0 — uprobes libssl (SSL_write/SSL_read[_ex], SSL_set_fd)
// + tracepoints syscalls pour attribuer le fd du socket à chaque SSL*.
//
// Autonome : aucune dépendance libbpf-dev / vmlinux.h (le lab n'en a pas
// besoin). x86_64 uniquement en 2.21.0. Compilé par build.rs :
//   clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -c vtap.bpf.c
//
// Layout `struct vtap_event` partagé avec src/record.rs (HEADER_LEN = 56).

#if !defined(__TARGET_ARCH_x86)
#error "POLARIS vTAP 2.21.0: x86_64 only (define __TARGET_ARCH_x86)"
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

/* x86_64 struct pt_regs (uapi ptrace.h) */
struct pt_regs {
    unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
    unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#define PARM1(x) ((x)->di)
#define PARM2(x) ((x)->si)
#define PARM3(x) ((x)->dx)
#define PARM4(x) ((x)->cx)
#define RC(x) ((x)->ax)

/* tracepoint syscalls/sys_enter_* : en-tête commun 8 o, __syscall_nr (int)
 * + padding, puis 6 arguments. */
struct sys_enter_ctx {
    __u64 common;
    __s32 syscall_nr;
    __u32 pad;
    unsigned long args[6];
};

#define VTAP_CHUNK 16384
#define VTAP_MAX_CHUNKS 8
#define OP_WRITE 0
#define OP_READ 1
#define FLAG_TRUNCATED 0x01
#define FLAG_FD_UNKNOWN 0x02

/* stats (PERCPU_ARRAY) — lus par l'agent, jamais silencieux. */
#define STAT_RINGBUF_FULL 0
#define STAT_TRUNCATED 1
#define STAT_FD_UNKNOWN 2
#define STAT_MAX 4

struct vtap_event {
    __u64 ts_ns;          /* 0  */
    __u32 tgid;           /* 8  */
    __u32 tid;            /* 12 */
    __s32 fd;             /* 16 */
    __u8 op;              /* 20 */
    __u8 flags;           /* 21 */
    __u16 chunk_index;    /* 22 */
    __u32 total_len;      /* 24 */
    __u32 data_len;       /* 28 */
    __u64 ssl;            /* 32 */
    char comm[16];        /* 40 */
    __u8 data[VTAP_CHUNK];/* 56 */
};

struct ssl_key {
    __u32 tgid;
    __u32 pad;
    __u64 ssl;
};

struct active_call {
    __u64 ssl;
    __u64 buf;
    __u64 len_ptr; /* _ex : size_t *written / *readbytes ; 0 sinon */
    __u32 op;
    __u32 is_ex;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ssl_key);
    __type(value, __s32);
} ssl_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct active_call);
} active SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __attribute__((always_inline)) void stat_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        *v += 1;
}

static __attribute__((always_inline)) int enter(struct pt_regs *ctx, __u32 op, __u32 is_ex)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct active_call call = {
        .ssl = PARM1(ctx),
        .buf = PARM2(ctx),
        .len_ptr = is_ex ? PARM4(ctx) : 0,
        .op = op,
        .is_ex = is_ex,
    };
    bpf_map_update_elem(&active, &id, &call, BPF_ANY);
    return 0;
}

static __attribute__((always_inline)) int leave(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct active_call *call = bpf_map_lookup_elem(&active, &id);
    if (!call)
        return 0;
    /* SSL_read/SSL_write[_ex] renvoient un `int` : les 32 bits hauts de
     * rax sont indéfinis. Lire rax en 64 bits transforme -1 (EAGAIN) en
     * 4294967295 → faux octets (bug vu en test réel 2.21.0). */
    int rc = (int)RC(ctx);
    __u64 total = 0;
    if (call->is_ex) {
        if (rc == 1 && call->len_ptr) {
            bpf_probe_read_user(&total, sizeof(total), (void *)call->len_ptr);
        }
    } else if (rc > 0) {
        total = (__u64)rc;
    }
    __u64 buf = call->buf;
    __u32 op = call->op;
    struct ssl_key key = {.tgid = id >> 32, .pad = 0, .ssl = call->ssl};
    bpf_map_delete_elem(&active, &id);
    if (total == 0)
        return 0;

    __s32 fd = -1;
    __s32 *known = bpf_map_lookup_elem(&ssl_fd, &key);
    if (known)
        fd = *known;
    else
        stat_inc(STAT_FD_UNKNOWN);

    __u8 truncated = total > (__u64)VTAP_CHUNK * VTAP_MAX_CHUNKS;
    if (truncated)
        stat_inc(STAT_TRUNCATED);
    __u64 ts = bpf_ktime_get_ns();

    for (__u32 i = 0; i < VTAP_MAX_CHUNKS; i++) {
        __u64 off = (__u64)i * VTAP_CHUNK;
        if (off >= total)
            break;
        struct vtap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            stat_inc(STAT_RINGBUF_FULL);
            break;
        }
        __u64 n = total - off;
        if (n > VTAP_CHUNK)
            n = VTAP_CHUNK;
        e->ts_ns = ts;
        e->tgid = id >> 32;
        e->tid = (__u32)id;
        e->fd = fd;
        e->op = op;
        e->flags = (truncated ? FLAG_TRUNCATED : 0) | (known ? 0 : FLAG_FD_UNKNOWN);
        e->chunk_index = i;
        e->total_len = total > 0xffffffffULL ? 0xffffffffU : (__u32)total;
        e->ssl = key.ssl;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        n &= (VTAP_CHUNK * 2 - 1); /* borne explicite pour le vérifieur */
        if (n > VTAP_CHUNK)
            n = VTAP_CHUNK;
        if (bpf_probe_read_user(e->data, (__u32)n, (void *)(buf + off)) != 0)
            n = 0;
        e->data_len = (__u32)n;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("uprobe") int vtap_ssl_write_enter(struct pt_regs *ctx) { return enter(ctx, OP_WRITE, 0); }
SEC("uretprobe") int vtap_ssl_write_exit(struct pt_regs *ctx) { return leave(ctx); }
SEC("uprobe") int vtap_ssl_read_enter(struct pt_regs *ctx) { return enter(ctx, OP_READ, 0); }
SEC("uretprobe") int vtap_ssl_read_exit(struct pt_regs *ctx) { return leave(ctx); }
SEC("uprobe") int vtap_ssl_write_ex_enter(struct pt_regs *ctx) { return enter(ctx, OP_WRITE, 1); }
SEC("uretprobe") int vtap_ssl_write_ex_exit(struct pt_regs *ctx) { return leave(ctx); }
SEC("uprobe") int vtap_ssl_read_ex_enter(struct pt_regs *ctx) { return enter(ctx, OP_READ, 1); }
SEC("uretprobe") int vtap_ssl_read_ex_exit(struct pt_regs *ctx) { return leave(ctx); }

/* SSL_set_fd(ssl, fd) : attribution directe quand l'application la fait. */
SEC("uprobe") int vtap_ssl_set_fd(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_key key = {.tgid = id >> 32, .pad = 0, .ssl = PARM1(ctx)};
    __s32 fd = (__s32)PARM2(ctx);
    bpf_map_update_elem(&ssl_fd, &key, &fd, BPF_ANY);
    return 0;
}

/* Pendant un SSL_* actif sur ce thread, le premier syscall d'E/S révèle
 * le fd du socket (cas libcurl / BIO custom sans SSL_set_fd). */
static __attribute__((always_inline)) int learn_fd(struct sys_enter_ctx *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct active_call *call = bpf_map_lookup_elem(&active, &id);
    if (!call)
        return 0;
    struct ssl_key key = {.tgid = id >> 32, .pad = 0, .ssl = call->ssl};
    __s32 fd = (__s32)ctx->args[0];
    bpf_map_update_elem(&ssl_fd, &key, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write") int vtap_sys_write(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_writev") int vtap_sys_writev(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_sendto") int vtap_sys_sendto(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_sendmsg") int vtap_sys_sendmsg(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_read") int vtap_sys_read(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_readv") int vtap_sys_readv(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_recvfrom") int vtap_sys_recvfrom(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }
SEC("tracepoint/syscalls/sys_enter_recvmsg") int vtap_sys_recvmsg(struct sys_enter_ctx *ctx) { return learn_fd(ctx); }

char LICENSE[] SEC("license") = "GPL";
