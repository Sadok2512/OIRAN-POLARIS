//! Objet eBPF `vtap.bpf.o`, uniquement avec la feature `ebpf`.
//!
//! 2.21.1 — deux voies, toujours annoncées (`cargo:warning`), jamais
//! silencieuses :
//! 1. clang présent (`$CLANG` ou `clang` dans le PATH) → compilation de
//!    `bpf/vtap.bpf.c`.
//! 2. clang absent (cas du lab) → objet précompilé `bpf/prebuilt/vtap.bpf.o`,
//!    ACCEPTÉ SEULEMENT si `bpf/vtap.bpf.c` est octet pour octet identique à
//!    la source qui l'a produit (`bpf/prebuilt/vtap.bpf.c`). Sinon le build
//!    échoue : installer clang ou régénérer (`bpf/build-prebuilt.sh`).

use std::path::Path;
use std::process::Command;

const SOURCE: &str = "bpf/vtap.bpf.c";
const PREBUILT_OBJ: &str = "bpf/prebuilt/vtap.bpf.o";
const PREBUILT_SRC: &str = "bpf/prebuilt/vtap.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed={PREBUILT_OBJ}");
    println!("cargo:rerun-if-changed={PREBUILT_SRC}");
    println!("cargo:rerun-if-env-changed=CLANG");
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("vtap.bpf.o");
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let compiled = Command::new(&clang)
        .args(["-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-Wall", "-Werror", "-c"])
        .arg(SOURCE)
        .arg("-o")
        .arg(&out)
        .status();
    match compiled {
        Ok(status) => {
            assert!(status.success(), "compilation eBPF échouée ({clang})");
            println!("cargo:warning=polaris-vtap: objet eBPF compilé par {clang}");
        }
        Err(_) => {
            let source = std::fs::read(SOURCE).expect("bpf/vtap.bpf.c");
            let reference = std::fs::read(PREBUILT_SRC).unwrap_or_default();
            assert!(
                source == reference,
                "VTAP_PREBUILT_STALE: clang ({clang}) absent ET {SOURCE} diffère de {PREBUILT_SRC} \
                 → installer clang, ou régénérer l'objet avec bpf/build-prebuilt.sh"
            );
            std::fs::copy(PREBUILT_OBJ, &out).expect("bpf/prebuilt/vtap.bpf.o");
            println!(
                "cargo:warning=polaris-vtap: clang absent → objet eBPF PRÉCOMPILÉ utilisé (source identique vérifiée)"
            );
        }
    }
}
