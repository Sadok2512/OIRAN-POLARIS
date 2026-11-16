//! Compile `bpf/vtap.bpf.c` en objet BPF uniquement avec la feature `ebpf`.
//! Sans la feature (tests hors ligne), aucun clang n'est requis.

fn main() {
    println!("cargo:rerun-if-changed=bpf/vtap.bpf.c");
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let obj = out.join("vtap.bpf.o");
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = std::process::Command::new(&clang)
        .args(["-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-Wall", "-Werror", "-c"])
        .arg("bpf/vtap.bpf.c")
        .arg("-o")
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("clang ({clang}) introuvable pour la cible bpf: {e}"));
    assert!(status.success(), "compilation eBPF échouée");
}
