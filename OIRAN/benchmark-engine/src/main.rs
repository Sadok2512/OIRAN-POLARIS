use benchmark_engine::{
    run, BenchmarkConfig, BenchmarkMode, SafetyGateReceipt, SUPPORTED_FRAME_SIZES,
};
use std::{env, process, time::Duration};
use worker_runtime::AffinityRequest;

fn usage() {
    eprintln!("usage: benchmark-engine --safety-receipt PATH [--mode generator|processing|full] [--workers 1..4] [--duration-ms N] [--frame-size 64|128|512|1500|all] [--batch-size 32|64|128|256] [--queue-batches N] [--flows N] [--affinity auto|disabled|explicit] [--producer-cpu N --worker-cpus N,N,...]");
}

fn main() {
    let mut workers = 2;
    let mut duration_ms = 250;
    let mut frame = "all".to_string();
    let mut batch_size = 64;
    let mut queue_batches = 256;
    let mut flows = 256;
    let mut mode = BenchmarkMode::FullPipeline;
    let mut affinity_mode = "auto".to_string();
    let mut producer_cpu = None;
    let mut worker_cpus = None;
    let mut receipt_path = None;
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if option == "--no-pin" {
            affinity_mode = "disabled".into();
            index += 1;
            continue;
        }
        if index + 1 >= args.len() {
            usage();
            process::exit(2)
        }
        let value = &args[index + 1];
        let usize_value = || {
            value
                .parse::<usize>()
                .unwrap_or_else(|_| fail("invalid integer"))
        };
        match option {
            "--mode" => {
                mode = match value.as_str() {
                    "generator" => BenchmarkMode::GeneratorOnly,
                    "processing" => BenchmarkMode::ProcessingOnly,
                    "full" => BenchmarkMode::FullPipeline,
                    _ => fail("invalid mode"),
                }
            }
            "--workers" => workers = usize_value(),
            "--duration-ms" => {
                duration_ms = value.parse().unwrap_or_else(|_| fail("invalid duration"))
            }
            "--frame-size" => frame = value.clone(),
            "--batch-size" => batch_size = usize_value(),
            "--queue-batches" => queue_batches = usize_value(),
            "--flows" => flows = usize_value(),
            "--affinity" => affinity_mode = value.clone(),
            "--producer-cpu" => producer_cpu = Some(usize_value()),
            "--worker-cpus" => {
                worker_cpus = Some(
                    value
                        .split(',')
                        .map(|v| {
                            v.parse::<usize>()
                                .unwrap_or_else(|_| fail("invalid worker CPU list"))
                        })
                        .collect(),
                )
            }
            "--safety-receipt" => receipt_path = Some(value.clone()),
            _ => {
                usage();
                process::exit(2)
            }
        }
        index += 2;
    }
    let affinity = match affinity_mode.as_str() {
        "auto" => AffinityRequest::Automatic,
        "disabled" => AffinityRequest::Disabled,
        "explicit" => AffinityRequest::Explicit {
            producer_cpu: producer_cpu
                .unwrap_or_else(|| fail("explicit affinity requires --producer-cpu")),
            worker_cpus: worker_cpus
                .unwrap_or_else(|| fail("explicit affinity requires --worker-cpus")),
        },
        _ => fail("invalid affinity mode"),
    };
    let receipt = SafetyGateReceipt::read(&receipt_path.unwrap_or_else(|| {
        fail("--safety-receipt is mandatory; run scripts/s2_1_safety_gate.sh first")
    }))
    .unwrap_or_else(|error| {
        eprintln!("safety_gate_error={error}");
        process::exit(1)
    });
    let sizes = if frame == "all" {
        SUPPORTED_FRAME_SIZES.to_vec()
    } else {
        vec![frame.parse().unwrap_or_else(|_| fail("invalid frame size"))]
    };
    for size in sizes {
        let config = BenchmarkConfig {
            mode,
            workers,
            duration: Duration::from_millis(duration_ms),
            frame_size: size,
            batch_size,
            queue_capacity_batches: queue_batches,
            flow_count: flows,
            affinity: affinity.clone(),
        };
        match run(&config, &receipt) {
            Ok(result) => print_result(size, workers, &result),
            Err(error) => {
                eprintln!("benchmark_error={error}");
                process::exit(1)
            }
        }
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    usage();
    process::exit(2)
}
fn print_result(size: usize, workers: usize, r: &benchmark_engine::BenchmarkResult) {
    println!("mode={} frame_size={} workers={} elapsed_ms={} preloaded={} generated={} enqueued={} processed={} in_flight={} pps={:.0} mpps={:.6} captured_gbps={:.6} gtpu_payload_gbps={:.6} ethernet_wire_gbps_equivalent={:.6} cpu_percent={:.2} rss_mib={:.2} queue_high_watermark={} drops={} loss_percent={:.6} malformed={} integrity_errors={} length_errors={} work_accumulator={} affinity_failures={} allowed_cpus={:?} producer_cpu={:?} worker_cpus={:?}",r.mode.as_str(),size,workers,r.elapsed.as_millis(),r.preloaded_packets,r.generated_packets,r.enqueued_packets,r.processed.packets,r.accounted_in_flight,r.packets_per_second,r.mpps,r.captured_gbps,r.gtpu_payload_gbps,r.ethernet_wire_gbps_equivalent,r.cpu_percent,r.rss_bytes as f64/1_048_576.0,r.processed.queue_high_watermark,r.processed.dropped,r.packet_loss_percent,r.processed.malformed,r.processed.integrity_errors,r.processed.length_errors,r.processed.work_accumulator,r.affinity_failures,r.affinity.allowed_cpus,r.affinity.producer_cpu,r.affinity.worker_cpus);
    for (worker, stats) in r.per_worker.iter().enumerate() {
        let pps = stats.packets as f64 / r.elapsed.as_secs_f64().max(f64::EPSILON);
        println!("worker={} packets={} bytes={} pps={:.0} queue_high_watermark={} drops={} effective_cpus={:?}",worker,stats.packets,stats.bytes,pps,stats.queue_high_watermark,stats.dropped,r.worker_effective_cpus.get(worker));
    }
}
