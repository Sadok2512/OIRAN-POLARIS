use polaris_control_api::{verify_open5gs_profile_binding, UeProfileRegistry};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use ueransim_adapter::{planned_profiles, ProvisioningBinding};

fn fail(message: &str) -> ! {
    eprintln!("ATTESTATION_FAILED={message}");
    std::process::exit(1)
}

fn main() {
    let mut records_path = None;
    let mut profile_root = PathBuf::from(ueransim_adapter::LIVE_PROFILE_ROOT);
    let mut ue01_profile = PathBuf::from("/root/POLARIS/runtime/ueransim/ue.yaml");
    let mut output = PathBuf::from("/var/lib/polaris-control/ue-provisioning-attestation.json");
    let mut count = 3_usize;
    let mut profile_registry = None;
    let mut write = false;
    let mut offline_fixture = false;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--open5gs-records" => records_path = args.next().map(PathBuf::from),
            "--profile-root" => {
                profile_root = args
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| fail("ARGUMENT_MISSING"))
            }
            "--ue01-profile" => {
                ue01_profile = args
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| fail("ARGUMENT_MISSING"))
            }
            "--output" => {
                output = args
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| fail("ARGUMENT_MISSING"))
            }
            "--count" => {
                count = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| fail("COUNT_INVALID"))
            }
            "--profile-registry" => profile_registry = args.next().map(PathBuf::from),
            "--write" => write = true,
            "--offline-fixture" => offline_fixture = true,
            _ => fail("ARGUMENT_INVALID"),
        }
    }
    if !(1..=ueransim_adapter::MAX_CONFIGURABLE_UES).contains(&count) {
        fail("COUNT_INVALID");
    }
    if offline_fixture && write {
        fail("OFFLINE_FIXTURE_WRITE_FORBIDDEN");
    }
    let records_path = records_path.unwrap_or_else(|| fail("OPEN5GS_RECORDS_REQUIRED"));
    if !offline_fixture {
        require_private_root_file(&records_path).unwrap_or_else(|error| fail(&error));
    }
    let bytes = fs::read(&records_path).unwrap_or_else(|_| fail("OPEN5GS_RECORDS_UNREADABLE"));
    let export: Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| fail("OPEN5GS_RECORDS_INVALID"));
    if export.pointer("/source/system").and_then(Value::as_str) != Some("OPEN5GS")
        || export.pointer("/source/database").and_then(Value::as_str) != Some("open5gs")
        || export.pointer("/source/collection").and_then(Value::as_str) != Some("subscribers")
    {
        fail("OPEN5GS_PROVENANCE_INVALID");
    }
    let records = export
        .get("subscribers")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("OPEN5GS_RECORDS_INVALID"));
    let profiles = if let Some(path) = profile_registry {
        if !offline_fixture {
            require_private_root_file(&path).unwrap_or_else(|error| fail(&error));
        }
        let registry: UeProfileRegistry = serde_json::from_slice(
            &fs::read(path).unwrap_or_else(|_| fail("PROFILE_REGISTRY_UNREADABLE")),
        )
        .unwrap_or_else(|_| fail("PROFILE_REGISTRY_INVALID"));
        registry
            .profiles
            .into_iter()
            .filter(|record| record.profile.configured)
            .map(|record| record.profile)
            .take(count)
            .collect::<Vec<_>>()
    } else {
        planned_profiles().into_iter().take(count).collect()
    };
    if profiles.len() != count {
        fail("PROFILE_COUNT_MISMATCH");
    }
    let mut bindings = Vec::<ProvisioningBinding>::new();
    for profile in profiles {
        let managed_path = profile_root.join(&profile.profile_name);
        let path = if managed_path.is_file() {
            managed_path
        } else if profile.ue_id == "UE-01" {
            ue01_profile.clone()
        } else {
            fail("PROFILE_UNREADABLE")
        };
        if !offline_fixture {
            require_private_root_file(&path).unwrap_or_else(|error| fail(&error));
        }
        let profile_bytes = fs::read(&path).unwrap_or_else(|_| fail("PROFILE_UNREADABLE"));
        let supi = profile_bytes
            .split(|byte| *byte == b'\n')
            .find_map(|line| {
                let line = std::str::from_utf8(line).ok()?.trim();
                line.strip_prefix("supi:")
                    .map(str::trim)
                    .map(|value| value.trim_matches(|ch| matches!(ch, '\'' | '"')))
            })
            .unwrap_or_else(|| fail("PROFILE_INVALID"));
        let imsi = supi.strip_prefix("imsi-").unwrap_or(supi);
        let record = records
            .iter()
            .find(|record| record.get("imsi").and_then(Value::as_str) == Some(imsi))
            .unwrap_or_else(|| fail("OPEN5GS_IDENTITY_NOT_FOUND"));
        bindings.push(
            verify_open5gs_profile_binding(&profile, &profile_bytes, record)
                .unwrap_or_else(|error| fail(&error)),
        );
    }
    let serialized = serde_json::to_vec_pretty(&bindings)
        .unwrap_or_else(|_| fail("ATTESTATION_SERIALIZATION_FAILED"));
    if write {
        write_private_atomic(&output, &serialized).unwrap_or_else(|error| fail(&error));
    }
    println!(
        "{}",
        json!({
            "mode": if write {"WRITE"} else {"DRY_RUN"},
            "authority": "OPEN5GS",
            "verified_profiles": bindings.iter().map(|binding| binding.ue_id.as_str()).collect::<Vec<_>>(),
            "output": output,
            "written": write
        })
    );
}

fn require_private_root_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path).map_err(|_| "PRIVATE_INPUT_UNREADABLE")?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("PRIVATE_INPUT_UNSAFE".into());
        }
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let parent = path.parent().ok_or("ATTESTATION_OUTPUT_INVALID")?;
    fs::create_dir_all(parent).map_err(|_| "ATTESTATION_OUTPUT_UNWRITABLE")?;
    let temporary = path.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|_| "ATTESTATION_OUTPUT_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "ATTESTATION_OUTPUT_UNWRITABLE")?;
    #[cfg(unix)]
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|_| "ATTESTATION_OUTPUT_UNWRITABLE")?;
    fs::rename(&temporary, path).map_err(|_| "ATTESTATION_OUTPUT_UNWRITABLE")?;
    Ok(())
}
