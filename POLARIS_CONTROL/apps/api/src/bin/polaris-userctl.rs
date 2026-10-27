use polaris_control_api::provision_user;
use rand_core::{OsRng, RngCore};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn usage() -> ! {
    eprintln!("usage: polaris-userctl provision --username NAME --role operator|administrator [--password-stdin | --generated-password-file PATH]");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) != Some("provision") {
        usage();
    }
    let value = |flag: &str| {
        args.iter()
            .position(|item| item == flag)
            .and_then(|index| args.get(index + 1))
            .cloned()
            .unwrap_or_else(|| usage())
    };
    let username = value("--username");
    let role = value("--role");
    let generated_password_file = args
        .iter()
        .position(|item| item == "--generated-password-file")
        .and_then(|index| args.get(index + 1))
        .cloned();
    let password = if generated_password_file.is_some() {
        let mut value = [0_u8; 24];
        OsRng.fill_bytes(&mut value);
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    } else if args.iter().any(|item| item == "--password-stdin") {
        let mut password = String::new();
        io::stdin()
            .read_to_string(&mut password)
            .unwrap_or_else(|_| usage());
        password.trim_end_matches(['\r', '\n']).to_string()
    } else {
        let first = rpassword::prompt_password("Password: ").unwrap_or_else(|_| usage());
        let second = rpassword::prompt_password("Confirm password: ").unwrap_or_else(|_| usage());
        if first != second {
            eprintln!("passwords do not match");
            std::process::exit(2);
        }
        first
    };
    let path = env::var("POLARIS_USERS_PATH")
        .unwrap_or_else(|_| "/var/lib/polaris-control/users.json".into());
    if let Err(error) = provision_user(Path::new(&path), &username, &role, &password) {
        eprintln!("provisioning failed: {error}");
        std::process::exit(1);
    }
    if let Some(output) = generated_password_file {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&output).unwrap_or_else(|error| {
            eprintln!("password file creation failed: {error}");
            std::process::exit(1)
        });
        use std::io::Write;
        writeln!(file, "{password}").unwrap_or_else(|error| {
            eprintln!("password file write failed: {error}");
            std::process::exit(1)
        });
        println!("initial password written with mode 0600 to {output}");
    }
    println!("provisioned {username} with role {role}");
}
