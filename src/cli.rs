use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliMode {
    Compat,
    Isolate,
    Judge,
}

impl CliMode {
    fn primary_binary(self) -> &'static str {
        match self {
            Self::Compat => "rustbox",
            Self::Isolate => "isolate",
            Self::Judge => "judge",
        }
    }

    fn mode_name(self) -> &'static str {
        match self {
            Self::Compat => "compat",
            Self::Isolate => "isolate",
            Self::Judge => "judge",
        }
    }

    fn allows(self, command: &Commands) -> bool {
        match self {
            Self::Compat => true,
            Self::Isolate => matches!(
                command,
                Commands::ExecuteCode { .. } | Commands::CheckDeps { .. } | Commands::Status
            ),
            Self::Judge => matches!(
                command,
                Commands::ExecuteCode { .. } | Commands::CheckDeps { .. } | Commands::Status
            ),
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, hide = true)]
    internal_role: Option<String>,
    #[arg(long, hide = true)]
    launch_fd: Option<i32>,
    #[arg(long, hide = true)]
    status_fd: Option<i32>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    ExecuteCode {
        #[arg(long)]
        language: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        stdin: Option<String>,
        #[arg(long)]
        mem: Option<u64>,
        #[arg(long)]
        time: Option<u64>,
        #[arg(long)]
        cpu: Option<u64>,
        #[arg(long)]
        wall_time: Option<u64>,
        #[arg(long)]
        processes: Option<u32>,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        permissive: bool,
        #[arg(long)]
        no_seccomp: bool,
        #[arg(long)]
        seccomp_policy: Option<String>,
        #[arg(long, default_value = "judge")]
        profile: String,
        #[arg(long, value_delimiter = ',')]
        dns: Option<Vec<String>>,
    },
    Status,
    CheckDeps {
        #[arg(long)]
        verbose: bool,
    },
}

impl Commands {
    fn command_name(&self) -> &'static str {
        match self {
            Self::ExecuteCode { .. } => "execute-code",
            Self::Status => "status",
            Self::CheckDeps { .. } => "check-deps",
        }
    }
}

fn validate_command_mode(mode: CliMode, command: &Commands) {
    if mode.allows(command) {
        return;
    }

    eprintln!(
        "Error: command '{}' is not available in '{}' mode",
        command.command_name(),
        mode.mode_name()
    );

    match mode {
        CliMode::Compat => {}
        CliMode::Isolate => {
            eprintln!(
                "Use '{}' for language-adapter commands like 'execute-code' and 'check-deps'.",
                CliMode::Judge.primary_binary()
            );
        }
        CliMode::Judge => {
            eprintln!(
                "Use '{}' for sandbox lifecycle commands like 'init', 'run', 'status', and 'cleanup'.",
                CliMode::Isolate.primary_binary()
            );
        }
    }

    std::process::exit(2);
}

extern "C" fn signal_handler(sig: i32) {
    crate::kernel::signal::request_shutdown(sig);
}

fn setup_signal_handlers() {
    // SAFETY: signal_handler only performs atomic stores (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as usize);
        libc::signal(libc::SIGINT, signal_handler as *const () as usize);
    }
}

fn maybe_exit_on_pending_signal() {
    let sig = crate::kernel::signal::received_signal();
    if sig == 0 {
        return;
    }

    eprintln!("Signal {} received; exiting", sig);
    std::process::exit(128 + sig as i32);
}

pub fn run(mode: CliMode) -> Result<()> {
    setup_signal_handlers();

    env_logger::init();

    if let Err(e) = crate::observability::audit::init_security_logger(None) {
        eprintln!("Failed to initialize security logger: {}", e);
        std::process::exit(1);
    }

    if !cfg!(unix) {
        eprintln!("Error: rustbox requires Unix-like systems for security features");
        eprintln!("Current platform does not support necessary isolation mechanisms");
        std::process::exit(1);
    }

    let cli = Cli::parse();
    if let Some(role) = cli.internal_role.as_deref() {
        if role == "proxy" {
            let launch_fd = cli.launch_fd.ok_or_else(|| {
                anyhow::anyhow!("--launch-fd is required for --internal-role=proxy")
            })?;
            let status_fd = cli.status_fd.ok_or_else(|| {
                anyhow::anyhow!("--status-fd is required for --internal-role=proxy")
            })?;
            return crate::sandbox::proxy::run_proxy_role(launch_fd, status_fd).map_err(Into::into);
        }
        return Err(anyhow::anyhow!("unsupported internal role: {}", role));
    }

    let command = cli
        .command
        .ok_or_else(|| anyhow::anyhow!("missing command"))?;
    validate_command_mode(mode, &command);

    if unsafe { libc::getuid() } != 0 {
        eprintln!(
            "Warning: {} may require root privileges for full functionality",
            mode.primary_binary()
        );
        eprintln!("Running without root may limit:");
        eprintln!("  - Cgroups resource enforcement");
        eprintln!("  - Namespace isolation capabilities");
        eprintln!("  - Chroot directory creation");
    }

    crate::judge::checks::perform_security_checks();

    match crate::kernel::network::setup_bridge() {
        Ok(()) => eprintln!("✅ network bridge ready - executor profile available"),
        Err(e) => eprintln!(
            "⚠️  Network bridge setup failed: {} (executor profile will not work)",
            e
        ),
    }

    maybe_exit_on_pending_signal();

    let command_result = match command {
        Commands::ExecuteCode {
            language,
            code,
            stdin,
            mem,
            time,
            cpu,
            wall_time,
            processes,
            strict,
            permissive,
            no_seccomp,
            seccomp_policy,
            profile,
            dns,
        } => {
            if strict && permissive {
                eprintln!("Error: --strict and --permissive are mutually exclusive");
                std::process::exit(1);
            }
            let strict = !permissive;
            let is_root = unsafe { libc::getuid() } == 0;

            if !is_root {
                eprintln!("Error: rustbox requires root privileges for sandbox isolation");
                std::process::exit(1);
            }

            let language = match language.to_lowercase().as_str() {
                "py" => "python".to_string(),
                "cc" | "c++" => "cpp".to_string(),
                "js" => "javascript".to_string(),
                "ts" => "typescript".to_string(),
                "rs" => "rust".to_string(),
                other => other.to_string(),
            };

            let security_profile = match profile.to_lowercase().as_str() {
                "judge" => crate::config::profile::SecurityProfile::Judge,
                "executor" => crate::config::profile::SecurityProfile::Executor,
                other => {
                    eprintln!(
                        "Error: unknown profile '{}'. Use 'judge' or 'executor'",
                        other
                    );
                    std::process::exit(1);
                }
            };

            let resolved = crate::config::profile::resolve_limits(
                security_profile,
                None,
                wall_time.or(time),
                cpu,
                mem,
                processes,
                dns,
            );

            let mode_label = if strict { "STRICT" } else { "ROOT" };
            eprintln!(
                "Executing {} code ({}, profile={:?}{})",
                language,
                mode_label,
                security_profile,
                if resolved.was_capped {
                    ", limits capped"
                } else {
                    ""
                }
            );

            let mut config = crate::config::types::IsolateConfig::with_language_defaults(
                &language,
                crate::config::constants::DEFAULT_INSTANCE_ID.to_string(),
            )?;
            config.strict_mode = strict;
            config.no_seccomp = no_seccomp;
            config.seccomp_policy_file = seccomp_policy.map(std::path::PathBuf::from);
            config.wall_time_limit = Some(resolved.wall_time);
            config.cpu_time_limit = Some(resolved.cpu_time);
            config.memory_limit = Some(resolved.memory_bytes);
            config.process_limit = Some(resolved.process_limit);
            config.packages_enabled = resolved.packages;
            config.network_enabled = resolved.network;
            config.net_egress_bytes = resolved.net_egress_bytes;
            config.net_ingress_bytes = resolved.net_ingress_bytes;
            config.dns_servers = resolved.dns_servers.clone();

            let mut isolate = crate::runtime::isolate::Isolate::new(config)?;

            let overrides = crate::runtime::isolate::ExecutionOverrides {
                stdin_data: stdin.clone(),
                max_cpu: cpu.or(time),
                max_memory: mem,
                max_time: time,
                max_wall_time: wall_time,
                fd_limit: None,
                process_limit: processes,
            };
            let execution_outcome: anyhow::Result<crate::config::types::ExecutionStatus> =
                match isolate.execute_code_string(&language, &code, &overrides) {
                    Ok(result) => {
                        emit_execution_result(&mut isolate, &result, Some(&language), &overrides)
                    }
                    Err(err) => Err(err.into()),
                };

            let _ = isolate.cleanup();

            let reported_status = execution_outcome?;
            if reported_status != crate::config::types::ExecutionStatus::Ok {
                std::process::exit(1);
            }

            Ok(())
        }
        Commands::Status => {
            let json_result = serde_json::json!({
                "status": "OK",
                "pool_active": crate::safety::uid_pool::active_count(),
                "pool_capacity": 1000,
            });
            println!("{}", serde_json::to_string_pretty(&json_result)?);
            Ok(())
        }
        Commands::CheckDeps { verbose } => {
            check_language_dependencies(verbose, mode.primary_binary())
        }
    };

    maybe_exit_on_pending_signal();
    command_result
}

fn emit_execution_result(
    isolate: &mut crate::runtime::isolate::Isolate,
    result: &crate::config::types::ExecutionResult,
    language: Option<&str>,
    overrides: &crate::runtime::isolate::ExecutionOverrides,
) -> Result<crate::config::types::ExecutionStatus> {
    let output_config =
        crate::runtime::isolate::apply_overrides_to_config(isolate.config(), overrides);
    let launch_evidence = isolate.take_last_launch_evidence();
    crate::judge::envelope::emit_judge_json(
        result,
        &output_config,
        language,
        launch_evidence.as_ref(),
    )
}

fn check_language_dependencies(verbose: bool, primary_binary: &str) -> Result<()> {
    use std::process::Command;

    println!("🔍 Checking language dependencies...");
    println!();

    let mut all_ok = true;
    let mut missing_languages = Vec::new();

    let languages = [
        ("Python", vec![("python3", "--version")]),
        ("C++", vec![("gcc", "--version"), ("g++", "--version")]),
        ("Java", vec![("java", "-version"), ("javac", "-version")]),
        ("JavaScript/TypeScript", vec![("bun", "--version")]),
    ];

    for (lang_name, commands) in &languages {
        let mut lang_ok = true;
        let mut versions = Vec::new();

        for (cmd, version_arg) in commands {
            match Command::new(cmd).arg(version_arg).output() {
                Ok(output) => {
                    if output.status.success() {
                        let version_info = if !output.stdout.is_empty() {
                            String::from_utf8_lossy(&output.stdout)
                        } else {
                            String::from_utf8_lossy(&output.stderr)
                        }
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();

                        if verbose {
                            versions.push(format!("  {} -> {}", cmd, version_info.trim()));
                        }
                    } else {
                        lang_ok = false;
                        if verbose {
                            versions.push(format!("  {} -> FAILED", cmd));
                        }
                    }
                }
                Err(_) => {
                    lang_ok = false;
                    if verbose {
                        versions.push(format!("  {} -> NOT FOUND", cmd));
                    }
                }
            }
        }

        if lang_ok {
            println!("✅ {} - OK", lang_name);
            if verbose {
                for version in versions {
                    println!("{}", version);
                }
            }
        } else {
            println!("❌ {} - MISSING", lang_name);
            if verbose {
                for version in versions {
                    println!("{}", version);
                }
            }
            missing_languages.push(*lang_name);
            all_ok = false;
        }

        if verbose {
            println!();
        }
    }

    println!();

    if all_ok {
        println!("🎉 All language dependencies are installed!");
        println!("✅ RustBox is ready to use");

        if verbose {
            println!();
            println!("💡 Usage examples:");
            println!(
                "  {} execute-code --strict --box-id=1 --language=python --code='print(\"Hello World\")'",
                primary_binary
            );
            println!(
                "  {} execute-code --strict --box-id=2 --language=cpp --processes=10 --code='#include<iostream>...'",
                primary_binary
            );
        }

        Ok(())
    } else {
        println!(
            "❌ Missing language dependencies: {}",
            missing_languages.join(", ")
        );
        println!();
        println!("🔧 To install missing languages, run:");
        println!("   ./setup_languages.sh");
        println!();
        println!("Or install manually:");

        for lang in &missing_languages {
            match *lang {
                "Python" => println!("  • Python: sudo apt install python3 python3-pip"),
                "C++" => println!("  • C++: sudo apt install build-essential gcc g++"),
                "Java" => println!("  • Java: sudo apt install openjdk-21-jdk-headless"),
                "JavaScript/TypeScript" => {
                    println!("  • Bun runtime: curl -fsSL https://bun.sh/install | bash")
                }
                _ => {}
            }
        }

        std::process::exit(1);
    }
}
