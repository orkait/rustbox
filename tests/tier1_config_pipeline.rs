mod common;

use rustbox::config::constants;
use rustbox::config::loader::normalize_language;
use rustbox::config::profile::{resolve_limits, SecurityProfile};
use rustbox::config::types::IsolateConfig;
use rustbox::config::validation::validate_dns_servers;

const EXPECTED_LANGUAGES: &[&str] = &[
    "python",
    "java",
    "javascript",
    "typescript",
    "cpp",
    "c",
    "go",
    "rust",
];
const COMPILED_LANGUAGES: &[&str] = &["cpp", "c", "java", "go", "rust"];
const INTERPRETED_LANGUAGES: &[&str] = &["python", "javascript", "typescript"];

#[test]
fn judge_config_loads_all_languages() {
    let config = common::load_config(SecurityProfile::Judge);
    for lang in EXPECTED_LANGUAGES {
        let lc = config
            .get_language_config(lang)
            .unwrap_or_else(|| panic!("judge config must contain language '{}'", lang));
        assert!(lc.limits.memory_mb > 0, "{}: memory_mb must be > 0", lang);
        assert!(
            lc.limits.cpu_time_sec > 0,
            "{}: cpu_time_sec must be > 0",
            lang
        );
        assert!(
            lc.limits.wall_time_sec > 0,
            "{}: wall_time_sec must be > 0",
            lang
        );
        assert!(
            lc.limits.max_processes > 0,
            "{}: max_processes must be > 0",
            lang
        );
        assert!(
            lc.limits.max_open_files > 0,
            "{}: max_open_files must be > 0",
            lang
        );
    }
}

#[test]
fn executor_config_loads_all_languages() {
    let config = common::load_config(SecurityProfile::Executor);
    for lang in EXPECTED_LANGUAGES {
        let lc = config
            .get_language_config(lang)
            .unwrap_or_else(|| panic!("executor config must contain language '{}'", lang));
        assert!(lc.limits.memory_mb > 0, "{}: memory_mb must be > 0", lang);
        assert!(
            lc.limits.wall_time_sec > 0,
            "{}: wall_time_sec must be > 0",
            lang
        );
    }
}

#[test]
fn executor_limits_exceed_judge_for_all_languages() {
    let judge = common::load_config(SecurityProfile::Judge);
    let executor = common::load_config(SecurityProfile::Executor);
    for lang in EXPECTED_LANGUAGES {
        let (_, j_resolved) = common::resolve_for_language(SecurityProfile::Judge, &judge, lang);
        let (_, e_resolved) =
            common::resolve_for_language(SecurityProfile::Executor, &executor, lang);
        assert!(
            e_resolved.memory_bytes >= j_resolved.memory_bytes,
            "{}: executor memory ({}) must be >= judge memory ({})",
            lang,
            e_resolved.memory_bytes,
            j_resolved.memory_bytes
        );
        assert!(
            e_resolved.wall_time >= j_resolved.wall_time,
            "{}: executor wall_time ({:?}) must be >= judge wall_time ({:?})",
            lang,
            e_resolved.wall_time,
            j_resolved.wall_time
        );
        assert!(
            e_resolved.cpu_time >= j_resolved.cpu_time,
            "{}: executor cpu_time ({:?}) must be >= judge cpu_time ({:?})",
            lang,
            e_resolved.cpu_time,
            j_resolved.cpu_time
        );
        assert!(
            e_resolved.process_limit >= j_resolved.process_limit,
            "{}: executor process_limit ({}) must be >= judge process_limit ({})",
            lang,
            e_resolved.process_limit,
            j_resolved.process_limit
        );
    }
}

#[test]
fn executor_enables_network_judge_does_not() {
    for lang in EXPECTED_LANGUAGES {
        let judge_config = common::load_config(SecurityProfile::Judge);
        let executor_config = common::load_config(SecurityProfile::Executor);
        let (_, j_resolved) =
            common::resolve_for_language(SecurityProfile::Judge, &judge_config, lang);
        let (_, e_resolved) =
            common::resolve_for_language(SecurityProfile::Executor, &executor_config, lang);
        assert!(
            !j_resolved.network,
            "{}: judge must have network disabled",
            lang
        );
        assert!(
            e_resolved.network,
            "{}: executor must have network enabled",
            lang
        );
    }
}

#[test]
fn compiled_languages_have_compilation_config() {
    let config = common::load_config(SecurityProfile::Judge);
    for lang in COMPILED_LANGUAGES {
        let lc = config
            .get_language_config(lang)
            .unwrap_or_else(|| panic!("missing language '{}'", lang));
        assert!(
            lc.compilation.is_some(),
            "{}: compiled language must have compilation config",
            lang
        );
        let comp = lc.compilation.as_ref().unwrap();
        assert!(
            !comp.command.is_empty(),
            "{}: compilation command must not be empty",
            lang
        );
        assert!(
            !comp.source_file.is_empty(),
            "{}: compilation source_file must not be empty",
            lang
        );
    }
}

#[test]
fn interpreted_languages_lack_compilation_config() {
    let config = common::load_config(SecurityProfile::Judge);
    for lang in INTERPRETED_LANGUAGES {
        let lc = config
            .get_language_config(lang)
            .unwrap_or_else(|| panic!("missing language '{}'", lang));
        assert!(
            lc.compilation.is_none(),
            "{}: interpreted language must not have compilation config",
            lang
        );
    }
}

#[test]
fn isolate_config_from_language_config_preserves_limits() {
    let config = common::load_config(SecurityProfile::Judge);
    let (lang, resolved) = common::resolve_for_language(SecurityProfile::Judge, &config, "python");
    let ic = IsolateConfig::from_language_config(
        &lang,
        &config.sandbox,
        &resolved,
        "test/python".to_string(),
    );
    assert_eq!(ic.memory_limit, Some(resolved.memory_bytes));
    assert_eq!(ic.cpu_time_limit, Some(resolved.cpu_time));
    assert_eq!(ic.wall_time_limit, Some(resolved.wall_time));
    assert_eq!(ic.process_limit, Some(resolved.process_limit));
    assert_eq!(ic.fd_limit, Some(resolved.fd_limit));
}

#[test]
fn resolve_limits_caps_above_absolute_maximum() {
    let config = common::load_config(SecurityProfile::Judge);
    let lang = config.get_language_config("python").unwrap();
    let resolved = resolve_limits(
        SecurityProfile::Judge,
        &lang.limits,
        Some(999_999),
        Some(999_999),
        Some(999_999),
        Some(999_999),
        None,
    );
    assert!(resolved.was_capped);
    assert_eq!(resolved.wall_time, constants::MAX_ABSOLUTE_WALL_TIME);
    assert_eq!(resolved.cpu_time, constants::MAX_ABSOLUTE_CPU_TIME);
    assert_eq!(resolved.memory_bytes, constants::MAX_ABSOLUTE_MEMORY);
    assert_eq!(resolved.process_limit, constants::MAX_ABSOLUTE_PROCESSES);
}

#[test]
fn resolve_limits_zero_falls_back_to_config_defaults() {
    let config = common::load_config(SecurityProfile::Judge);
    let lang = config.get_language_config("python").unwrap();
    let resolved = resolve_limits(
        SecurityProfile::Judge,
        &lang.limits,
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        None,
    );
    assert!(!resolved.was_capped);
    assert_eq!(
        resolved.wall_time,
        std::time::Duration::from_secs(lang.limits.wall_time_sec)
    );
    assert_eq!(resolved.memory_bytes, lang.limits.memory_mb * constants::MB);
    assert_eq!(resolved.process_limit, lang.limits.max_processes);
}

#[test]
fn dns_validation_accepts_public_servers() {
    let servers = vec!["1.1.1.1".into(), "8.8.8.8".into(), "9.9.9.9".into()];
    let result = validate_dns_servers(&servers);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 3);
}

#[test]
fn dns_validation_rejects_private_ranges() {
    let private_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"];
    for ip in &private_ips {
        let result = validate_dns_servers(&[ip.to_string()]);
        assert!(result.is_err(), "{} must be rejected as a DNS server", ip);
    }
}

#[test]
fn dns_validation_rejects_invalid_addresses() {
    let invalids = ["not-an-ip", "256.1.2.3", ""];
    for addr in &invalids {
        let result = validate_dns_servers(&[addr.to_string()]);
        assert!(
            result.is_err(),
            "'{}' must be rejected as a DNS server",
            addr
        );
    }
}

#[test]
fn dns_validation_caps_at_max_entries() {
    let servers: Vec<String> = (1..=10).map(|i| format!("1.0.0.{}", i)).collect();
    let result = validate_dns_servers(&servers).unwrap();
    assert_eq!(result.len(), constants::MAX_DNS_ENTRIES);
}

#[test]
fn normalize_language_maps_all_aliases() {
    assert_eq!(normalize_language("py"), "python");
    assert_eq!(normalize_language("PY"), "python");
    assert_eq!(normalize_language("Py"), "python");
    assert_eq!(normalize_language("cc"), "cpp");
    assert_eq!(normalize_language("CC"), "cpp");
    assert_eq!(normalize_language("c++"), "cpp");
    assert_eq!(normalize_language("C++"), "cpp");
    assert_eq!(normalize_language("cxx"), "cpp");
    assert_eq!(normalize_language("CXX"), "cpp");
    assert_eq!(normalize_language("js"), "javascript");
    assert_eq!(normalize_language("JS"), "javascript");
    assert_eq!(normalize_language("ts"), "typescript");
    assert_eq!(normalize_language("TS"), "typescript");
    assert_eq!(normalize_language("rs"), "rust");
    assert_eq!(normalize_language("RS"), "rust");
    assert_eq!(normalize_language("python"), "python");
    assert_eq!(normalize_language("java"), "java");
    assert_eq!(normalize_language("go"), "go");
    assert_eq!(normalize_language("brainfuck"), "brainfuck");
    assert_eq!(normalize_language(""), "");
}
