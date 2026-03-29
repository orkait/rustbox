use rustbox::config::loader::{LanguageConfig, RustBoxConfig};
use rustbox::config::profile::{resolve_limits, ResolvedLimits, SecurityProfile};
use rustbox::config::types::{ExecutionResult, IsolateConfig};
use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_subsystems() {
    INIT.call_once(|| {
        let _ = rustbox::observability::audit::init_security_logger(None);
    });
}

pub fn load_config(profile: SecurityProfile) -> &'static RustBoxConfig {
    RustBoxConfig::cached_for_profile(profile).expect("config file must be present")
}

pub fn resolve_for_language(
    profile: SecurityProfile,
    config: &RustBoxConfig,
    language: &str,
) -> (LanguageConfig, ResolvedLimits) {
    let lang = config
        .get_language_config(language)
        .unwrap_or_else(|| panic!("language '{}' must be in config", language))
        .clone();
    let resolved = resolve_limits(profile, &lang.limits, None, None, None, None, None);
    (lang, resolved)
}

pub fn build_isolate(
    profile: SecurityProfile,
    language: &str,
    strict: bool,
) -> (Isolate, LanguageConfig) {
    init_subsystems();
    let config = load_config(profile);
    let (lang, resolved) = resolve_for_language(profile, &config, language);
    let mut ic = IsolateConfig::from_language_config(
        &lang,
        &config.sandbox,
        &resolved,
        format!("test/{}", language),
    );
    ic.strict_mode = strict;
    let isolate = Isolate::new(ic).expect("Isolate::new failed");
    (isolate, lang)
}

pub fn run_code(
    profile: SecurityProfile,
    language: &str,
    code: &str,
    strict: bool,
) -> ExecutionResult {
    let (mut isolate, lang) = build_isolate(profile, language, strict);
    let result = isolate
        .execute_code_string(language, code, &lang, &ExecutionOverrides::default())
        .expect("execute_code_string failed");
    let _ = isolate.cleanup();
    result
}

pub fn run_code_with_stdin(
    profile: SecurityProfile,
    language: &str,
    code: &str,
    stdin: &str,
    strict: bool,
) -> ExecutionResult {
    let (mut isolate, lang) = build_isolate(profile, language, strict);
    let overrides = ExecutionOverrides {
        stdin_data: Some(stdin.to_string()),
        ..ExecutionOverrides::default()
    };
    let result = isolate
        .execute_code_string(language, code, &lang, &overrides)
        .expect("execute_code_string failed");
    let _ = isolate.cleanup();
    result
}

pub fn run_code_with_overrides(
    profile: SecurityProfile,
    language: &str,
    code: &str,
    strict: bool,
    overrides: ExecutionOverrides,
) -> ExecutionResult {
    let (mut isolate, lang) = build_isolate(profile, language, strict);
    let result = isolate
        .execute_code_string(language, code, &lang, &overrides)
        .expect("execute_code_string failed");
    let _ = isolate.cleanup();
    result
}

pub fn run_code_with_evidence(
    profile: SecurityProfile,
    language: &str,
    code: &str,
    strict: bool,
) -> (
    ExecutionResult,
    Option<rustbox::sandbox::types::LaunchEvidence>,
) {
    let (mut isolate, lang) = build_isolate(profile, language, strict);
    let result = isolate
        .execute_code_string(language, code, &lang, &ExecutionOverrides::default())
        .expect("execute_code_string failed");
    let evidence = isolate.take_last_launch_evidence();
    let _ = isolate.cleanup();
    (result, evidence)
}
