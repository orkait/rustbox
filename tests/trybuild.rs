/// Compile-fail tests for type-state invariants
/// Implements P1-TYPESTATE-003: Compile-Fail Guardrails for Pre-Exec Invariants
///
/// These tests verify that illegal type-state transitions fail to compile,
/// proving that ordering violations are impossible at compile time.

#[test]
fn typestate_compile_fail_tests() {
    let t = trybuild::TestCases::new();

    // Test that early exec fails to compile
    t.compile_fail("tests/typestate_compile_fail/early_exec_from_fresh.rs");
    t.compile_fail("tests/typestate_compile_fail/early_exec_from_namespaces.rs");
    t.compile_fail("tests/typestate_compile_fail/early_exec_from_mounts.rs");

    // Test that skipped transitions fail to compile
    t.compile_fail("tests/typestate_compile_fail/skip_namespace_setup.rs");
    t.compile_fail("tests/typestate_compile_fail/skip_mount_hardening.rs");
    t.compile_fail("tests/typestate_compile_fail/skip_cgroup_attach.rs");

    // Test that state reuse fails to compile
    t.compile_fail("tests/typestate_compile_fail/reuse_consumed_state.rs");
}
