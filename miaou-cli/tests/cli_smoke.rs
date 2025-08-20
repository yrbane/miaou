// miaou-cli/tests/cli_smoke.rs
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn prints_version_and_mode() {
    let mut cmd = Command::cargo_bin("miaou").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Miaou v"))
        .stdout(predicate::str::contains("Version"));
}

#[test]
fn shows_help_and_subcommands() {
    let mut cmd = Command::cargo_bin("miaou").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"))
        .stdout(predicate::str::contains("CreateProfile"))
        .stdout(predicate::str::contains("SecurityAudit"));
}

#[test]
fn bad_subcommand_returns_error_code() {
    let mut cmd = Command::cargo_bin("miaou").unwrap();
    cmd.arg("not-a-real-subcommand").assert().failure();
}
