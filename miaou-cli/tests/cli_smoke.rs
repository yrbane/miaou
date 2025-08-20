// miaou-cli/tests/cli_smoke.rs
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn prints_version_and_mode() {
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn shows_help_and_subcommands() {
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"))
        .stdout(predicate::str::contains("profile"))
        .stdout(predicate::str::contains("crypto-test"));
}

#[test]
fn bad_subcommand_returns_error_code() {
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();
    cmd.arg("not-a-real-subcommand").assert().failure();
}
