//! TraceDesk native command-line utility and benchmark driver (`tracedesk-cli`):
//! - `verify-bundle <zip_path> [--sha256 <hex64>]`: standalone verifiable review bundle checker
//! - `run-demo [--cases-dir <dir>] [--evidence <path>]`: full closed-loop forensic demo workflow
//! - `make-demo [--out-dir <dir>]`: deterministic pure-Rust FAT16 demo image generator
//! - `bench [--json-out <path>]`: native Rust performance benchmark suite & Python speedup comparison

pub mod bench;
pub mod demo;
pub mod make_demo;
pub mod verify;

use std::path::PathBuf;

use tracedesk_core::{CoreError, CoreResult};

pub use bench::{RustBenchReport, make_synthetic_entries, run_bench_command};
pub use demo::{DemoRunSummary, DemoTimings, run_demo_command};
pub use make_demo::{
    DemoFileDigest, DemoImageManifest, EXPECTED_DEMO_DD_SHA256, EXPECTED_DEMO_VOLUME_DD_SHA256,
    MakeDemoSummary, build_demo_image_bytes, create_demo_image, create_demo_image_with_deleted,
    run_make_demo_command,
};
pub use verify::{run_verify_bundle_command, verify_bundle_strict};

/// Parsed CLI subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    VerifyBundle {
        zip_path: PathBuf,
        sha256: Option<String>,
    },
    RunDemo {
        cases_dir: Option<PathBuf>,
        evidence: Option<PathBuf>,
    },
    MakeDemo {
        out_dir: Option<PathBuf>,
    },
    Bench {
        json_out: Option<PathBuf>,
    },
    Help,
    Version,
}

/// Usage help text in Chinese.
pub fn usage_text() -> &'static str {
    "TraceDesk 原生取证命令行工具与性能基准套件 (tracedesk-cli)\n\
     \n\
     用法:\n\
       tracedesk-cli verify-bundle <zip_path> [--sha256 <hex64>]\n\
       tracedesk-cli run-demo [--cases-dir <dir>] [--evidence <path>]\n\
       tracedesk-cli make-demo [--out-dir <dir>]\n\
       tracedesk-cli bench [--json-out <path>]\n\
     \n\
     子命令:\n\
       verify-bundle  独立核验复核包 ZIP、SHA256SUMS.json、manifest.json、report.md 与审计哈希链\n\
       run-demo       使用 evidence/demo.dd 执行完整取证演示闭环并更新 logs/latest-demo.txt\n\
       make-demo      纯 Rust 生成确定性 FAT16 演示镜像 (demo.dd 与 demo_volume.dd)\n\
       bench          运行原生 Rust 性能基准测试并与 Python 基线对比计算加速比"
}

fn next_flag_value(
    flag: &str,
    inline: Option<&str>,
    iter: &mut std::slice::Iter<'_, String>,
) -> CoreResult<String> {
    if let Some(val) = inline {
        if val.is_empty() {
            return Err(CoreError::InvalidInput(format!("参数 {flag} 缺少取值")));
        }
        return Ok(val.to_string());
    }
    match iter.next() {
        Some(v) if !v.is_empty() => Ok(v.clone()),
        _ => Err(CoreError::InvalidInput(format!("参数 {flag} 缺少取值"))),
    }
}

fn split_flag(arg: &str) -> (&str, Option<&str>) {
    if let Some((k, v)) = arg.split_once('=') {
        (k, Some(v))
    } else {
        (arg, None)
    }
}

/// Parse command-line arguments (excluding `argv[0]`) into a [`CliCommand`].
pub fn parse_cli_args(args: &[String]) -> CoreResult<CliCommand> {
    let Some(first) = args.first() else {
        return Ok(CliCommand::Help);
    };

    match first.as_str() {
        "-h" | "--help" | "help" => Ok(CliCommand::Help),
        "-V" | "--version" | "version" => Ok(CliCommand::Version),
        "verify-bundle" | "verify_bundle" => {
            let mut zip_path: Option<PathBuf> = None;
            let mut sha256: Option<String> = None;
            let mut iter = args[1..].iter();
            while let Some(arg) = iter.next() {
                if arg == "-h" || arg == "--help" {
                    return Ok(CliCommand::Help);
                }
                let (flag, inline) = split_flag(arg);
                match flag {
                    "--sha256" => {
                        sha256 = Some(next_flag_value("--sha256", inline, &mut iter)?);
                    }
                    s if s.starts_with('-') => {
                        return Err(CoreError::InvalidInput(format!(
                            "verify-bundle 不支持的参数：{arg}"
                        )));
                    }
                    positional => {
                        if zip_path.is_some() {
                            return Err(CoreError::InvalidInput(format!(
                                "verify-bundle 多余的位置参数：{positional}"
                            )));
                        }
                        zip_path = Some(PathBuf::from(positional));
                    }
                }
            }
            let zip_path = zip_path.ok_or_else(|| {
                CoreError::InvalidInput("verify-bundle 缺少复核包 <zip_path> 参数".to_string())
            })?;
            Ok(CliCommand::VerifyBundle { zip_path, sha256 })
        }
        "run-demo" | "run_demo" => {
            let mut cases_dir: Option<PathBuf> = None;
            let mut evidence: Option<PathBuf> = None;
            let mut iter = args[1..].iter();
            while let Some(arg) = iter.next() {
                if arg == "-h" || arg == "--help" {
                    return Ok(CliCommand::Help);
                }
                let (flag, inline) = split_flag(arg);
                match flag {
                    "--cases-dir" => {
                        cases_dir = Some(PathBuf::from(next_flag_value(
                            "--cases-dir",
                            inline,
                            &mut iter,
                        )?));
                    }
                    "--evidence" => {
                        evidence = Some(PathBuf::from(next_flag_value(
                            "--evidence",
                            inline,
                            &mut iter,
                        )?));
                    }
                    "--gui" => {
                        // Ignore legacy `--gui` flag gracefully for script compatibility.
                    }
                    other => {
                        return Err(CoreError::InvalidInput(format!(
                            "run-demo 不支持的参数：{other}"
                        )));
                    }
                }
            }
            Ok(CliCommand::RunDemo {
                cases_dir,
                evidence,
            })
        }
        "make-demo" | "make_demo" => {
            let mut out_dir: Option<PathBuf> = None;
            let mut iter = args[1..].iter();
            while let Some(arg) = iter.next() {
                if arg == "-h" || arg == "--help" {
                    return Ok(CliCommand::Help);
                }
                let (flag, inline) = split_flag(arg);
                match flag {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_flag_value(
                            "--out-dir",
                            inline,
                            &mut iter,
                        )?));
                    }
                    other => {
                        return Err(CoreError::InvalidInput(format!(
                            "make-demo 不支持的参数：{other}"
                        )));
                    }
                }
            }
            Ok(CliCommand::MakeDemo { out_dir })
        }
        "bench" => {
            let mut json_out: Option<PathBuf> = None;
            let mut iter = args[1..].iter();
            while let Some(arg) = iter.next() {
                if arg == "-h" || arg == "--help" {
                    return Ok(CliCommand::Help);
                }
                let (flag, inline) = split_flag(arg);
                match flag {
                    "--json-out" => {
                        json_out = Some(PathBuf::from(next_flag_value(
                            "--json-out",
                            inline,
                            &mut iter,
                        )?));
                    }
                    other => {
                        return Err(CoreError::InvalidInput(format!(
                            "bench 不支持的参数：{other}"
                        )));
                    }
                }
            }
            Ok(CliCommand::Bench { json_out })
        }
        unknown => Err(CoreError::InvalidInput(format!(
            "未知子命令：{unknown}\n\n{}",
            usage_text()
        ))),
    }
}

/// Execute a parsed [`CliCommand`].
pub fn execute_command(cmd: CliCommand) -> CoreResult<()> {
    match cmd {
        CliCommand::Help => {
            println!("{}", usage_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("tracedesk-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::VerifyBundle { zip_path, sha256 } => {
            let msg = run_verify_bundle_command(&zip_path, sha256.as_deref())?;
            println!("{msg}");
            Ok(())
        }
        CliCommand::RunDemo {
            cases_dir,
            evidence,
        } => {
            run_demo_command(cases_dir.as_deref(), evidence.as_deref())?;
            Ok(())
        }
        CliCommand::MakeDemo { out_dir } => {
            run_make_demo_command(out_dir.as_deref())?;
            Ok(())
        }
        CliCommand::Bench { json_out } => {
            run_bench_command(json_out.as_deref())?;
            Ok(())
        }
    }
}

/// Top-level CLI runner taking raw argument strings (excluding `argv[0]`).
pub fn run_cli(args: &[String]) -> CoreResult<()> {
    let cmd = parse_cli_args(args)?;
    execute_command(cmd)
}
