//! `riftengine-host build`: check community packs against the rules and build the overlay.
//! `riftengine-host watch`: wait for the game, load the engine DLL into it and serve that
//! overlay. Both print what happens as one JSON object per line.

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use riftengine_host::attach::{self, AttachError, Options};
use riftengine_host::{Event, overlay, watch};
use riftengine_core::proto::flags;

const USAGE: &str = "\
usage:
  riftengine-host build --game-dir <dir> --overlay <dir> <pack.fantome>...
  riftengine-host watch --game-dir <dir> --overlay <dir> [--dll <path>] [--once]
                             [--max-age-ms <n>] [--timeout-ms <n>] [--dry-run]
  riftengine-host rules

build takes the packs highest priority first, and replaces whatever overlay is in --overlay.";

fn emit(event: &Event) {
    let line = serde_json::to_string(event).expect("events serialise");
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

struct Args {
    game_dir: PathBuf,
    overlay: PathBuf,
    dll: PathBuf,
    once: bool,
    max_age_ms: u64,
    timeout_ms: u64,
    dry_run: bool,
}

fn parse(args: Vec<String>) -> Result<Args, String> {
    let mut game_dir = None;
    let mut overlay = None;
    let mut dll = None;
    let mut once = false;
    let mut dry_run = false;
    let mut max_age_ms = 15_000;
    let mut timeout_ms = 20_000;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--game-dir" => game_dir = Some(PathBuf::from(value("--game-dir")?)),
            "--overlay" => overlay = Some(PathBuf::from(value("--overlay")?)),
            "--dll" => dll = Some(PathBuf::from(value("--dll")?)),
            "--max-age-ms" => max_age_ms = value("--max-age-ms")?.parse().map_err(|e| format!("--max-age-ms: {e}"))?,
            "--timeout-ms" => timeout_ms = value("--timeout-ms")?.parse().map_err(|e| format!("--timeout-ms: {e}"))?,
            "--once" => once = true,
            "--dry-run" => dry_run = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let dll = match dll {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .with_file_name("riftengine_dll.dll"),
    };
    Ok(Args {
        game_dir: game_dir.ok_or("--game-dir is required")?,
        overlay: overlay.ok_or("--overlay is required")?,
        dll,
        once,
        max_age_ms,
        timeout_ms,
        dry_run,
    })
}

fn watch_games(args: Args) -> ExitCode {
    let opts = Options {
        game_dir: args.game_dir.clone(),
        overlay_root: args.overlay,
        dll: args.dll,
        max_process_age_ms: args.max_age_ms,
        flags: if args.dry_run { flags::DRY_RUN } else { 0 },
        timeout: Duration::from_millis(args.timeout_ms),
    };
    if let Err(message) = attach::preflight(&opts) {
        emit(&Event::Failed { pid: 0, message });
        return ExitCode::from(2);
    }
    emit(&Event::Waiting { game_dir: args.game_dir.to_string_lossy().into_owned() });
    let mut handled = HashSet::new();
    loop {
        match watch::find_games(&args.game_dir) {
            Ok(games) => {
                for game in games {
                    if !handled.insert(game.pid) {
                        continue;
                    }
                    emit(&Event::Found { pid: game.pid, age_ms: game.age_ms });
                    let result = attach::attach(&opts, &game, &mut |event| emit(&event));
                    let failed = match result {
                        Ok(()) => false,
                        Err(AttachError::Refused(reason)) => {
                            emit(&Event::Refused { pid: game.pid, reason });
                            true
                        }
                        Err(other) => {
                            emit(&Event::Failed { pid: game.pid, message: other.to_string() });
                            true
                        }
                    };
                    if args.once {
                        return if failed { ExitCode::from(2) } else { ExitCode::SUCCESS };
                    }
                }
            }
            Err(e) => {
                emit(&Event::Failed { pid: 0, message: format!("cannot list processes: {e}") });
                if args.once {
                    return ExitCode::from(2);
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

struct BuildArgs {
    game_dir: PathBuf,
    overlay: PathBuf,
    packs: Vec<PathBuf>,
}

fn parse_build(args: Vec<String>) -> Result<BuildArgs, String> {
    let mut game_dir = None;
    let mut overlay = None;
    let mut packs = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--game-dir" => game_dir = Some(PathBuf::from(it.next().ok_or("--game-dir needs a value")?)),
            "--overlay" => overlay = Some(PathBuf::from(it.next().ok_or("--overlay needs a value")?)),
            flag if flag.starts_with("--") => return Err(format!("unknown argument {flag}")),
            _ => packs.push(PathBuf::from(&arg)),
        }
    }
    if packs.is_empty() {
        return Err("no pack given".into());
    }
    Ok(BuildArgs {
        game_dir: game_dir.ok_or("--game-dir is required")?,
        overlay: overlay.ok_or("--overlay is required")?,
        packs,
    })
}

fn build_overlay(args: BuildArgs) -> ExitCode {
    let options = overlay::Options { game_dir: &args.game_dir, overlay_root: &args.overlay, packs: &args.packs };
    match overlay::build(&options, &mut |event| emit(&event)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            // A refusal has been reported pack by pack already; this is the verdict.
            emit(&Event::Failed { pid: 0, message: error.to_string() });
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => match parse_build(args.collect()) {
            Ok(parsed) => build_overlay(parsed),
            Err(message) => {
                eprintln!("{message}\n{USAGE}");
                ExitCode::from(64)
            }
        },
        Some("watch") => match parse(args.collect()) {
            Ok(parsed) => watch_games(parsed),
            Err(message) => {
                eprintln!("{message}\n{USAGE}");
                ExitCode::from(64)
            }
        },
        Some("rules") => {
            println!("rule set {} ({})", riftengine_rules::RULESET_VERSION, riftengine_rules::digest());
            println!(
                "end of life: a game linked at or after {} is refused",
                riftengine_rules::utc(riftengine_rules::END_OF_LIFE)
            );
            for rule in riftengine_rules::RULES {
                println!("{:<18} {:<8} {}", rule.id, rule.clause, rule.summary);
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(64)
        }
    }
}
