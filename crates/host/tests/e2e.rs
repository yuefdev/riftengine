//! End-to-end tests: a real host process hooks the real DLL into a stand-in game process
//! (`fakegame`, copied to `League of Legends.exe`) and we watch which file contents the game gets.
//!
//! Run `cargo build --workspace` first so `riftengine_dll.dll` is next to the host binary.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use riftengine_core::manifest::OverlayManifest;
use riftengine_core::pe;
use riftengine_rules::END_OF_LIFE;
use serde_json::Value;

const HOST: &str = env!("CARGO_BIN_EXE_riftengine-host");
const FAKE: &str = env!("CARGO_BIN_EXE_fakegame");
const WAIT: Duration = Duration::from_secs(30);
/// The newest game build the rules reach, which the stand-in game is linked at unless a test says
/// otherwise.
const NEWEST_COVERED: u32 = END_OF_LIFE - 1;
/// A build the rules reach as well, a day before the stand-in game was linked.
const A_DAY_EARLIER: u32 = NEWEST_COVERED - 86_400;

fn dll_path() -> PathBuf {
    static DLL: OnceLock<PathBuf> = OnceLock::new();
    DLL.get_or_init(|| {
        let dll = Path::new(HOST).with_file_name("riftengine_dll.dll");
        if !dll.exists() {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
            let mut build = Command::new(cargo);
            build.args(["build", "-p", "riftengine-dll"]);
            if HOST.contains("release") {
                build.arg("--release");
            }
            assert!(build.status().expect("cargo runs").success(), "building the DLL failed");
        }
        dll
    })
    .clone()
}

struct Tree {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    game_dir: PathBuf,
    overlay: PathBuf,
}

impl Tree {
    fn ahri_in_game(&self) -> PathBuf {
        self.game_dir.join(r"DATA\FINAL\Champions\Ahri.wad.client")
    }
}

/// Changes the link time in the headers of an executable file.
fn link_at(exe: &Path, time: u32) {
    let mut bytes = fs::read(exe).unwrap();
    let at = pe::link_time_offset(&bytes[..pe::HEAD_BYTES]).expect("the stand-in game is an executable");
    bytes[at..at + 4].copy_from_slice(&time.to_le_bytes());
    fs::write(exe, bytes).unwrap();
}

/// A game folder with two stock WADs and an overlay that replaces one of them.
fn tree() -> Tree {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let game_dir = root.join("Game");
    let overlay = root.join("overlay");
    fs::create_dir_all(game_dir.join("DATA/FINAL/Champions")).unwrap();
    fs::create_dir_all(overlay.join("DATA/FINAL/Champions")).unwrap();
    fs::copy(FAKE, game_dir.join("League of Legends.exe")).unwrap();
    link_at(&game_dir.join("League of Legends.exe"), NEWEST_COVERED);
    fs::write(game_dir.join("DATA/FINAL/Champions/Ahri.wad.client"), "ORIGINAL-AHRI").unwrap();
    fs::write(game_dir.join("DATA/FINAL/Champions/Zed.wad.client"), "ORIGINAL-ZED").unwrap();
    fs::write(overlay.join("DATA/FINAL/Champions/Ahri.wad.client"), "MODDED-AHRI").unwrap();
    Tree { _tmp: tmp, root, game_dir, overlay }
}

/// Seals the overlay as made for a game linked at `built_for`.
fn seal_for(overlay: &Path, built_for: u32) {
    OverlayManifest::scan(overlay, riftengine_rules::digest(), built_for).unwrap().write(overlay).unwrap();
}

/// Seals the overlay as made for the game `tree()` holds.
fn seal(overlay: &Path) {
    seal_for(overlay, NEWEST_COVERED);
}

fn lines_of(stdout: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

struct Host {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<Value>,
}

impl Host {
    fn start(tree: &Tree, extra: &[&str]) -> Self {
        Self::start_exe(Path::new(HOST), &dll_path(), tree, extra)
    }

    fn start_exe(exe: &Path, dll: &Path, tree: &Tree, extra: &[&str]) -> Self {
        let mut host = Self::spawn(exe, dll, tree, extra);
        host.wait_event("waiting");
        host
    }

    /// Starts the host and does not wait for it to say anything.
    fn spawn(exe: &Path, dll: &Path, tree: &Tree, extra: &[&str]) -> Self {
        let mut child = Command::new(exe)
            .args(["watch", "--once", "--timeout-ms", "20000", "--game-dir"])
            .arg(&tree.game_dir)
            .arg("--overlay")
            .arg(&tree.overlay)
            .arg("--dll")
            .arg(dll)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("host starts");
        let lines = lines_of(child.stdout.take().unwrap());
        Self { child, lines, seen: Vec::new() }
    }

    /// Blocks until an event with this name arrives and returns it.
    fn wait_event(&mut self, name: &str) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no `{name}` event; saw {:#?}", self.seen));
            let event: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad line {line:?}: {e}"));
            self.seen.push(event.clone());
            if event["event"] == name {
                return event;
            }
        }
    }

    /// Waits for either `attached` or the first failure, returning the event that arrived.
    fn wait_outcome(&mut self) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no outcome; saw {:#?}", self.seen));
            let event: Value = serde_json::from_str(&line).unwrap();
            self.seen.push(event.clone());
            if ["attached", "refused", "failed"].contains(&event["event"].as_str().unwrap_or("")) {
                return event;
            }
        }
    }

    fn finish(mut self) -> (i32, Vec<Value>) {
        let deadline = Instant::now() + WAIT;
        while let Ok(line) = self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            self.seen.push(serde_json::from_str(&line).unwrap());
        }
        let code = self.child.wait().expect("host exits").code().unwrap_or(-1);
        (code, std::mem::take(&mut self.seen))
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

struct Game {
    child: Child,
    input: ChildStdin,
    lines: Receiver<String>,
}

impl Game {
    fn start(tree: &Tree) -> Self {
        let mut child = Command::new(tree.game_dir.join("League of Legends.exe"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("fake game starts");
        let input = child.stdin.take().unwrap();
        let lines = lines_of(child.stdout.take().unwrap());
        let mut game = Self { child, input, lines };
        let ready = game.next_line();
        assert!(ready.starts_with("READY"), "{ready}");
        game
    }

    fn next_line(&mut self) -> String {
        self.lines.recv_timeout(WAIT).expect("the fake game answers")
    }

    fn ask(&mut self, command: &str, path: &Path) -> String {
        self.say(&format!("{command} {}", path.display()))
    }

    /// Sends one line as it is and returns the answer.
    fn say(&mut self, line: &str) -> String {
        writeln!(self.input, "{line}").unwrap();
        self.input.flush().unwrap();
        self.next_line()
    }

    fn quit(mut self) {
        let _ = writeln!(self.input, "quit");
        let _ = self.input.flush();
        let _ = self.child.wait();
    }
}

impl Drop for Game {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[test]
fn redirects_wad_reads_and_leaves_everything_else_alone() {
    let tree = tree();
    seal(&tree.overlay);
    let mut host = Host::start(&tree, &[]);
    let mut game = Game::start(&tree);

    let attached = host.wait_outcome();
    assert_eq!(attached["event"], "attached", "{:#?}", host.seen);
    assert_eq!(attached["files"], 1);
    let hooks: Vec<_> = attached["hooks"].as_array().unwrap().iter().map(|h| h.as_str().unwrap()).collect();
    assert!(hooks.contains(&"CreateFileA") && hooks.contains(&"CreateFileW"), "{hooks:?}");

    let ahri = tree.ahri_in_game();
    assert_eq!(game.ask("a", &ahri), "RESULT a OK MODDED-AHRI");
    assert_eq!(game.ask("w", &ahri), "RESULT w OK MODDED-AHRI");
    // Other spellings of the same file: forward slashes, odd case, `..`.
    let spelled = ahri.to_string_lossy().replace('\\', "/").to_uppercase();
    assert_eq!(game.ask("a", Path::new(&spelled)), "RESULT a OK MODDED-AHRI");
    let dotted = tree.game_dir.join(r"DATA\FINAL\..\FINAL\Champions\Ahri.wad.client");
    assert_eq!(game.ask("w", &dotted), "RESULT w OK MODDED-AHRI");

    let zed = tree.game_dir.join(r"DATA\FINAL\Champions\Zed.wad.client");
    assert_eq!(game.ask("a", &zed), "RESULT a OK ORIGINAL-ZED");
    assert_eq!(game.ask("w", &zed), "RESULT w OK ORIGINAL-ZED");
    assert_eq!(game.ask("a", &tree.game_dir.join("missing.bin")), "RESULT a ERR 2");
    // A file with the same name outside the game folder is not ours to redirect.
    let outside = tree.root.join("Ahri.wad.client");
    fs::write(&outside, "OUTSIDE").unwrap();
    assert_eq!(game.ask("a", &outside), "RESULT a OK OUTSIDE");

    game.quit();
    let (code, events) = host.finish();
    assert_eq!(code, 0, "{events:#?}");
    let redirected: Vec<_> = events.iter().filter(|e| e["event"] == "redirected").collect();
    assert_eq!(redirected.len(), 4, "{events:#?}");
    let served = redirected[0]["served"].as_str().unwrap();
    assert!(served.ends_with(r"overlay\DATA\FINAL\Champions\Ahri.wad.client"), "{served}");
    assert!(events.iter().any(|e| e["event"] == "detached"), "{events:#?}");
}

#[test]
fn dry_run_reports_but_serves_the_original_files() {
    let tree = tree();
    seal(&tree.overlay);
    let mut host = Host::start(&tree, &["--dry-run"]);
    let mut game = Game::start(&tree);
    assert_eq!(host.wait_outcome()["event"], "attached");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
    let (code, events) = host.finish();
    assert_eq!(code, 0, "{events:#?}");
    let dry = events.iter().find(|e| e["event"] == "redirected").expect("a redirect is reported");
    assert!(dry["served"].as_str().unwrap().starts_with("(dry run)"), "{dry}");
}

#[test]
fn a_game_that_started_too_long_ago_is_refused_and_left_alone() {
    let tree = tree();
    seal(&tree.overlay);
    let mut game = Game::start(&tree);
    std::thread::sleep(Duration::from_millis(300));
    let mut host = Host::start(&tree, &["--max-age-ms", "100"]);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "refused", "{:#?}", host.seen);
    let reason = outcome["reason"].as_str().unwrap();
    assert!(reason.contains("joined too late"), "{reason}");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
    assert_eq!(host.finish().0, 2);
}

#[test]
fn a_host_that_is_not_installed_beside_the_dll_is_refused() {
    let tree = tree();
    seal(&tree.overlay);
    let elsewhere = tree.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let copy = elsewhere.join("riftengine-host.exe");
    fs::copy(HOST, &copy).unwrap();

    let mut host = Host::start_exe(&copy, &dll_path(), &tree, &[]);
    let mut game = Game::start(&tree);
    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "refused", "{:#?}", host.seen);
    assert!(outcome["reason"].as_str().unwrap().contains("not installed beside this DLL"), "{outcome}");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
}

#[test]
fn an_overlay_that_changed_after_sealing_is_not_attached() {
    let tree = tree();
    seal(&tree.overlay);
    fs::write(tree.overlay.join("DATA/FINAL/Champions/Ahri.wad.client"), "MODDED-AHRI-EDITED").unwrap();
    let mut host = Host::start(&tree, &[]);
    let mut game = Game::start(&tree);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "failed", "{:#?}", host.seen);
    assert!(outcome["message"].as_str().unwrap().contains("does not match its manifest"), "{outcome}");
    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
}

#[test]
fn an_unsealed_overlay_is_not_attached() {
    let tree = tree();
    let mut host = Host::start(&tree, &[]);
    let mut game = Game::start(&tree);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "failed", "{:#?}", host.seen);
    assert!(outcome["message"].as_str().unwrap().contains("manifest"), "{outcome}");
    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
}

#[test]
fn an_overlay_built_for_another_game_build_is_not_attached() {
    let tree = tree();
    // The game on disk was linked a day after the one this overlay was made for, say after a patch.
    seal_for(&tree.overlay, A_DAY_EARLIER);
    let mut host = Host::start(&tree, &[]);
    let mut game = Game::start(&tree);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "failed", "{:#?}", host.seen);
    let message = outcome["message"].as_str().unwrap();
    assert!(message.contains("the overlay was built for a game linked"), "{message}");
    assert!(message.contains("rebuild the overlay"), "{message}");
    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
}

#[test]
fn a_running_game_of_another_build_than_the_overlay_is_refused_by_the_dll() {
    let tree = tree();
    seal(&tree.overlay);
    let mut game = Game::start(&tree);
    // The file the host looks at is the build the overlay was made for. The image in the game's
    // memory, which is what the DLL looks at, was linked a day earlier.
    assert_eq!(game.say(&format!("stamp {A_DAY_EARLIER}")), "RESULT stamp OK");
    let mut host = Host::start(&tree, &[]);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "refused", "{:#?}", host.seen);
    let reason = outcome["reason"].as_str().unwrap();
    assert!(reason.contains("the overlay was built for a game linked"), "{reason}");
    assert!(reason.contains("rebuild the overlay"), "{reason}");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
    assert_eq!(host.finish().0, 2);
}

#[test]
fn a_game_folder_the_rules_do_not_reach_is_refused_before_anything_waits() {
    let tree = tree();
    seal(&tree.overlay);
    link_at(&tree.game_dir.join("League of Legends.exe"), END_OF_LIFE);

    let mut host = Host::spawn(Path::new(HOST), &dll_path(), &tree, &[]);
    let failed = host.wait_event("failed");
    let message = failed["message"].as_str().unwrap();
    assert!(message.contains("League of Legends.exe was linked"), "{message}");
    assert!(message.contains("the rules cover only builds before"), "{message}");

    let (code, events) = host.finish();
    assert_eq!(code, 2, "{events:#?}");
    assert!(events.iter().all(|e| e["event"] != "waiting"), "{events:#?}");
}

#[test]
fn a_running_game_newer_than_the_rules_is_refused_by_the_dll_and_left_alone() {
    let tree = tree();
    seal(&tree.overlay);
    let mut game = Game::start(&tree);
    // The file the host looks at is a build the rules reach. The image in the game's memory, which
    // is what the DLL looks at, now says it was linked at the end of life.
    assert_eq!(game.say(&format!("stamp {END_OF_LIFE}")), "RESULT stamp OK");
    let mut host = Host::start(&tree, &[]);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "refused", "{:#?}", host.seen);
    let reason = outcome["reason"].as_str().unwrap();
    assert!(reason.contains("the game was linked"), "{reason}");
    assert!(reason.contains("the rules cover only builds before"), "{reason}");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
    assert_eq!(host.finish().0, 2);
}

#[test]
fn a_running_game_without_a_build_time_is_refused_by_the_dll() {
    let tree = tree();
    seal(&tree.overlay);
    let mut game = Game::start(&tree);
    assert_eq!(game.say("stamp 0"), "RESULT stamp OK");
    let mut host = Host::start(&tree, &[]);

    let outcome = host.wait_outcome();
    assert_eq!(outcome["event"], "refused", "{:#?}", host.seen);
    assert!(outcome["reason"].as_str().unwrap().contains("carries no build time"), "{outcome}");

    assert_eq!(game.ask("a", &tree.ahri_in_game()), "RESULT a OK ORIGINAL-AHRI");
    game.quit();
}
