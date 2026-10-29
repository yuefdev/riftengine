# RiftEngine

A host and a DLL of our own, in place of the League Toolkit patcher. The host checks community packs against a fixed set of rules, builds an overlay from the very bytes it checked, and loads the DLL into the game. The DLL serves the overlay's WADs when the game opens them.

No switch turns a rule off: not in the protocol, not in the configuration, not on the command line.

## Download

Windows only. Builds are on the [releases page](../../releases).

The game loads a DLL only if it carries a valid signature, and this project has no certificate yet. Until it does, the builds there are unsigned: the host builds and checks overlays, but it cannot attach to the game. See [Help wanted](#help-wanted).

RiftEngine is not endorsed by Riot Games and does not reflect the views or opinions of Riot Games or anyone officially involved in producing or managing Riot Games properties. Riot Games and all associated properties are trademarks or registered trademarks of Riot Games, Inc. The engine accepts cosmetic content only, but that does not make modified game files permitted under Riot's terms; use it at your own risk.

## Code signing policy

No release is signed yet. The project plans to apply to [SignPath Foundation](https://signpath.org), which signs open-source projects for free through [SignPath.io](https://signpath.io). When it accepts the project, this section will say so, and releases will be signed with a certificate issued to SignPath Foundation.

Only the host and the DLL built from this repository by the [release workflow](.github/workflows/release.yml), on GitHub-hosted runners, will be sent for signing, and every release will be approved by hand first. The artifact configuration is in [`.signpath`](.signpath/artifact-configuration.xml).

| Role | Who |
| --- | --- |
| Authors and reviewers | [@yuefdev](https://github.com/yuefdev) |
| Approvers | [@yuefdev](https://github.com/yuefdev) |

<!-- Once SignPath Foundation accepts the project, replace the first paragraph of this section with: Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org). -->

Releases of this project are made by the maintainers above; contributors without commit rights have their changes reviewed first.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

The engine makes no network connections at all. The host and the DLL talk through a local named pipe, and everything else is read from and written to local files.

## Help wanted

A code-signing certificate costs money that this project does not have. SignPath Foundation signs open-source projects for free, but it takes only those with a verifiable reputation, and a new project has none yet.

If the engine is of use to you, any of these helps: a star, a bug report, a pull request, a review of the rules in `crates/rules`, or a note on what you use it for.

## Crates

| Crate | What it holds |
| --- | --- |
| `core` | The pipe protocol (length-prefixed CBOR), the overlay manifest and the path redirect logic. |
| `rules` | The rule table and its digest. Host and DLL compare the digest in the handshake. |
| `validator` | The checks behind the rules. It streams BINs with `ltk_meta` and compares them with the installed game. |
| `dll` | `riftengine_dll.dll`. It checks its host, patches the game's import table for `CreateFileA/W` and redirects plain reads of listed WADs to the overlay. |
| `host` | `riftengine-host`. It reads packs, validates, builds and audits the overlay, finds the game, loads the DLL and serves the pipe. |

## How an overlay is made

1. `game.rs` reads when the installed game was linked. A build the rules do not reach is refused before any pack is opened (see [End of life](#end-of-life)).
2. `pack.rs` reads each `.fantome` into memory once, within limits on size and entry count.
3. The validator checks those bytes against the rules and the installed game. One violation refuses the whole build, and nothing on disk is touched.
4. `ltk_overlay` builds from the same bytes, handed over from memory. It never opens an archive. WADs outside `DATA/FINAL/Champions` are blocked.
5. `overlay.rs` audits what the builder wrote. Every chunk has to be the game's own or the bytes of a file that was checked.
6. Only then is `riftengine-overlay.json` written, with the build of the game the overlay was made for. The DLL serves nothing without it.

If anything fails after the old overlay was cleared, the folder is left empty. A build that is refused before that leaves the earlier overlay as it was.

The packs are given highest priority first. Within a pack, a layer of higher priority wins over a lower one, and all layers are enabled.

## Commands

Run them from `engine/`, so that `.cargo/config.toml` is found.

```
riftengine-host build --game-dir <Game> --overlay <dir> <pack.fantome>...
riftengine-host watch --game-dir <Game> --overlay <dir> [--dll <path>] [--once] [--dry-run]
riftengine-host rules
```

`build` replaces whatever overlay is in `--overlay`. The folder must be missing, empty, or hold only an earlier overlay, and it may not overlap the game folder. It refuses a game the rules do not reach.

`watch` waits for the game, loads the DLL with a `WH_GETMESSAGE` hook and serves the overlay. `--dry-run` resolves and reports redirects, but the game gets its original files. By default the DLL is looked for next to the host, and the DLL refuses a host that is anywhere else. A game folder the rules do not reach fails at once, before anything waits. An overlay made for another build of the game is not served (see [The overlay and the game build](#the-overlay-and-the-game-build)).

`rules` prints the rule set, its digest and the end of life.

Both print one JSON object per line: `validated`, `violation`, `building`, `built`, `failed`, and for `watch` also `found`, `attached`, `redirected`, `refused`, `detached`.

## What the rules cover

`riftengine-host rules` lists them; `crates/rules/src/lib.rs` has the clauses. The checks are structural and grounded in the BINs of the installed game:

- Names stay inside their WAD, and only cosmetic kinds are accepted: `bin dds tex skn skl anm scb sco bnk wpk png jpg jpeg tga ogg wav`. Scripts, executables and override (PTCH) BINs are refused.
- Only champion WADs are targets, and a chunk is refused if only WADs outside the champions hold it (see [Chunks shared with other WADs](#chunks-shared-with-other-wads)).
- A pack may not declare game data.
- Every BIN has to parse, within limits (8 MiB a file, 1 MiB an object, 96 levels deep, 30 s).
- A BIN may keep the gameplay objects the game has, as they are, and add or change none.
- The base skin (skin0) may not take another skin's name, assets, animation set or data files.

What it does not do: look inside textures, meshes or audio, or prove a pack harmless. It refuses the patterns it knows.

A pack that turns skin0 into another official skin is refused by design, so that flow does not work with this engine.

## Chunks shared with other WADs

An overlay carries champion WADs only, but the game keeps some chunks in more than one WAD. In the installed build, 173 of the 348 champion WADs hold chunks that also sit in one of 25 other WADs (maps, the UI, `Global`, game modes), with the same checksum and size as the champion's. `RR-TARGET` tells two cases apart:

- **The champion WAD holds the chunk too.** For a `RAW/` file, any champion WAD does. The chunk is replaced there and nowhere else. The build goes ahead and warns once for each other WAD, in a `log` event of level 2: `<pack>: 36 chunks it replaces are also in map30.wad.client, which the overlay does not carry; the game may keep using its own copy there`.
- **Only WADs outside the champions hold it.** There is nothing of it to replace, and the file could only edit what the content rules know nothing about, such as a HUD scene or the UI's client-state BIN. The pack is refused.

The warning is given only for a build that goes ahead. The content rules apply to the bytes either way.

## End of life

The rules were reviewed against one build of the game, and they reach only a little past it. The tie is the time the executable was linked (the `TimeDateStamp` in its PE header). `END_OF_LIFE` in `crates/rules/src/lib.rs` is 2027-01-15 00:00 UTC: the installed build, linked 2026-10-16, plus about 90 days. A game linked at or after that time is refused. So is one with no link time at all (a stamp of 0), because nothing can be tied to it.

- The DLL reads the time from the headers of the image the game runs, as its first check after the handshake and before any hook. Neither the host nor the disk has a say in it.
- The host reads the same field from `League of Legends.exe` on disk with the same code (`core::pe`). `build` and `watch` use it to say no early. The DLL's check is the one that counts.
- The date is part of the rules digest, so a host and a DLL built with different dates refuse each other. There is no switch for it.

Moving the date means reviewing the rules against the newer game, then rebuilding both halves.

## The overlay and the game build

The packs are checked against the files of one build of the game, and the overlay carries copies of its WADs. So `riftengine-overlay.json` records when the game it was made for was linked (`game_linked`, the same PE field), and an overlay is served only to a game linked at exactly that time, newer or older.

- `build` records the link time it read before it looked at any pack.
- `watch` compares it with the executable on disk for each game it finds, and reports `failed`. The DLL compares it with the image the game runs, and answers `refused`. Either way the game starts with its own files.
- After a patch the overlay has to be rebuilt. A manifest of format 1, which carried no build, is not served.

## Not done yet

- Every build is a full rebuild. `ltk_overlay` can build incrementally from its `.state`, but that would trust files left on disk, so the folder is cleared first. Only champion WADs are patched, each copied whole. In a release build on the installed game, a pack that touches Viego (113 MB) builds in 0.7 s and one that touches Sona (227 MB, the largest) in 1.1 s, so a cache has not been worth its risk so far.
- An overlay is tied to the game's link time, not to its WADs. A patch that changes WADs and leaves `League of Legends.exe` as it was would not be noticed, so rebuild after any patch.
- A chunk that a map's or the UI's WAD shares with the champion WAD is replaced in the champion WAD alone. Whether the game then shows it depends on which WAD it reads that chunk from, and that has not been tried in a running game.
- The DLL has run against a fake game process (`crates/host/tests/e2e.rs`), but has never reported from the real game. On 29 Oct 2026 (game 16.21, Vanguard 1.19.1) `watch` found the game and put the `WH_GETMESSAGE` hook on its window thread, and no session followed: `failed`, "the game did not load the engine DLL". The same host, DLL and nudge load fine into an ordinary program (Character Map), the game's token is an ordinary medium-integrity one, and the game has no process mitigation that blocks hook DLLs. A run with the League Toolkit manager and patcher host closed gave the same result, and the DLL's `DllMain` never ran in the game (no loaded event, no debug output).
  What the game logs show: in all three runs with the host attached, the game's window thread stood still right after it found the graphics adapter (`Detected Adapter` to `DXGI: Tearing support enabled` took 59.7, 58.2 and 43.1 s, against 8 ms in a run without the host). In the LTK manager's own logs of 22-24 Oct, 15 of 17 hooks were followed by "dll attached" 56-214 ms later.
  A run with a four-minute wait (29 Oct, 22:42) showed why. The window thread stood still for 48 s, then went on without the DLL while the hook stayed up. Until the host removed the hook, that thread asked Windows Code Integrity to check an image about six times a second: 2,348 `3010` events in `Microsoft-Windows-CodeIntegrity/Operational`, all from the game's process and the hooked thread, none in the hour before. Each one is a failure to open one of two broken OEM catalogs (`oem7.cat`, `oem8.cat`), and Code Integrity opens the catalogs to look for the signature of an image that carries none of its own. No attempt let the DLL in. So the game takes only DLLs that pass a signature check. LTK's DLL is signed (Natoken LLC, through Microsoft's Trusted Signing, `Microsoft ID Verified CS EOC CA 04`); this one is not, and needs a code-signing certificate of its own. A self-signed certificate or a change to the trust store would only fool the check, and is not an option.
- When `watch` times out it tells two cases apart: the DLL creates the named event `Local\riftengine-loaded-<pid>` as soon as it is loaded into the game, and the host looks for it. The DLL also writes where it stopped to the debug output (`OutputDebugString`), for a debugger or DebugView. The host reports, as `log` events, which thread it hooked (and that thread's window class), how old the game was, and how long it waited; it wakes the thread once on hooking and then once a second.
- Windows only.

## Tests

```
cargo test --workspace --offline
```

Three tests need an installed game and are ignored by default. None writes to it. The validator test takes a few minutes in a debug build. The two host tests each build an overlay from a pack of three of the game's own textures, and take a few seconds. One uses textures only the champion's WAD holds; the other uses textures it shares with a WAD outside the champions, and checks the warning:

```
RIFTENGINE_GAME_DIR=<Game> cargo test -p riftengine-validator -- --ignored --nocapture
RIFTENGINE_GAME_DIR=<Game> cargo test -p riftengine-host --lib -- --ignored --nocapture
```

The host tests take the smallest champion WAD that fits. `RIFTENGINE_TEST_WAD=sona.wad.client` picks another.
