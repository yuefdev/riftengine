//! The rule set. Host and DLL both link this crate and compare [`digest`] in the handshake, so a
//! DLL never serves an overlay that was checked against a different (looser) rule set.
//!
//! This crate only names the rules. The checks live in `riftengine-validator`, which the host
//! runs on every pack before an overlay is built. There is deliberately no way to switch a rule off
//! at run time: not in the protocol, not in the configuration, not on the command line.
//!
//! The rules were reviewed against the game as it was at one time, and they reach only so far past
//! it: [`END_OF_LIFE`]. Host and DLL both refuse a game built after that, with the same
//! [`check_build`]. An overlay is checked against the files of one build, and both refuse to serve
//! it to another with the same [`check_overlay_build`].

use std::fmt;

use riftengine_core::sha256_hex;

pub const RULESET_VERSION: u32 = 2;

/// Game builds linked at or after this instant are refused, by the host and by the DLL, whatever
/// else is right. The rules were reviewed against the game as it was on 2026-10-16 (that build was
/// the one installed), and a game that has moved on a long way may hold gameplay data they do not
/// know about.
///
/// Moving it means reviewing the rules again and building both halves again. It is part of the
/// [`digest`], so a host and a DLL with different dates refuse each other.
///
/// This is 2027-01-15 00:00 UTC, about 90 days after that build.
pub const END_OF_LIFE: u32 = unix(2027, 1, 15);

pub struct Rule {
    pub id: &'static str,
    /// Where the rule comes from. Section numbers refer to the CSLOL DLL License Addendum v1.1.
    pub clause: &'static str,
    pub summary: &'static str,
}

/// Rule ids, so the validator and its tests cannot disagree with the table by a typo.
pub mod id {
    pub const PATH: &str = "RR-PATH";
    pub const TARGET: &str = "RR-TARGET";
    pub const FILE_KIND: &str = "RR-FILE-KIND";
    pub const DATA_DECL: &str = "RR-DATA-DECL";
    pub const BIN_READABLE: &str = "RR-BIN-READABLE";
    pub const GAMEPLAY_CLASS: &str = "RR-GAMEPLAY-CLASS";
    pub const BASE_NAME: &str = "RR-BASE-NAME";
    pub const BASE_ASSETS: &str = "RR-BASE-ASSETS";
}

pub const RULES: &[Rule] = &[
    Rule {
        id: id::PATH,
        clause: "hygiene",
        summary: "entry names stay inside their WAD (no absolute paths, `..`, drive letters or control characters)",
    },
    Rule {
        id: id::TARGET,
        clause: "6.1",
        summary: "packs may only change champion WADs; maps and shared game data are refused, and so is a chunk only they hold; a chunk a champion WAD shares with them is replaced in that WAD alone",
    },
    Rule {
        id: id::FILE_KIND,
        clause: "6.1",
        summary: "only cosmetic file kinds are accepted; scripts, executables and override BINs are refused",
    },
    Rule {
        id: id::DATA_DECL,
        clause: "6.1",
        summary: "packs must not edit game data through declarations; only reviewable files are accepted",
    },
    Rule {
        id: id::BIN_READABLE,
        clause: "fail-closed",
        summary: "every BIN must parse, so that it can be checked",
    },
    Rule {
        id: id::GAMEPLAY_CLASS,
        clause: "6.1",
        summary: "BINs must not add or change gameplay data (character records, spells, attack slots); the game's own, unchanged, may stay",
    },
    Rule {
        id: id::BASE_NAME,
        clause: "6.2",
        summary: "skin0 must not take another skin's name",
    },
    Rule {
        id: id::BASE_ASSETS,
        clause: "6.2",
        summary: "skin0 must not name another skin's assets, animation set or data files",
    },
];

/// The clause a rule id comes from, for messages.
pub fn clause_of(rule: &str) -> &'static str {
    RULES.iter().find(|r| r.id == rule).map_or("unknown", |r| r.clause)
}

/// Why the rules do not cover a game build. It reads after the thing it is about: "the game
/// {error}".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildTimeError {
    /// The executable carries no link time, so the rules cannot be tied to it.
    Unstamped,
    /// Linked at or after [`END_OF_LIFE`].
    EndOfLife { linked: u32 },
}

impl fmt::Display for BuildTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstamped => f.write_str("carries no build time, so the rules cannot be tied to it"),
            Self::EndOfLife { linked } => write!(
                f,
                "was linked {}, but the rules cover only builds before {}; a newer RiftEngine is needed",
                utc(*linked),
                utc(END_OF_LIFE)
            ),
        }
    }
}

impl std::error::Error for BuildTimeError {}

/// Whether the rules cover a game executable linked at `link_time`, in seconds since the Unix epoch.
pub fn check_build(link_time: u32) -> Result<(), BuildTimeError> {
    match link_time {
        0 => Err(BuildTimeError::Unstamped),
        linked if linked >= END_OF_LIFE => Err(BuildTimeError::EndOfLife { linked }),
        _ => Ok(()),
    }
}

/// An overlay was made for a game of another build than the one it is about to be served to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherBuild {
    /// When the game the overlay was built for was linked.
    pub built_for: u32,
    /// When the game in front of us was linked.
    pub running: u32,
}

impl fmt::Display for OtherBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the overlay was built for a game linked {}, but this game was linked {}; rebuild the overlay",
            utc(self.built_for),
            utc(self.running)
        )
    }
}

impl std::error::Error for OtherBuild {}

/// Whether an overlay built for a game linked at `built_for` may be served to the game linked at
/// `running`, both in seconds since the Unix epoch. The packs were checked against the files of one
/// build and the overlay carries copies of them, so any other build is refused, newer or older.
pub fn check_overlay_build(built_for: u32, running: u32) -> Result<(), OtherBuild> {
    if built_for == running { Ok(()) } else { Err(OtherBuild { built_for, running }) }
}

/// The text the digest is taken over: the version, how far in time the rules reach, then each rule.
fn digest_text(end_of_life: u32) -> String {
    let mut text = format!("riftengine-rules\nversion {RULESET_VERSION}\nend-of-life {end_of_life}\n");
    for rule in RULES {
        text.push_str(&format!("{}\t{}\t{}\n", rule.id, rule.clause, rule.summary));
    }
    text
}

/// SHA-256 over the version, the end of life, and the rule ids and summaries. Changing a rule, or
/// how far in time they reach, changes the digest.
pub fn digest() -> String {
    sha256_hex(digest_text(END_OF_LIFE).as_bytes())
}

// ---- dates ----

const SECONDS_PER_DAY: u32 = 86_400;

/// Days from 1970-01-01 to a day of the Gregorian calendar (Howard Hinnant's `days_from_civil`).
/// Meant for dates from 1970 on; an earlier one does not compile where a constant is built from it.
const fn days_from_civil(year: u32, month: u32, day: u32) -> u32 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let year_of_era = y - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Seconds since the Unix epoch at 00:00 UTC of a day.
const fn unix(year: u32, month: u32, day: u32) -> u32 {
    days_from_civil(year, month, day) * SECONDS_PER_DAY
}

/// A time as `2026-10-16 22:15 UTC`, for messages (Howard Hinnant's `civil_from_days`).
pub fn utc(time: u32) -> String {
    let z = time / SECONDS_PER_DAY + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u32::from(month <= 2);
    let seconds = time % SECONDS_PER_DAY;
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", seconds / 3600, seconds % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build the rules were reviewed against: `League of Legends.exe`, linked
    /// 2026-10-16 22:15:09 UTC.
    const REVIEWED_BUILD: u32 = 1_792_188_909;

    #[test]
    fn digest_is_stable_and_covers_every_rule() {
        assert_eq!(digest(), digest());
        assert_eq!(digest().len(), 64);
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }

    #[test]
    fn clause_lookup_knows_every_rule() {
        for rule in RULES {
            assert_eq!(clause_of(rule.id), rule.clause);
        }
        assert_eq!(clause_of("RR-NOPE"), "unknown");
    }

    #[test]
    fn the_digest_covers_how_far_the_rules_reach() {
        assert_eq!(digest(), sha256_hex(digest_text(END_OF_LIFE).as_bytes()));
        assert_ne!(digest_text(END_OF_LIFE), digest_text(END_OF_LIFE + 1));
    }

    #[test]
    fn builds_before_the_end_of_life_are_covered_and_later_ones_are_not() {
        assert_eq!(check_build(REVIEWED_BUILD), Ok(()));
        assert_eq!(check_build(END_OF_LIFE - 1), Ok(()));
        assert_eq!(check_build(END_OF_LIFE), Err(BuildTimeError::EndOfLife { linked: END_OF_LIFE }));
        assert_eq!(check_build(u32::MAX), Err(BuildTimeError::EndOfLife { linked: u32::MAX }));
        // A link time of nothing is no link time: the rules cannot be tied to it.
        assert_eq!(check_build(0), Err(BuildTimeError::Unstamped));
    }

    #[test]
    fn an_overlay_belongs_to_the_one_build_it_was_made_for() {
        assert_eq!(check_overlay_build(REVIEWED_BUILD, REVIEWED_BUILD), Ok(()));
        // Newer, older, unstamped, and as far off as it gets.
        for running in [REVIEWED_BUILD + 1, REVIEWED_BUILD - 1, 0, u32::MAX] {
            assert_eq!(
                check_overlay_build(REVIEWED_BUILD, running),
                Err(OtherBuild { built_for: REVIEWED_BUILD, running })
            );
        }
        assert_eq!(check_overlay_build(0, REVIEWED_BUILD), Err(OtherBuild { built_for: 0, running: REVIEWED_BUILD }));
    }

    #[test]
    fn another_build_is_refused_with_both_builds_named() {
        let message = check_overlay_build(REVIEWED_BUILD, unix(2026, 11, 3)).unwrap_err().to_string();
        assert!(message.contains("built for a game linked 2026-10-16 22:15 UTC"), "{message}");
        assert!(message.contains("this game was linked 2026-11-03 00:00 UTC"), "{message}");
        assert!(message.ends_with("rebuild the overlay"), "{message}");
    }

    #[test]
    fn the_reviewed_build_is_inside_the_rules_reach() {
        const { assert!(REVIEWED_BUILD < END_OF_LIFE) };
        assert_eq!(utc(REVIEWED_BUILD), "2026-10-16 22:15 UTC");
    }

    #[test]
    fn a_refusal_names_both_times() {
        let message = check_build(unix(2027, 2, 1)).unwrap_err().to_string();
        assert!(message.contains("2027-02-01 00:00 UTC"), "{message}");
        assert!(message.contains(&utc(END_OF_LIFE)), "{message}");
    }

    #[test]
    fn days_are_counted_from_the_unix_epoch() {
        assert_eq!(unix(1970, 1, 1), 0);
        assert_eq!(unix(2000, 3, 1), 951_868_800);
        assert_eq!(unix(2024, 2, 29), 1_709_164_800);
        // The cut-off in the League Toolkit patcher: an independent reading of the same calendar.
        assert_eq!(unix(2026, 11, 1) + 7 * 3600, 0x6ae6_e370);
        assert_eq!(utc(0x6ae6_e370), "2026-11-01 07:00 UTC");
    }

    #[test]
    fn every_day_is_the_day_after_the_one_before_and_reads_back() {
        let mut counted = 0;
        for year in 1970..=2105u32 {
            for month in 1..=12u32 {
                let length = match month {
                    2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
                    2 => 28,
                    4 | 6 | 9 | 11 => 30,
                    _ => 31,
                };
                for day in 1..=length {
                    assert_eq!(days_from_civil(year, month, day), counted, "{year}-{month}-{day}");
                    let at_half_past_noon = counted * SECONDS_PER_DAY + 12 * 3600 + 30 * 60;
                    assert_eq!(utc(at_half_past_noon), format!("{year:04}-{month:02}-{day:02} 12:30 UTC"));
                    counted += 1;
                }
            }
        }
    }
}
