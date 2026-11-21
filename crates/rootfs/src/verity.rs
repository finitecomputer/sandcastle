//! An image's dm-verity hash tree, for a Nitro Sandbox's measured root
//! (docs/nitro.md): `veritysetup format` (cryptsetup's) over the image's
//! ext4, 4 KiB blocks, SHA-256, the tree in a file of its own, and the
//! table it prints, parsed. The tree's root hash goes on the measured
//! kernel command line, so a sandbox's attestation covers every byte of
//! its root.

use std::path::Path;
use std::process::Command;

use thiserror::Error;

pub const VERITYSETUP: &str = "/usr/sbin/veritysetup";
/// The tree starts after veritysetup's superblock, one block in.
pub const HASH_START_BLOCK: u64 = 1;

#[derive(Debug, Error)]
pub enum VerityError {
    #[error("running veritysetup: {0}")]
    Io(std::io::Error),
    #[error("veritysetup failed: {0}")]
    Failed(String),
    #[error("veritysetup's table: {0}")]
    Table(&'static str),
}

/// What the kernel needs to make the verity device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub data_blocks: u64,
    pub hash_start_block: u64,
    pub root_hash: String,
    pub salt: String,
}

/// Formats `tree` as `data`'s hash tree and returns the table.
pub fn format(data: &Path, tree: &Path) -> Result<Table, VerityError> {
    let _ = std::fs::remove_file(tree);
    let out = Command::new(VERITYSETUP)
        .args(["format", "--data-block-size=4096", "--hash-block-size=4096", "--hash=sha256"])
        .arg(data)
        .arg(tree)
        .output()
        .map_err(VerityError::Io)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(tree);
        return Err(VerityError::Failed(String::from_utf8_lossy(&out.stderr).chars().take(2000).collect()));
    }
    parse(&String::from_utf8_lossy(&out.stdout))
}

/// `veritysetup format`'s report: a field per line, `Name:<tabs>value`.
pub fn parse(report: &str) -> Result<Table, VerityError> {
    let field = |name: &str| report.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == name).map(|(_, v)| v.trim().to_string()));
    let hex = |s: &str| !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit());
    let data_blocks = field("Data blocks").and_then(|v| v.parse::<u64>().ok()).filter(|&n| n > 0).ok_or(VerityError::Table("data blocks"))?;
    if field("Data block size").as_deref() != Some("4096") || field("Hash block size").as_deref() != Some("4096") || field("Hash algorithm").as_deref() != Some("sha256") {
        return Err(VerityError::Table("not 4 KiB blocks of sha256"));
    }
    let root_hash = field("Root hash").filter(|h| h.len() == 64 && hex(h)).ok_or(VerityError::Table("root hash"))?;
    let salt = field("Salt").filter(|s| hex(s) && s.len() <= 256).ok_or(VerityError::Table("salt"))?;
    Ok(Table { data_blocks, hash_start_block: HASH_START_BLOCK, root_hash, salt })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What cryptsetup 2.7 prints (the spike's image, its values made up).
    const REPORT: &str = "VERITY header information for /srv/root.verity\nUUID:            \t6e17f0a5-0000-4000-8000-00000000c0de\nHash type:       \t1\nData blocks:     \t923392\nData block size: \t4096\nHash blocks:     \t7280\nHash block size: \t4096\nHash algorithm:  \tsha256\nSalt:            \t6e17f0a50000400080000000000c0de06e17f0a50000400080000000000c0de0\nRoot hash:      \te11682c73d1f170d261e73efbe07b703f6daf419c9abb1a3646825751ee0ba5a\n";

    // Goal: the table reads out of veritysetup's report exactly, tabs and
    // all, and a report of another shape gives no table.
    #[test]
    fn the_report_reads_as_a_table() {
        let t = parse(REPORT).unwrap();
        assert_eq!(t.data_blocks, 923_392);
        assert_eq!(t.hash_start_block, 1);
        assert_eq!(t.root_hash, "e11682c73d1f170d261e73efbe07b703f6daf419c9abb1a3646825751ee0ba5a");
        assert!(t.salt.starts_with("6e17f0a5"));
        for (from, to) in [("sha256", "sha512"), ("Data block size: \t4096", "Data block size: \t512"), ("Root hash:      \te1", "Root hash:      \tzz"), ("Data blocks:     \t923392", "Data blocks:     \t0")] {
            assert!(parse(&REPORT.replace(from, to)).is_err(), "{to}");
        }
        assert!(parse("").is_err());
    }
}
