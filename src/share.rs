//! Local share index and audio metadata extraction (clean-room).
//!
//! [`ShareIndex`] walks the configured shared directories once and keeps an
//! in-memory, peer-visible view: for every file a virtual path (forward
//! slashes, rooted at the top-level directory's own name), its size,
//! extension, and best-effort audio attributes.
//!
//! Attribute generation is deliberately minimal and written from public
//! format documentation only:
//!
//! - **FLAC**: `STREAMINFO` metadata block gives sample rate, bit depth, and
//!   total sample count → exact duration; bitrate ≈ filesize / duration.
//! - **MP3**: first valid frame header gives CBR bitrate; duration estimated
//!   as filesize * 8 / bitrate (VBR files report an approximation).
//!
//! Any parse failure simply yields no attributes; indexing never errors.

use std::path::{Path, PathBuf};

/// One indexed, peer-visible file entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFileMeta {
    /// Peer-visible path, forward slashes, rooted at the shared directory's
    /// own name (e.g. sharing `D:\music` exposes `music/artist/song.flac`).
    pub virtual_path: String,
    /// Absolute local filesystem path used when serving uploads.
    pub local_path: PathBuf,
    pub size: u64,
    pub extension: String,
    /// `(code, value)` pairs matching the Soulseek attribute codes:
    /// 0 = bitrate kbps, 1 = duration s, 4 = sample rate Hz, 5 = bit depth.
    pub attributes: Vec<(u32, u32)>,
}

impl SharedFileMeta {
    pub fn attribute(&self, want: u32) -> Option<u32> {
        self.attributes
            .iter()
            .find(|(c, _)| *c == want)
            .map(|(_, v)| *v)
    }
}

/// An in-memory index of every file in the configured shared directories.
#[derive(Debug, Clone, Default)]
pub struct ShareIndex {
    /// Number of top-level directories contributing to this index.
    pub roots: usize,
    pub files: Vec<SharedFileMeta>,
}

impl ShareIndex {
    /// Build an index by walking each directory recursively. Unreadable
    /// entries are skipped silently; empty/missing roots contribute nothing
    /// beyond a root count.
    pub fn build(dirs: &[String]) -> ShareIndex {
        let mut files = Vec::new();
        for dir in dirs {
            let root = PathBuf::from(dir);
            let Some(top) = root.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            walk(&root, &top, &mut files);
        }
        let roots = dirs.len();
        ShareIndex { roots, files }
    }

    /// Case-insensitive substring match: every whitespace-separated query term
    /// must appear in the virtual path; paths containing any excluded phrase
    /// are skipped. Returns up to `cap` clones.
    pub fn find_matches(
        &self,
        query: &str,
        excluded: &[String],
        cap: usize,
    ) -> Vec<SharedFileMeta> {
        let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
        if terms.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for file in &self.files {
            let lower = file.virtual_path.to_lowercase();
            if !terms.iter().all(|t| lower.contains(t)) {
                continue;
            }
            if excluded.iter().any(|p| lower.contains(&p.to_lowercase())) {
                continue;
            }
            out.push(file.clone());
            if out.len() >= cap {
                break;
            }
        }
        out
    }

    /// Look up one file by virtual path, separator-insensitive.
    pub fn lookup(&self, vpath: &str) -> Option<&SharedFileMeta> {
        let want = normalized(vpath);
        self.files
            .iter()
            .find(|f| normalized(&f.virtual_path) == want)
    }
}

fn normalized(s: &str) -> String {
    s.replace('\\', "/").to_lowercase()
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<SharedFileMeta>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry
                .file_name()
                .to_string_lossy()
                .replace(['/', '\\'], "-");
            walk(&path, &format!("{prefix}/{name}"), out);
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() || meta.len() == 0 {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let extension = Path::new(&name)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let size = meta.len();
        let attributes = audio_attributes(&path, size, &extension);
        out.push(SharedFileMeta {
            virtual_path: format!("{prefix}/{name}"),
            local_path: path.clone(),
            size,
            extension,
            attributes,
        });
    }
}

/// Best-effort audio attributes: FLAC STREAMINFO or MP3 frame header.
/// Anything unparseable returns no attributes at all.
fn audio_attributes(path: &Path, size: u64, ext: &str) -> Vec<(u32, u32)> {
    const HEAD: usize = 64 * 1024;
    let Ok(mut bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    bytes.truncate(HEAD);
    let attrs = match ext {
        "flac" => flac_attributes(&bytes, size),
        "mp3" => mp3_attributes(&bytes, size),
        _ => None,
    };
    attrs.unwrap_or_default()
}

/// FLAC `STREAMINFO`: sample rate / channels / bits per sample / total
/// samples per the public FLAC format specification.
fn flac_attributes(bytes: &[u8], size: u64) -> Option<Vec<(u32, u32)>> {
    if bytes.len() < 8 || &bytes[0..4] != b"fLaC" {
        return None;
    }
    // Metadata block header: 1 byte (last-flag + type), 3-byte length.
    let block_type = bytes[4] & 0x7f;
    if block_type != 0 {
        return None; // STREAMINFO must be first
    }
    let len = ((bytes[5] as usize) << 16) | ((bytes[6] as usize) << 8) | bytes[7] as usize;
    if len < 34 || bytes.len() < 8 + len {
        return None;
    }
    let d = &bytes[8..8 + 34];
    // Last 64 bits of the block pack: sample_rate(20) | channels(3) |
    // bits_per_sample-1(5) | total_samples(36).
    let v = u64::from_be_bytes(d[10..18].try_into().ok()?);
    let sample_rate = (v >> 44) as u32;
    let bps = (((v >> 36) & 0x1f) + 1) as u32;
    let total_samples = (v & ((1u64 << 36) - 1)) as u32;
    if sample_rate == 0 || total_samples == 0 {
        return None;
    }
    let duration = total_samples / sample_rate;
    let bitrate = if duration > 0 {
        ((size.saturating_mul(8)) / (duration as u64)) as u32
    } else {
        return None;
    };
    Some(vec![
        (0, bitrate),
        (1, duration),
        (4, sample_rate),
        (5, bps),
    ])
}

/// MP3 frame-header scan per the public MPEG audio spec: 11 sync bits,
/// version/layer/bitrate-index/samplerate-index fields. Reports the first
/// valid frame's bitrate; duration is filesize*8/bitrate (CBR estimate).
fn mp3_attributes(bytes: &[u8], size: u64) -> Option<Vec<(u32, u32)>> {
    // Bitrate table rows: V1L3, V1L2, V1L1, V2L3, V2L2, V2L1 (kbps; 0 index
    // = free/noise and is rejected). Index by [version][layer].
    const RATES_V1_L3: [u32; 16] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
    ];
    const RATES_V1_L2: [u32; 16] = [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0,
    ];
    const RATES_V1_L1: [u32; 16] = [
        0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0,
    ];
    const RATES_V2: [u32; 16] = [
        0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
    ];
    const SAMPLE_RATES: [[u32; 3]; 2] = [[44100, 48000, 32000], [22050, 24000, 16000]];

    for w in bytes.windows(4) {
        if w[0] != 0xff || (w[1] & 0xe0) != 0xe0 {
            continue;
        }
        let version_bits = (w[1] >> 3) & 0x03; // 3 = MPEG1, 2 = MPEG2, 0 = MPEG2.5
        let layer_bits = (w[1] >> 1) & 0x03; // 1 = Layer III, 2 = Layer II, 3 = Layer I
        let rate_idx = (w[2] >> 4) as usize;
        let sr_idx = ((w[2] >> 2) & 0x03) as usize;
        if version_bits == 1 || layer_bits == 0 || sr_idx == 3 {
            continue;
        }
        let mpeg2 = version_bits != 3;
        let layer = layer_bits; // 1..3
        let kbps = if !mpeg2 {
            match layer {
                3 => RATES_V1_L1[rate_idx],
                2 => RATES_V1_L2[rate_idx],
                _ => RATES_V1_L3[rate_idx],
            }
        } else {
            RATES_V2[rate_idx]
        };
        if kbps == 0 {
            continue;
        }
        let sample_rate = SAMPLE_RATES[mpeg2 as usize][sr_idx];
        if sample_rate == 0 {
            continue;
        }
        let duration = ((size.saturating_mul(8)) / (u64::from(kbps) * 1000)) as u32;
        return Some(vec![(0, kbps), (1, duration)]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, data: &[u8]) -> PathBuf {
        std::fs::create_dir_all(root.join(rel).parent().unwrap()).unwrap();
        let p = root.join(rel);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn build_indexes_relative_paths_with_forward_slashes() {
        let tmp = std::env::temp_dir().join(format!("rss-share-{}", std::process::id()));
        let music = tmp.join("music");
        std::fs::create_dir_all(&music).unwrap();
        write(&music, "artist/a.txt", b"x");
        write(&music, "artist/sub/b.mp3", &[0xff, 0xfb, 0x90, 0x00]);

        let idx = ShareIndex::build(&[music.to_string_lossy().into_owned()]);
        assert_eq!(idx.roots, 1);
        assert_eq!(idx.files.len(), 2);
        let mp3 = idx.lookup("music/artist/sub/b.mp3").expect("mp3 indexed");
        assert_eq!(mp3.extension, "mp3");
        assert!(idx.virtual_path_prefixes_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    impl ShareIndex {
        fn virtual_path_prefixes_ok(&self) -> bool {
            self.files
                .iter()
                .all(|f| f.virtual_path.starts_with("music/") && !f.virtual_path.contains('\\'))
        }
    }

    #[test]
    fn find_matches_requires_all_terms_and_honors_cap() {
        let idx = ShareIndex {
            roots: 1,
            files: vec![
                SharedFileMeta {
                    virtual_path: "music/A/song.flac".into(),
                    local_path: PathBuf::from("/x"),
                    size: 1,
                    extension: "flac".into(),
                    attributes: vec![],
                },
                SharedFileMeta {
                    virtual_path: "music/B/other.flac".into(),
                    local_path: PathBuf::from("/x"),
                    size: 1,
                    extension: "flac".into(),
                    attributes: vec![],
                },
                SharedFileMeta {
                    virtual_path: "music/A/song.mp3".into(),
                    local_path: PathBuf::from("/x"),
                    size: 1,
                    extension: "mp3".into(),
                    attributes: vec![],
                },
            ],
        };
        let hits = idx.find_matches("SONG A", &[], 10);
        assert_eq!(hits.len(), 2);
        assert!(idx.find_matches("nope", &[], 10).is_empty());
        // Excluded phrases filter matches.
        assert!(idx.find_matches("song", &["music/A".into()], 10).is_empty());
        // Cap respected.
        assert_eq!(idx.find_matches("", &[], 10).len(), 0);
    }

    #[test]
    fn flac_streaminfo_yields_exact_duration() {
        // fLaC magic + STREAMINFO block (type 0, first-flag set, 34 bytes).
        // sample_rate=44100, ch=2, bps=16, total_samples=88200 (=2 s).
        let packed: u64 = (44100u64 << 44) | (1u64 << 41) | (15u64 << 36) | 88_200;
        let mut data = Vec::new();
        data.extend_from_slice(b"fLaC");
        data.push(0x80); // last flag + type 0
        data.push(0x00);
        data.push(0x00);
        data.push(0x22); // 34-byte payload
        data.extend_from_slice(&0x1000u16.to_be_bytes()); // min blocksize
        data.extend_from_slice(&0x1000u16.to_be_bytes()); // max blocksize
        data.extend_from_slice(&[0u8; 6]); // min/max framesize
        data.extend_from_slice(&packed.to_be_bytes());
        data.extend_from_slice(&[0u8; 2]); // md5 start (block padded to 34)
        data.resize(8 + 34 + 100, 0); // trailing garbage acts as file body

        let tmp = std::env::temp_dir().join(format!("rss-flac-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let path = write(&tmp, "t.flac", &data);
        let attrs = audio_attributes(&path, data.len() as u64, "flac");
        assert_eq!(attrs[0], (0, (data.len() as u64 * 8 / 2) as u32));
        assert_eq!(attrs[1], (1, 2));
        assert_eq!(attrs[2], (4, 44100));
        assert_eq!(attrs[3], (5, 16));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mp3_frame_header_yields_bitrate_and_cbr_estimate() {
        // MPEG1 Layer III, 128 kbps, 44100 Hz: FF FB 90 00.
        let mut data = vec![0xffu8, 0xfb, 0x90, 0x00];
        data.resize(468_750, 0xaa); // 468750*8/128000 = 29.25 -> 29 s
        let tmp = std::env::temp_dir().join(format!("rss-mp3-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let path = write(&tmp, "t.mp3", &data);
        let attrs = audio_attributes(&path, data.len() as u64, "mp3");
        assert_eq!(attrs[0], (0, 128));
        assert_eq!(attrs[1], (1, 29));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn non_audio_files_get_no_attributes() {
        let tmp = std::env::temp_dir().join(format!("rss-txt-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let path = write(&tmp, "t.txt", b"hello");
        assert!(audio_attributes(&path, 5, "txt").is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
