//! Integer-only inference for CDK agents (`no_std`, no floating point).
//!
//! Agents run in ring 3 without FPU state (roadmap 2.6), so models are
//! evaluated entirely in integer arithmetic: int8 weights, u8 features,
//! i32 accumulators. The result (argmax) matches the float model it was
//! quantized from except for near-ties.
//!
//! ## `CDKLM1` — linear classifier
//!
//! Little-endian; sizes are exact, anything else is rejected.
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | magic `CDKLM1\0\0` |
//! | 8 | 2 | `n_features` (1..=1024) |
//! | 10 | 1 | `n_classes` (2..=16) |
//! | 11 | 1 | feature kind: 0 = caller-defined, 1 = [`text::hashed_trigrams`] |
//! | 12 | 4 | `logit_scale_micro`: real logit ≈ integer logit × this / 10⁶ |
//! | 16 | 16 × C | class labels, NUL-padded ASCII |
//! | … | 4 × C | bias, i32 (already in integer-logit units) |
//! | … | C × F | weights, i8, class-major |
//!
//! Integer logit for class `c`: `bias[c] + Σ weights[c][i] × x[i]`, with
//! features `x[i]` in `0..=255` (255 ≙ 1.0).

#![no_std]

pub const MAGIC: &[u8; 8] = b"CDKLM1\0\0";
const HEADER: usize = 16;
const LABEL_LEN: usize = 16;
pub const MAX_FEATURES: usize = 1024;
pub const MAX_CLASSES: usize = 16;

/// How a model expects its features to be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureKind {
    /// The agent computes the feature vector itself.
    Custom,
    /// [`text::hashed_trigrams`] over the input text.
    HashedTrigrams,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    BadMagic,
    BadShape,
    BadFeatureKind,
    /// The byte length does not match the header.
    BadLength,
    BadLabel,
    /// The feature vector length does not match the model.
    FeatureCount,
}

/// A parsed `CDKLM1` model borrowing its bytes.
#[derive(Clone, Copy, Debug)]
pub struct Model<'a> {
    n_features: usize,
    n_classes: usize,
    kind: FeatureKind,
    logit_scale_micro: u32,
    labels: &'a [u8],
    bias: &'a [u8],
    weights: &'a [u8],
}

/// Classification result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prediction {
    pub class: usize,
    /// Integer logit of the winning class.
    pub logit: i32,
    /// Winning logit minus the runner-up (≥ 0; small = low confidence).
    pub margin: i32,
}

impl<'a> Model<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ModelError> {
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err(ModelError::BadMagic);
        }
        let n_features = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        let n_classes = bytes[10] as usize;
        if !(1..=MAX_FEATURES).contains(&n_features) || !(2..=MAX_CLASSES).contains(&n_classes) {
            return Err(ModelError::BadShape);
        }
        let kind = match bytes[11] {
            0 => FeatureKind::Custom,
            1 => FeatureKind::HashedTrigrams,
            _ => return Err(ModelError::BadFeatureKind),
        };
        let logit_scale_micro = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let labels_end = HEADER + LABEL_LEN * n_classes;
        let bias_end = labels_end + 4 * n_classes;
        let weights_end = bias_end + n_classes * n_features;
        if bytes.len() != weights_end {
            return Err(ModelError::BadLength);
        }
        let labels = &bytes[HEADER..labels_end];
        for c in 0..n_classes {
            let raw = &labels[c * LABEL_LEN..(c + 1) * LABEL_LEN];
            let len = raw.iter().position(|&b| b == 0).unwrap_or(LABEL_LEN);
            if len == 0 || !raw[..len].iter().all(|b| b.is_ascii_graphic()) {
                return Err(ModelError::BadLabel);
            }
        }
        Ok(Self {
            n_features,
            n_classes,
            kind,
            logit_scale_micro,
            labels,
            bias: &bytes[labels_end..bias_end],
            weights: &bytes[bias_end..weights_end],
        })
    }

    pub fn n_features(&self) -> usize {
        self.n_features
    }

    pub fn n_classes(&self) -> usize {
        self.n_classes
    }

    pub fn feature_kind(&self) -> FeatureKind {
        self.kind
    }

    /// Multiply an integer logit by this and divide by 10⁶ for real units.
    pub fn logit_scale_micro(&self) -> u32 {
        self.logit_scale_micro
    }

    pub fn label(&self, class: usize) -> &'a str {
        let raw = &self.labels[class * LABEL_LEN..(class + 1) * LABEL_LEN];
        let len = raw.iter().position(|&b| b == 0).unwrap_or(LABEL_LEN);
        core::str::from_utf8(&raw[..len]).unwrap_or("?")
    }

    fn bias(&self, class: usize) -> i32 {
        let b = &self.bias[4 * class..4 * class + 4];
        i32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Integer logits for `features` (length `n_features`) into `out`
    /// (length ≥ `n_classes`).
    pub fn logits(&self, features: &[u8], out: &mut [i32]) -> Result<(), ModelError> {
        if features.len() != self.n_features || out.len() < self.n_classes {
            return Err(ModelError::FeatureCount);
        }
        for (c, slot) in out.iter_mut().enumerate().take(self.n_classes) {
            let row = &self.weights[c * self.n_features..(c + 1) * self.n_features];
            let mut acc = self.bias(c) as i64;
            for (&w, &x) in row.iter().zip(features) {
                acc += (w as i8) as i64 * x as i64;
            }
            *slot = acc.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        }
        Ok(())
    }

    /// Argmax class, its logit, and the margin over the runner-up. Ties go
    /// to the lower class index.
    pub fn classify(&self, features: &[u8]) -> Result<Prediction, ModelError> {
        let mut logits = [0i32; MAX_CLASSES];
        self.logits(features, &mut logits)?;
        let logits = &logits[..self.n_classes];
        let mut best = 0;
        for c in 1..logits.len() {
            if logits[c] > logits[best] {
                best = c;
            }
        }
        let runner_up = logits
            .iter()
            .enumerate()
            .filter(|&(c, _)| c != best)
            .map(|(_, &l)| l)
            .max()
            .unwrap_or(logits[best]);
        Ok(Prediction {
            class: best,
            logit: logits[best],
            margin: logits[best].saturating_sub(runner_up),
        })
    }
}

/// Generic text featurizers.
pub mod text {
    /// FNV-1a, 32-bit.
    pub fn fnv1a32(bytes: &[u8]) -> u32 {
        bytes.iter().fold(0x811c_9dc5u32, |h, &b| {
            (h ^ b as u32).wrapping_mul(0x0100_0193)
        })
    }

    /// Hashed character-trigram presence features.
    ///
    /// The text is ASCII-lowercased, every other non-alphanumeric byte
    /// becomes a space, and it is padded with one space on each side. Each
    /// consecutive 3-byte window sets `out[fnv1a32(window) % out.len()]` to
    /// 255. `out` is cleared first. Texts longer than 512 bytes are
    /// truncated.
    pub fn hashed_trigrams(text: &[u8], out: &mut [u8]) {
        out.fill(0);
        if out.is_empty() {
            return;
        }
        let mut norm = [b' '; 514];
        let n = text.len().min(512);
        for (dst, &b) in norm[1..=n].iter_mut().zip(text) {
            *dst = if b.is_ascii_alphanumeric() {
                b.to_ascii_lowercase()
            } else {
                b' '
            };
        }
        let norm = &norm[..n + 2];
        for w in norm.windows(3) {
            let bucket = fnv1a32(w) as usize % out.len();
            out[bucket] = 255;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn model_bytes(n_f: u16, labels: &[&str], bias: &[i32], weights: &[i8], kind: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&n_f.to_le_bytes());
        b.push(labels.len() as u8);
        b.push(kind);
        b.extend_from_slice(&1000u32.to_le_bytes());
        for l in labels {
            let mut raw = [0u8; LABEL_LEN];
            raw[..l.len()].copy_from_slice(l.as_bytes());
            b.extend_from_slice(&raw);
        }
        for x in bias {
            b.extend_from_slice(&x.to_le_bytes());
        }
        b.extend(weights.iter().map(|&w| w as u8));
        b
    }

    #[test]
    fn parses_and_classifies() {
        let bytes = model_bytes(2, &["NO", "YES"], &[10, 0], &[0, 0, 1, 1], 0);
        let m = Model::parse(&bytes).unwrap();
        assert_eq!((m.n_features(), m.n_classes()), (2, 2));
        assert_eq!((m.label(0), m.label(1)), ("NO", "YES"));
        assert_eq!(
            m.classify(&[0, 0]).unwrap(),
            Prediction {
                class: 0,
                logit: 10,
                margin: 10
            }
        );
        let p = m.classify(&[255, 255]).unwrap();
        assert_eq!((p.class, p.logit, p.margin), (1, 510, 500));
    }

    #[test]
    fn negative_weights_and_ties() {
        let bytes = model_bytes(1, &["A", "B"], &[0, 0], &[-1, -1], 0);
        let m = Model::parse(&bytes).unwrap();
        let p = m.classify(&[200]).unwrap();
        assert_eq!(
            (p.class, p.logit, p.margin),
            (0, -200, 0),
            "tie goes to lower index"
        );
    }

    #[test]
    fn rejects_malformed_models() {
        let good = model_bytes(2, &["A", "B"], &[0, 0], &[0; 4], 0);
        assert!(Model::parse(&good).is_ok());
        assert_eq!(
            Model::parse(&good[..good.len() - 1]).err(),
            Some(ModelError::BadLength)
        );
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(Model::parse(&extra).err(), Some(ModelError::BadLength));
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(Model::parse(&magic).err(), Some(ModelError::BadMagic));
        assert_eq!(
            Model::parse(&model_bytes(2, &["A"], &[0], &[0; 2], 0)).err(),
            Some(ModelError::BadShape)
        );
        assert_eq!(
            Model::parse(&model_bytes(2, &["A", "B"], &[0, 0], &[0; 4], 9)).err(),
            Some(ModelError::BadFeatureKind)
        );
        assert_eq!(
            Model::parse(&model_bytes(2, &["A", ""], &[0, 0], &[0; 4], 0)).err(),
            Some(ModelError::BadLabel)
        );
        let m = Model::parse(&good).unwrap();
        assert_eq!(m.classify(&[0; 3]).err(), Some(ModelError::FeatureCount));
    }

    #[test]
    fn trigram_features_are_normalized() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        text::hashed_trigrams(b"Server DOWN!!", &mut a);
        text::hashed_trigrams(b"server down  ", &mut b);
        assert_eq!(a, b);
        assert!(a.contains(&255));
        assert!(a.iter().all(|&x| x == 0 || x == 255));
        assert_eq!(text::fnv1a32(b"abc"), 0x1a47_e90b);
    }

    /// Cross-implementation check: `tools/train_demo_model.py` writes the
    /// demo model and, using its own independent Python implementation of
    /// the featurizer and integer inference, the expected outputs.
    #[test]
    fn demo_model_matches_python_reference() {
        let model = include_bytes!("../../models/priority-demo.cdklm");
        let vectors = include_str!("../../models/priority-demo.vectors");
        let m = Model::parse(model).unwrap();
        assert_eq!(m.feature_kind(), FeatureKind::HashedTrigrams);
        let mut checked = 0;
        for line in vectors
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let mut parts = line.split('\t');
            let text = parts.next().unwrap();
            let label = parts.next().unwrap();
            let logits: Vec<i32> = parts
                .next()
                .unwrap()
                .split(',')
                .map(|v| v.parse().unwrap())
                .collect();
            let mut x = [0u8; MAX_FEATURES];
            let x = &mut x[..m.n_features()];
            text::hashed_trigrams(text.as_bytes(), x);
            let mut got = [0i32; MAX_CLASSES];
            m.logits(x, &mut got).unwrap();
            assert_eq!(&got[..m.n_classes()], &logits[..], "logits for {text:?}");
            assert_eq!(
                m.label(m.classify(x).unwrap().class),
                label,
                "label for {text:?}"
            );
            checked += 1;
        }
        assert!(checked >= 10);
    }
}
