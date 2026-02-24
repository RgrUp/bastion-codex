use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "bastion-core", version, about = "Bastion Codex Truth Engine (v1)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Normalize KEV + NVD into canonical items.json
    Normalize {
        /// Path to KEV JSON (known_exploited_vulnerabilities.json)
        #[arg(long)]
        kev: PathBuf,
        /// Path to NVD modified JSON (nvdcve-2.0-modified.json)
        #[arg(long)]
        nvd: PathBuf,
        /// Output path for canonical items.json
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CanonicalItem {
    id: String,                      // CVE-YYYY-NNNN
    sources: Vec<String>,            // ["kev","nvd"]
    published: Option<String>,       // ISO8601
    last_modified: Option<String>,   // ISO8601
    cvss: Option<f64>,
    severity_bucket: String,         // low|medium|high|critical|unknown
    kev: bool,
    short_desc: String,
    vendor: Option<String>,
    product: Option<String>,
    refs: Vec<String>,
}

fn bucket_cvss(cvss: Option<f64>) -> String {
    match cvss {
        None => "unknown".to_string(),
        Some(s) if s >= 9.0 => "critical".to_string(),
        Some(s) if s >= 7.0 => "high".to_string(),
        Some(s) if s >= 4.0 => "medium".to_string(),
        Some(_) => "low".to_string(),
    }
}

/* -------------------- KEV parsing -------------------- */

#[derive(Debug, Deserialize)]
struct KevRoot {
    #[serde(default)]
    vulnerabilities: Vec<KevVuln>,
}

#[derive(Debug, Deserialize)]
struct KevVuln {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    vendorProject: Option<String>,
    #[serde(default)]
    dateAdded: Option<String>,
    #[serde(default)]
    dueDate: Option<String>,
    #[serde(default)]
    knownRansomwareCampaignUse: Option<String>,
    #[serde(default)]
    shortDescription: Option<String>,
    #[serde(default)]
    requiredAction: Option<String>,
}

/* -------------------- NVD parsing (minimal, tolerant) -------------------- */
/*
NVD 2.0 feed format can evolve; we parse only what we need.

We target:
- vulnerabilities[].cve.id
- vulnerabilities[].cve.published
- vulnerabilities[].cve.lastModified
- vulnerabilities[].cve.descriptions[] { lang, value }
- vulnerabilities[].cve.metrics.* (extract best available baseScore)
- vulnerabilities[].cve.references[] { url }
*/

#[derive(Debug, Deserialize)]
struct NvdRoot {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrap>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrap {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    lastModified: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdLangValue>,
    #[serde(default)]
    references: Vec<NvdRef>,
    #[serde(default)]
    metrics: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NvdLangValue {
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdRef {
    #[serde(default)]
    url: Option<String>,
}

fn pick_english_description(descs: &[NvdLangValue]) -> String {
    // prefer lang == "en"
    for d in descs {
        if d.lang.as_deref() == Some("en") {
            if let Some(v) = &d.value {
                if !v.trim().is_empty() {
                    return v.trim().to_string();
                }
            }
        }
    }
    // fallback: first non-empty
    for d in descs {
        if let Some(v) = &d.value {
            if !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
    }
    "No description available.".to_string()
}

fn extract_best_cvss(metrics: &Option<serde_json::Value>) -> Option<f64> {
    let m = metrics.as_ref()?;

    // Try common NVD metric structures in preferred order (v3.1, v3.0, v2)
    // We look for something like:
    // metrics.cvssMetricV31[0].cvssData.baseScore
    // metrics.cvssMetricV30[0].cvssData.baseScore
    // metrics.cvssMetricV2[0].cvssData.baseScore
    let candidates = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];

    for key in candidates {
        if let Some(arr) = m.get(key).and_then(|v| v.as_array()) {
            for entry in arr {
                if let Some(score) = entry
                    .get("cvssData")
                    .and_then(|v| v.get("baseScore"))
                    .and_then(|v| v.as_f64())
                {
                    return Some(score);
                }
            }
        }
    }

    None
}

/* -------------------- Main normalize logic -------------------- */

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Normalize { kev, nvd, out } => normalize_cmd(kev, nvd, out),
    }
}

fn normalize_cmd(kev_path: PathBuf, nvd_path: PathBuf, out_path: PathBuf) -> Result<()> {
    let kev_bytes = fs::read(&kev_path)
        .with_context(|| format!("Failed to read KEV file: {}", kev_path.display()))?;
    let nvd_bytes = fs::read(&nvd_path)
        .with_context(|| format!("Failed to read NVD file: {}", nvd_path.display()))?;

    let kev_root: KevRoot = serde_json::from_slice(&kev_bytes)
        .with_context(|| "Failed to parse KEV JSON")?;
    let nvd_root: NvdRoot = serde_json::from_slice(&nvd_bytes)
        .with_context(|| "Failed to parse NVD JSON")?;

    // Build KEV set + small metadata map
    let mut kev_set: HashSet<String> = HashSet::new();
    let mut kev_notes: HashMap<String, String> = HashMap::new();
    let mut kev_vendor: HashMap<String, String> = HashMap::new();
    let mut kev_product: HashMap<String, String> = HashMap::new();

    for v in kev_root.vulnerabilities {
        let id = v.cve_id.trim().to_string();
        kev_set.insert(id.clone());
        if let Some(s) = v.shortDescription.or(v.notes) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                kev_notes.insert(id.clone(), s);
            }
        }
        if let Some(vendor) = v.vendorProject {
            let vendor = vendor.trim().to_string();
            if !vendor.is_empty() {
                kev_vendor.insert(id.clone(), vendor);
            }
        }
        if let Some(prod) = v.product {
            let prod = prod.trim().to_string();
            if !prod.is_empty() {
                kev_product.insert(id.clone(), prod);
            }
        }
    }

    // Normalize NVD items
    let mut items: Vec<CanonicalItem> = Vec::with_capacity(nvd_root.vulnerabilities.len());

    for wrap in nvd_root.vulnerabilities {
        let cve = wrap.cve;
        let id = cve.id.trim().to_string();

        let cvss = extract_best_cvss(&cve.metrics);
        let mut refs: Vec<String> = cve.references.iter()
            .filter_map(|r| r.url.as_ref().map(|u| u.trim().to_string()))
            .filter(|u| !u.is_empty())
            .collect();

        // Always include the NVD detail page as a ref
        refs.push(format!("https://nvd.nist.gov/vuln/detail/{}", id));

        // Deduplicate refs
        let mut seen = HashSet::new();
        refs.retain(|r| seen.insert(r.clone()));

        // Prefer NVD description; fall back to KEV note if empty
        let mut desc = pick_english_description(&cve.descriptions);
        if desc == "No description available." {
            if let Some(k) = kev_notes.get(&id) {
                desc = k.clone();
            }
        }

        let is_kev = kev_set.contains(&id);
        let mut sources = vec!["nvd".to_string()];
        if is_kev {
            sources.push("kev".to_string());
        }

        let vendor = kev_vendor.get(&id).cloned();
        let product = kev_product.get(&id).cloned();

        let item = CanonicalItem {
            id,
            sources,
            published: cve.published,
            last_modified: cve.lastModified,
            cvss,
            severity_bucket: bucket_cvss(cvss),
            kev: is_kev,
            short_desc: desc,
            vendor,
            product,
            refs,
        };

        items.push(item);
    }

    // Also include KEV-only items that might not appear in NVD modified feed snapshot
    // (rare, but keeps completeness)
    let existing: HashSet<String> = items.iter().map(|i| i.id.clone()).collect();
    for id in kev_set {
        if !existing.contains(&id) {
            let mut refs = vec![format!("https://nvd.nist.gov/vuln/detail/{}", id)];
            let mut seen = HashSet::new();
            refs.retain(|r| seen.insert(r.clone()));

            items.push(CanonicalItem {
                id: id.clone(),
                sources: vec!["kev".to_string()],
                published: None,
                last_modified: None,
                cvss: None,
                severity_bucket: "unknown".to_string(),
                kev: true,
                short_desc: kev_notes.get(&id).cloned().unwrap_or_else(|| "KEV-listed vulnerability (details not in current NVD modified feed).".to_string()),
                vendor: kev_vendor.get(&id).cloned(),
                product: kev_product.get(&id).cloned(),
                refs,
            });
        }
    }

    // Write output
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output dir: {}", parent.display()))?;
    }

    let payload = serde_json::to_string_pretty(&items)?;
    fs::write(&out_path, payload)
        .with_context(|| format!("Failed to write output: {}", out_path.display()))?;

    let now: DateTime<Utc> = Utc::now();
    eprintln!(
        "[OK] normalize wrote {} items to {} at {}",
        items.len(),
        out_path.display(),
        now.to_rfc3339(),
    );

    Ok(())
}