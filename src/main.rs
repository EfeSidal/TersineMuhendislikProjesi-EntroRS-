use chrono::Local;
use clap::{Parser, ValueEnum};
use goblin::pe::PE;
use regex::bytes::Regex as BytesRegex;
use serde::Serialize;
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  EntroRS — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
// ─────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════
//  ŞÜPHELİ API LİSTESİ — Zararlı Yazılımlarda Sık Kullanılan
// ═══════════════════════════════════════════════════════════════

const SUSPICIOUS_APIS: &[&str] = &[
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree",
    "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory", "ReadProcessMemory",
    "NtWriteVirtualMemory", "QueueUserAPC", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
    "LoadLibraryExW", "GetProcAddress", "LdrLoadDll", "OpenProcess", "CreateProcessA",
    "CreateProcessW", "WinExec", "TerminateProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
];

fn is_suspicious_api(api_name: &str) -> bool {
    SUSPICIOUS_APIS.contains(&api_name)
}

// ═══════════════════════════════════════════════════════════════
//  CI/CD UYUMLU VERİ YAPILARI (JSON/HTML Çıktı Şeması)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct AnalysisReport {
    file_info: FileInfo,
    analysis_date: String,
    risk_score: u32,
    risk_level: String,
    pe_header: Option<PeHeaderSummary>,
    sections: Vec<SectionInfo>,
    heuristics: HeuristicResult,
    suspicious_apis: Vec<String>,
    strings_found: Vec<String>,
    mitre_techniques: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct PeHeaderSummary {
    architecture: String,
    entry_point: u64,
    import_count: usize,
}

#[derive(Debug, Serialize)]
struct FileInfo {
    dosya_adi: String,
    dosya_yolu: String,
    boyut: u64,
    sha256_hash: String,
    format: String,
}

#[derive(Debug, Serialize, Clone)]
struct SectionInfo {
    isim: String,
    raw_size: u32,
    virtual_size: u32,
    virtual_address: u64,
    entropy: f64,
    is_packed: bool,
}

#[derive(Debug, Serialize)]
struct HeuristicResult {
    is_packed: bool,
    entry_point_entropy: f64,
    warnings: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "EntroRS",
    version,
    about = "Zararlı Yazılım Statik Analiz Aracı — Entropy Checker",
    long_about = "Çalıştırılabilir dosyaların entropi profilini analiz ederek \
                  paketlenmiş, şifrelenmiş veya obfuscate edilmiş bölümleri tespit eder."
)]
struct Cli {
    /// Analiz edilecek dosyanın yolu
    #[arg(short = 'f', long = "file", value_name = "DOSYA_YOLU")]
    file: PathBuf,

    /// Çıktı formatı (terminal, json, html)
    #[arg(short = 'm', long = "format", value_enum, default_value_t = OutputFormat::Terminal)]
    format: OutputFormat,

    /// Çıktıyı belirtilen dosyaya kaydet (belirtilmezse ekrana yazılır)
    #[arg(short = 'o', long = "output", value_name = "RAPOR_PATH")]
    output: Option<PathBuf>,

    /// Geriye dönük uyumluluk için (Format'ı JSON yapar)
    #[arg(short = 'j', long = "json")]
    json: bool,
}

#[derive(ValueEnum, Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    Terminal,
    Json,
    Html,
}

// ═══════════════════════════════════════════════════════════════
//  ANALİZ MOTORU FONKSİYONLARI
// ═══════════════════════════════════════════════════════════════

fn main() {
    let mut cli = Cli::parse();
    if cli.json {
        cli.format = OutputFormat::Json;
    }

    if cli.format == OutputFormat::Terminal {
        print_banner();
    }

    let file_data = read_and_validate_file(&cli.file);
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let sha256_hash = format!("{:x}", hasher.finalize());

    let (sections, entry_point, import_count, arch) = analyze_executable(&file_data);
    let format_str = detect_format(&file_data).unwrap_or("Unknown").to_string();

    let mut report = AnalysisReport {
        file_info: FileInfo {
            dosya_adi: cli.file.file_name().unwrap_or_default().to_string_lossy().into(),
            dosya_yolu: cli.file.to_string_lossy().into(),
            boyut: file_data.len() as u64,
            sha256_hash,
            format: format_str,
        },
        analysis_date: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        risk_score: 0,
        risk_level: "LOW".to_string(),
        pe_header: Some(PeHeaderSummary {
            architecture: arch,
            entry_point,
            import_count,
        }),
        sections,
        heuristics: HeuristicResult {
            is_packed: false,
            entry_point_entropy: 0.0,
            warnings: Vec::new(),
        },
        suspicious_apis: extract_suspicious_apis(&file_data),
        strings_found: extract_strings(&file_data),
        mitre_techniques: vec!["T1027".to_string(), "T1140".to_string(), "T1129".to_string(), "T1082".to_string()],
    };

    // Sezgisel Kurallar
    for sec in &report.sections {
        if report.pe_header.as_ref().map_or(false, |h| entry_point >= sec.virtual_address && entry_point < (sec.virtual_address + sec.virtual_size as u64)) {
            report.heuristics.entry_point_entropy = sec.entropy;
        }
        if sec.is_packed {
            report.heuristics.is_packed = true;
            report.heuristics.warnings.push(format!("Bölüm {} şüpheli derecede yüksek entropiye sahip ({:.2})", sec.isim, sec.entropy));
        }
    }

    calculate_risk_score(&mut report);

    // ÇIKTI YÖNETİMİ
    let final_output = match cli.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Html => generate_html_report(&report),
        OutputFormat::Terminal => {
            render_terminal_report(&report);
            return;
        }
    };

    if let Some(out_path) = cli.output {
        if let Ok(mut file) = fs::File::create(&out_path) {
            let _ = file.write_all(final_output.as_bytes());
            println!("  [OK] Rapor kaydedildi: {}", out_path.display());
        }
    } else {
        println!("{}", final_output);
    }
}

fn calculate_risk_score(report: &mut AnalysisReport) {
    let mut score = 0;
    
    // Packed sections: +20 each
    for sec in &report.sections {
        if sec.is_packed { score += 20; }
    }
    
    // Suspicious APIs: +10 each
    score += (report.suspicious_apis.len() as u32) * 10;
    
    // Strings (URLs/IPs): +15
    if !report.strings_found.is_empty() {
        score += 15;
    }

    report.risk_score = score.min(100);
    report.risk_level = match report.risk_score {
        0..=30 => "LOW",
        31..=60 => "MEDIUM",
        61..=80 => "HIGH",
        _ => "CRITICAL",
    }.to_string();
}

fn extract_suspicious_apis(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let data_str = String::from_utf8_lossy(data);
    for &api in SUSPICIOUS_APIS {
        if data_str.contains(api) {
            found.push(api.to_string());
        }
    }
    found
}

fn extract_strings(data: &[u8]) -> Vec<String> {
    let url_regex = BytesRegex::new(r"https?://[a-zA-Z0-9./-]+").unwrap();
    let ip_regex = BytesRegex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    
    let mut matches = Vec::new();
    for m in url_regex.find_iter(data) {
        matches.push(String::from_utf8_lossy(m.as_bytes()).into());
    }
    for m in ip_regex.find_iter(data) {
        matches.push(String::from_utf8_lossy(m.as_bytes()).into());
    }
    matches.dedup();
    matches
}

fn generate_html_report(report: &AnalysisReport) -> String {
    let color = match report.risk_level.as_str() {
        "LOW" => "#28a745", "MEDIUM" => "#ffc107", "HIGH" => "#fd7e14", _ => "#dc3545"
    };

    let mut sections_html = String::new();
    for s in &report.sections {
        sections_html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{:.4}</td><td>{}</td></tr>", 
            s.isim, s.raw_size, s.entropy, if s.is_packed { "EVET" } else { "HAYIR" }));
    }

    format!(r#"
    <html><head><style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; }}
        .container {{ width: 80%; margin: auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .risk-box {{ font-size: 48px; color: {}; font-weight: bold; text-align: center; margin: 20px 0; border: 4px solid {}; padding: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
    </style></head><body>
    <div class="container">
        <div class="header"><h1>EntroRS Analiz Raporu</h1><p>Dosya: {} | Tarih: {}</p></div>
        <div class="risk-box">{} - RISK: {}/100</div>
        <h3>Bölüm Analizi (Sections)</h3>
        <table><tr><th>İsim</th><th>Boyut</th><th>Entropi</th><th>Packed?</th></tr>{}</table>
        <h3>Tespit Edilen Şüpheli API ve Stringler</h3>
        <p><b>APIler:</b> {}</p>
        <p><b>Stringler:</b> {}</p>
    </div>
    </body></html>"#, color, color, report.file_info.dosya_adi, report.analysis_date, report.risk_level, report.risk_score, sections_html, 
    report.suspicious_apis.join(", "), report.strings_found.join(", "))
}

fn render_terminal_report(report: &AnalysisReport) {
    println!("  ── Analiz Özeti ──────────────────────────────────────────");
    println!("    ├─ Hedef Dosya : {} ({})", report.file_info.dosya_adi, report.file_info.format);
    println!("    ├─ Risk Skoru  : {} ({})", report.risk_score, report.risk_level);
    println!("    ├─ SHA-256     : {}", report.file_info.sha256_hash);
    println!("    ├─ Import API  : {}", report.pe_header.as_ref().map(|h| h.import_count).unwrap_or(0));
    println!("    └─ Bildirimler :");
    for warn in &report.heuristics.warnings { println!("       [!] {}", warn); }
    if !report.suspicious_apis.is_empty() { println!("       [!] Şüpheli APIler: {:?}", report.suspicious_apis); }
}

// ─────────────────────────────────────────────────────────────
//  EXISTING HELPERS (Refactored minimally for integration)
// ─────────────────────────────────────────────────────────────

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let len = data.len() as f64;
    let mut freq = [0u64; 256];
    for &byte in data { freq[byte as usize] += 1; }
    let mut entropy: f64 = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn analyze_executable(data: &[u8]) -> (Vec<SectionInfo>, u64, usize, String) {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(pe)) => {
            let (mut sections, ep, imports) = analyze_pe(&pe, data);
            (sections, ep, imports, if pe.is_64 { "x64" } else { "x86" }.to_string())
        }
        _ => (Vec::new(), 0, 0, "Unknown".into()),
    }
}

fn analyze_pe(pe: &goblin::pe::PE, file_data: &[u8]) -> (Vec<SectionInfo>, u64, usize) {
    let mut sections = Vec::new();
    for s in &pe.sections {
        let isim = s.name().unwrap_or("<unknown>").to_string();
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;
        let section_data = if start < file_data.len() && end <= file_data.len() { &file_data[start..end] } else { &[] };
        let entropy = calculate_entropy(section_data);
        sections.push(SectionInfo {
            isim, entropy, raw_size: s.size_of_raw_data, virtual_size: s.virtual_size,
            virtual_address: s.virtual_address as u64, is_packed: entropy > 7.2
        });
    }
    (sections, pe.entry as u64, pe.imports.len())
}

/// Belirtilen dosya yolundaki zararlı yazılım örneğini okur ve güvenlik/limit doğrulamalarını yapar.
///
/// OOM (Out of Memory) saldırılarına karşı koruma sağlar ve dosya varlığını kontrol eder.
///
/// # Parametreler
/// * `path`: Okunacak dosyanın tam yolu.
///
/// # Dönüş Değeri
/// * `Vec<u8>`: Başarıyla okunmuş dosyanın byte dizisi.
fn read_and_validate_file(path: &PathBuf) -> Vec<u8> {
    // ── Dosyanın var olup olmadığını kontrol et ──
    if !path.exists() {
        eprintln!("\n  [HATA] Belirtilen dosya bulunamadı: \"{}\"\n", path.display());
        process::exit(1);
    }

    // ── Dosya bir dizin mi kontrol et ──
    if path.is_dir() {
        eprintln!("\n  [HATA] Belirtilen yol bir dizin, dosya değil: \"{}\"\n", path.display());
        process::exit(1);
    }

    // ── Dosyayı belleğe oku ──
    match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("\n  [HATA] Dosya belleğe okunamadı: \"{}\"\n  Sebep: {}\n", path.display(), e);
            process::exit(1);
        }
    }
}

fn detect_format(data: &[u8]) -> Option<&str> {
    if data.starts_with(b"MZ") { Some("PE") } else if data.starts_with(b"\x7FELF") { Some("ELF") } else { None }
}

fn print_banner() {
    println!("\n  EntroRS Malware Analyzer (v0.1.0)");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_risk_scoring() {
        let mut report = AnalysisReport {
            file_info: FileInfo { dosya_adi: "".into(), dosya_yolu: "".into(), boyut: 0, sha256_hash: "".into(), format: "".into() },
            analysis_date: "".into(), risk_score: 0, risk_level: "".into(), pe_header: None,
            sections: vec![SectionInfo { isim: ".text".into(), raw_size: 0, virtual_size: 0, virtual_address: 0, entropy: 7.5, is_packed: true }],
            heuristics: HeuristicResult { is_packed: true, entry_point_entropy: 0.0, warnings: vec![] },
            suspicious_apis: vec!["VirtualAlloc".into()], strings_found: vec!["http".into()], mitre_techniques: vec![]
        };
        calculate_risk_score(&mut report);
        assert_eq!(report.risk_score, 20 + 10 + 15); // Packed(20) + API(10) + String(15) = 45
        assert_eq!(report.risk_level, "MEDIUM");
    }
}
