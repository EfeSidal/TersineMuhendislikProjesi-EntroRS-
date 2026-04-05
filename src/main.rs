use clap::Parser;
use goblin::pe::PE;
use serde::Serialize;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  EntroRS — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
//  Aşama 1: Proje İskeleti & CLI Kurulumu
//  Aşama 2: PE (Portable Executable) Analizi — goblin ile
//  Aşama 3: Matematiksel Motor — Shannon Entropisi
//  Aşama 4: Import Address Table (IAT) Analizi
// ─────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════
//  ŞÜPHELİ API LİSTESİ — Zararlı Yazılımlarda Sık Kullanılan
// ═══════════════════════════════════════════════════════════════

const SUSPICIOUS_APIS: &[&str] = &[
    // ── Bellek Manipülasyonu ──
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualFree",
    // ── Süreç Enjeksiyonu ──
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "NtWriteVirtualMemory",
    "QueueUserAPC",
    // ── DLL / Kod Yükleme ──
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "LdrLoadDll",
    // ── Süreç / Thread Yönetimi ──
    "OpenProcess",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "CreateThread",
    "SuspendThread",
    "ResumeThread",
    "TerminateProcess",
    // ── Dosya Sistemi ──
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    // ── Kayıt Defteri (Registry) ──
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    // ── Ağ / İnternet ──
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "HttpOpenRequestA",
    "HttpSendRequestA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WSAStartup",
    "connect",
    "send",
    "recv",
    // ── Anti-Debug / Anti-Analysis ──
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetTickCount",
    "QueryPerformanceCounter",
    "OutputDebugStringA",
    // ── Kripto / Şifreleme ──
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextA",
    "CryptCreateHash",
    // ── Token / Yetki Yükseltme ──
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    // ── Servis Yönetimi ──
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
    // ── Pano / Keylogger ──
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetClipboardData",
];

// ═══════════════════════════════════════════════════════════════
//  CI/CD UYUMLU VERİ YAPILARI (JSON Çıktı Şeması)
// ═══════════════════════════════════════════════════════════════

/// En dış analiz raporu yapısı — tüm sonuçları kapsar.
#[derive(Debug, Serialize)]
struct AnalysisReport {
    file_info: FileInfo,
    sections: Vec<SectionInfo>,
    heuristics: HeuristicResult,
}

/// Dosya kimlik bilgileri.
#[derive(Debug, Serialize)]
struct FileInfo {
    dosya_adi: String,
    dosya_yolu: String,
    boyut: u64,
    sha256_hash: String,
    format: String,
}

/// Bölüm (section) entropi bilgisi.
#[derive(Debug, Serialize)]
struct SectionInfo {
    isim: String,
    raw_size: u32,
    virtual_size: u32,
    entropy: f64,
}

/// Sezgisel (heuristic) analiz sonuçları.
#[derive(Debug, Serialize)]
struct HeuristicResult {
    is_packed: bool,
    entry_point_entropy: f64,
    warnings: Vec<String>,
}

/// Zararlı yazılım statik analiz aracı.
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

    /// Çıktıyı JSON formatında yazdır (CI/CD entegrasyonu için)
    #[arg(short = 'j', long = "json")]
    json: bool,
}

fn main() {
    print_banner();

    let cli = Cli::parse();
    let file_path = &cli.file;

    // ── Dosyanın var olup olmadığını kontrol et ──
    if !file_path.exists() {
        eprintln!(
            "\n  [HATA] Belirtilen dosya bulunamadı: \"{}\"\n\
             \n  Lütfen dosya yolunu kontrol edip tekrar deneyin.\n\
             \n  Kullanım: EntroRS --file <DOSYA_YOLU>\n",
            file_path.display()
        );
        process::exit(1);
    }

    // ── Bir dizin değil, dosya olduğundan emin ol ──
    if file_path.is_dir() {
        eprintln!(
            "\n  [HATA] Belirtilen yol bir dizin, dosya değil: \"{}\"\n\
             \n  Lütfen geçerli bir dosya yolu belirtin.\n",
            file_path.display()
        );
        process::exit(1);
    }

    // ── Dosya meta verisini oku ──
    let metadata = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "\n  [HATA] Dosya meta verisi okunamadı: \"{}\"\n\
                 \n  Sebep: {}\n",
                file_path.display(),
                e
            );
            process::exit(1);
        }
    };

    let file_size = metadata.len();
    let file_name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "<bilinmeyen>".to_string());

    // ── Temel dosya bilgisi çıktısı ──
    println!("  ✔ Analiz edilecek dosya yüklendi:");
    println!("    ├─ Dosya Adı : {}", file_name);
    println!("    ├─ Tam Yol   : {}", file_path.display());
    println!(
        "    └─ Boyut     : {} bytes ({:.2} KB)",
        file_size,
        file_size as f64 / 1024.0
    );
    println!();

    // ── OOM Koruması: Pumped malware savunması (256 MB limit) ──
    const MAX_FILE_SIZE: u64 = 268_435_456; // 256 MB
    if file_size > MAX_FILE_SIZE {
        eprintln!(
            "\n  [HATA] Dosya boyutu çok büyük ({:.2} MB). RAM limitini (256 MB) aşıyor.\
             \n         Analiz reddedildi.\n",
            file_size as f64 / (1024.0 * 1024.0)
        );
        process::exit(1);
    }

    // ── Dosyayı belleğe oku ──
    let file_data = match fs::read(file_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!(
                "  [HATA] Dosya belleğe okunamadı: \"{}\"\n\
                 \n  Sebep: {}\n",
                file_path.display(),
                e
            );
            process::exit(1);
        }
    };

    // ── SHA-256 Hash Hesaplama ──
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let sha256_hash = format!("{:x}", hasher.finalize());

    // ── Magic Bytes Kontrolü & Format Belirleme ──
    let format_str = if file_data.starts_with(b"MZ") {
        "PE".to_string()
    } else if file_data.starts_with(b"\x7FELF") {
        "ELF".to_string()
    } else {
        eprintln!(
            "  [HATA] Desteklenmeyen Format.\n\
             \n  Dosya PE veya ELF formatında değil (MZ veya \\x7FELF imzası bulunamadı).\n"
        );
        process::exit(1);
    };

    // ── FileInfo Doldurma ──
    let file_info = FileInfo {
        dosya_adi: file_name,
        dosya_yolu: file_path.to_string_lossy().to_string(),
        boyut: file_size,
        sha256_hash,
        format: format_str,
    };

    // Şimdilik derlenmesi için file_info'yu bastırıyoruz (veya analiz fonksiyonuna aktaracağız)
    if cli.json {
        // İleride AnalysisReport içine koyulacak
    }

    // ── Dosya Analizi (goblin ile otomatik format tespiti) ──
    analyze_executable(&file_data);
}

// ═══════════════════════════════════════════════════════════════
//  MATEMATİKSEL MOTOR — SHANNON ENTROPİSİ
// ═══════════════════════════════════════════════════════════════

/// Verilen byte dizisinin Shannon Entropisini hesaplar.
///
/// Formül: H(X) = - Σ P(xᵢ) × log₂(P(xᵢ))
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut entropy: f64 = 0.0;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

// ═══════════════════════════════════════════════════════════════
//  DOSYA ANALİZ FONKSİYONLARI (goblin)
// ═══════════════════════════════════════════════════════════════

/// Ana analiz fonksiyonu — goblin ile dosya formatını otomatik tespit eder.
fn analyze_executable(data: &[u8]) {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(pe)) => {
            let bitness = if pe.is_64 { "PE32+ (64-bit)" } else { "PE32 (32-bit)" };
            println!("  ── PE (Portable Executable) Analizi ──────────────────────");
            println!();
            println!("  ✔ Geçerli PE dosyası tespit edildi: {}", bitness);
            println!();
            analyze_pe_sections(&pe, data);
            analyze_pe_imports(&pe);
        }
        Ok(goblin::Object::Elf(elf)) => {
            let bitness = if elf.is_64 { "ELF64 (64-bit)" } else { "ELF32 (32-bit)" };
            println!("  ── ELF (Executable and Linkable Format) Analizi ─────────");
            println!();
            println!("  ✔ Geçerli ELF dosyası tespit edildi: {}", bitness);
            println!();
            analyze_elf_sections(&elf, data);
        }
        Ok(_) => {
            eprintln!("  [UYARI] Desteklenmeyen dosya formatı.");
            eprintln!("          Bu araç PE ve ELF dosyalarını desteklemektedir.");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("  [UYARI] Dosya parse edilemedi: {}", e);
            eprintln!();
            eprintln!("  İpucu: Dosya korumalı, bozulmuş veya desteklenmeyen bir formatta olabilir.");
            process::exit(1);
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  PE BÖLÜM (SECTION) ANALİZİ
// ─────────────────────────────────────────────────────────────

struct SectionRow {
    name: String,
    raw_size: u32,
    virtual_size: u32,
    entropy: f64,
}

/// PE dosyasının bölümlerini entropi ile birlikte analiz eder (goblin).
fn analyze_pe_sections(pe: &PE, file_data: &[u8]) {
    let sections = &pe.sections;
    let section_count = sections.len();

    let rows: Vec<SectionRow> = sections.iter().map(|s| {
        let name = s.name().unwrap_or("<bilinmeyen>").to_string();
        let start = s.pointer_to_raw_data as usize;
        let raw_size = s.size_of_raw_data;
        let end = start + raw_size as usize;
        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(section_data);
        SectionRow {
            name,
            raw_size,
            virtual_size: s.virtual_size,
            entropy,
        }
    }).collect();

    print_section_table(section_count, &rows);
}

// ─────────────────────────────────────────────────────────────
//  ELF BÖLÜM (SECTION) ANALİZİ
// ─────────────────────────────────────────────────────────────

/// ELF dosyasının bölümlerini entropi ile birlikte analiz eder (goblin).
fn analyze_elf_sections(elf: &goblin::elf::Elf, file_data: &[u8]) {
    let sections = &elf.section_headers;
    let section_count = sections.len();

    let rows: Vec<SectionRow> = sections.iter().map(|s| {
        let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("<bilinmeyen>").to_string();
        let start = s.sh_offset as usize;
        let size = s.sh_size as usize;
        let end = start + size;
        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(section_data);
        SectionRow {
            name,
            raw_size: size as u32,
            virtual_size: s.sh_size as u32,
            entropy,
        }
    }).collect();

    print_section_table(section_count, &rows);
}

fn entropy_label(entropy: f64) -> &'static str {
    if entropy > 7.0 {
        "[!] Yüksek Entropi (Paketlenmiş/Şifrelenmiş)"
    } else if entropy > 6.0 {
        "[~] Sıkıştırılmış/Yoğun Veri"
    } else {
        ""
    }
}

fn print_section_table(section_count: usize, rows: &[SectionRow]) {
    println!(
        "  ── Bölüm Tablosu ({} bölüm bulundu) ──────────────────────────────────",
        section_count
    );
    println!();
    println!(
        "  {:<4} {:<12} {:>14} {:>14} {:>10}   {}",
        "#", "Bölüm Adı", "Raw Size", "Virtual Size", "Entropy", "Durum"
    );
    println!("  {}", "─".repeat(88));

    for (i, row) in rows.iter().enumerate() {
        let label = entropy_label(row.entropy);
        println!(
            "  {:<4} {:<12} {:>10} B {:>10} B {:>10.4}   {}",
            i + 1,
            row.name,
            format_number(row.raw_size),
            format_number(row.virtual_size),
            row.entropy,
            label
        );
    }

    println!("  {}", "─".repeat(88));
    println!();

    if !rows.is_empty() {
        let entropies: Vec<f64> = rows.iter().map(|r| r.entropy).collect();
        let max_e = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_e = entropies.iter().cloned().fold(f64::INFINITY, f64::min);
        let avg_e = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let high_count = entropies.iter().filter(|&&e| e > 7.0).count();

        println!("  ── Entropi Özeti ─────────────────────────────────────────");
        println!("    ├─ En Düşük  : {:.4}", min_e);
        println!("    ├─ Ortalama  : {:.4}", avg_e);
        println!("    ├─ En Yüksek : {:.4}", max_e);

        if high_count > 0 {
            println!(
                "    └─ ⚠ {} bölüm yüksek entropiye sahip (>7.0) — Paketleme/şifreleme şüphesi!",
                high_count
            );
        } else {
            println!("    └─ ✔ Yüksek entropi tespit edilmedi.");
        }
        println!();
    }

    println!("  [BİLGİ] Bölüm analizi ve entropi taraması tamamlandı.");
    println!();
}

// ─────────────────────────────────────────────────────────────
//  PE IAT (IMPORT ADDRESS TABLE) ANALİZİ
// ─────────────────────────────────────────────────────────────

const MAX_FUNCTIONS_PER_DLL: usize = 10;

fn is_suspicious_api(name: &str) -> bool {
    SUSPICIOUS_APIS.iter().any(|&api| api == name)
}

struct DllImportInfo {
    dll_name: String,
    functions: Vec<FunctionInfo>,
}

struct FunctionInfo {
    name: String,
    suspicious: bool,
}

/// PE dosyasının import tablosunu analiz eder (goblin).
fn analyze_pe_imports(pe: &PE) {
    println!("  ── Import Address Table (IAT) Analizi ────────────────────");
    println!();

    let imports = &pe.imports;
    if imports.is_empty() {
        println!("    Import tablosu boş veya bulunamadı.");
        println!();
        return;
    }

    // Import'ları DLL bazında grupla
    let mut dll_map: std::collections::BTreeMap<String, Vec<FunctionInfo>> =
        std::collections::BTreeMap::new();

    for import in imports {
        let dll_name = import.dll.to_string();
        let fn_name = if import.name.is_empty() {
            format!("Ordinal({})", import.ordinal)
        } else {
            import.name.to_string()
        };
        let suspicious = is_suspicious_api(&fn_name);
        dll_map
            .entry(dll_name)
            .or_default()
            .push(FunctionInfo { name: fn_name, suspicious });
    }

    let dll_data: Vec<DllImportInfo> = dll_map
        .into_iter()
        .map(|(dll_name, functions)| DllImportInfo { dll_name, functions })
        .collect();

    print_import_table(&dll_data);
}

fn print_import_table(dll_data: &[DllImportInfo]) {
    if dll_data.is_empty() {
        println!("    Import tablosu boş veya bulunamadı.");
        println!();
        return;
    }

    let total_dlls = dll_data.len();
    let total_functions: usize = dll_data.iter().map(|d| d.functions.len()).sum();
    let total_suspicious: usize = dll_data
        .iter()
        .flat_map(|d| d.functions.iter())
        .filter(|f| f.suspicious)
        .count();

    println!(
        "  ✔ {} DLL, toplam {} fonksiyon tespit edildi.",
        total_dlls, total_functions
    );
    println!();

    for (dll_idx, dll) in dll_data.iter().enumerate() {
        let is_last_dll = dll_idx == total_dlls - 1;
        let dll_prefix = if is_last_dll { "└─" } else { "├─" };
        let child_prefix = if is_last_dll { "   " } else { "│  " };

        let dll_suspicious_count = dll.functions.iter().filter(|f| f.suspicious).count();
        let dll_warning = if dll_suspicious_count > 0 {
            format!("  ⚠ {} şüpheli API", dll_suspicious_count)
        } else {
            String::new()
        };

        println!(
            "  {} 📦 {} ({} fonksiyon){}",
            dll_prefix,
            dll.dll_name,
            dll.functions.len(),
            dll_warning
        );

        let display_count = dll.functions.len().min(MAX_FUNCTIONS_PER_DLL);
        let remaining = dll.functions.len().saturating_sub(MAX_FUNCTIONS_PER_DLL);

        for (fn_idx, func) in dll.functions.iter().take(display_count).enumerate() {
            let is_last_fn = fn_idx == display_count - 1 && remaining == 0;
            let fn_prefix = if is_last_fn { "└─" } else { "├─" };

            if func.suspicious {
                println!(
                    "  {} {} {} [!] KRİTİK API ÇAĞRISI",
                    child_prefix, fn_prefix, func.name
                );
            } else {
                println!("  {} {} {}", child_prefix, fn_prefix, func.name);
            }
        }

        if remaining > 0 {
            println!("  {} └─ ... ve {} fonksiyon daha", child_prefix, remaining);
        }

        println!();
    }

    // ── IAT Özeti ──
    println!("  ── IAT Özeti ─────────────────────────────────────────────");
    println!("    ├─ Toplam DLL       : {}", total_dlls);
    println!("    ├─ Toplam Fonksiyon : {}", total_functions);

    if total_suspicious > 0 {
        println!(
            "    └─ ⚠ {} şüpheli/kritik API çağrısı tespit edildi!",
            total_suspicious
        );
        println!();

        println!("  ── Tespit Edilen Kritik API Çağrıları ────────────────────");
        for dll in dll_data {
            for func in &dll.functions {
                if func.suspicious {
                    println!("    [!] {} → {}", dll.dll_name, func.name);
                }
            }
        }
    } else {
        println!("    └─ ✔ Şüpheli API çağrısı tespit edilmedi.");
    }

    println!();
    println!("  [BİLGİ] IAT analizi tamamlandı.");
    println!();
}

// ═══════════════════════════════════════════════════════════════
//  YARDIMCI FONKSİYONLAR
// ═══════════════════════════════════════════════════════════════

fn format_number(n: u32) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push('.');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn print_banner() {
    println!(
        r#"
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║   ███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ███████╗║
  ║   ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝║
  ║   █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██████╔╝███████╗║
  ║   ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██╔══██╗╚════██║║
  ║   ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║  ██║███████║║
  ║   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝║
  ║                                                          ║
  ║   Zararlı Yazılım Statik Analiz Aracı — Entropy Checker  ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
"#
    );
}
