use clap::Parser;
use regex::Regex;
use std::fs;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  EntroRS — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
//  Aşama 1: Proje İskeleti & CLI Kurulumu
//  Aşama 2: PE (Portable Executable) Analizi
//  Aşama 3: Matematiksel Motor — Shannon Entropisi
//  Aşama 4: Import Address Table (IAT) Analizi
//  Aşama 5: Strings Analysis — Metin Ayıklama & Şüpheli Desen Tarama
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
//  STRINGS ANALİZİ SABİTLERİ
// ═══════════════════════════════════════════════════════════════

/// String olarak kabul edilecek minimum karakter uzunluğu.
const MIN_STRING_LENGTH: usize = 5;

/// Performans için taranacak maksimum string sayısı.
const MAX_STRINGS_TO_SCAN: usize = 1000;

/// Genel string çıktısında gösterilecek maksimum string sayısı.
const MAX_STRINGS_TO_DISPLAY: usize = 30;

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

    // ── PE Analizi ──
    analyze_pe(&file_data);
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
//  PE ANALİZ FONKSİYONLARI
// ═══════════════════════════════════════════════════════════════

/// Ana PE analiz fonksiyonu — tüm aşamaları sırayla çalıştırır.
fn analyze_pe(data: &[u8]) {
    println!("  ── PE (Portable Executable) Analizi ──────────────────────");
    println!();

    // MZ imzası kontrolü
    if data.len() < 2 || data[0] != b'M' || data[1] != b'Z' {
        eprintln!("  [UYARI] Bu geçerli bir Windows PE dosyası değil.");
        eprintln!("          Dosya \"MZ\" imzası ile başlamıyor.");
        eprintln!();
        eprintln!("  İpucu: Bu araç şu anda yalnızca Windows PE (.exe, .dll, .sys)");
        eprintln!("         dosyalarını desteklemektedir.");
        process::exit(1);
    }

    // pelite ile PE'yi parse et
    if let Ok(pe64) = pelite::pe64::PeFile::from_bytes(data) {
        println!("  ✔ Geçerli PE dosyası tespit edildi: PE32+ (64-bit)");
        println!();
        print_sections_64(&pe64, data);
        analyze_imports_64(&pe64);
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(data) {
        println!("  ✔ Geçerli PE dosyası tespit edildi: PE32 (32-bit)");
        println!();
        print_sections_32(&pe32, data);
        analyze_imports_32(&pe32);
    } else {
        eprintln!("  [UYARI] Bu geçerli bir Windows PE dosyası değil.");
        eprintln!("          Dosya MZ imzasına sahip ancak PE yapısı bozuk veya tanınmıyor.");
        eprintln!();
        eprintln!("  İpucu: Dosya korumalı, bozulmuş veya desteklenmeyen bir formatta olabilir.");
        process::exit(1);
    }

    // Aşama 5: Strings Analizi (PE türünden bağımsız, ham veri üzerinde çalışır)
    analyze_strings(data);
}

// ─────────────────────────────────────────────────────────────
//  BÖLÜM (SECTION) ANALİZİ
// ─────────────────────────────────────────────────────────────

/// 64-bit PE dosyasının bölümlerini entropi ile birlikte yazdırır.
fn print_sections_64(pe: &pelite::pe64::PeFile, file_data: &[u8]) {
    use pelite::pe64::Pe;

    let sections = pe.section_headers();
    let section_count = sections.image().len();

    let rows: Vec<SectionRow> = sections.iter().map(|s| {
        let name = s.name().unwrap_or_else(|bytes| {
            std::str::from_utf8(bytes).unwrap_or("<bilinmeyen>")
        });
        let range = s.file_range();
        let start = range.start as usize;
        let end = range.end as usize;
        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(section_data);
        SectionRow {
            name: name.to_string(),
            raw_size: s.SizeOfRawData,
            virtual_size: s.VirtualSize,
            entropy,
        }
    }).collect();

    print_section_table(section_count, &rows);
}

/// 32-bit PE dosyasının bölümlerini entropi ile birlikte yazdırır.
fn print_sections_32(pe: &pelite::pe32::PeFile, file_data: &[u8]) {
    use pelite::pe32::Pe;

    let sections = pe.section_headers();
    let section_count = sections.image().len();

    let rows: Vec<SectionRow> = sections.iter().map(|s| {
        let name = s.name().unwrap_or_else(|bytes| {
            std::str::from_utf8(bytes).unwrap_or("<bilinmeyen>")
        });
        let range = s.file_range();
        let start = range.start as usize;
        let end = range.end as usize;
        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(section_data);
        SectionRow {
            name: name.to_string(),
            raw_size: s.SizeOfRawData,
            virtual_size: s.VirtualSize,
            entropy,
        }
    }).collect();

    print_section_table(section_count, &rows);
}

struct SectionRow {
    name: String,
    raw_size: u32,
    virtual_size: u32,
    entropy: f64,
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

    println!("  [BİLGİ] PE bölüm analizi ve entropi taraması tamamlandı.");
    println!();
}

// ─────────────────────────────────────────────────────────────
//  IAT (IMPORT ADDRESS TABLE) ANALİZİ
// ─────────────────────────────────────────────────────────────

const MAX_FUNCTIONS_PER_DLL: usize = 10;

fn is_suspicious_api(name: &str) -> bool {
    SUSPICIOUS_APIS.iter().any(|&api| api == name)
}

fn analyze_imports_64(pe: &pelite::pe64::PeFile) {
    use pelite::pe64::Pe;

    let imports = match pe.imports() {
        Ok(imports) => imports,
        Err(_) => {
            println!("  [BİLGİ] Import tablosu bulunamadı veya okunamadı.");
            println!();
            return;
        }
    };

    let mut dll_data: Vec<DllImportInfo> = Vec::new();

    for desc in imports {
        let dll_name = match desc.dll_name() {
            Ok(name) => name.to_str().unwrap_or("<bilinmeyen>").to_string(),
            Err(_) => continue,
        };

        let int = match desc.int() {
            Ok(int) => int,
            Err(_) => continue,
        };

        let mut functions: Vec<FunctionInfo> = Vec::new();
        for import in int {
            if let Ok(import) = import {
                match import {
                    pelite::pe64::imports::Import::ByName { name, .. } => {
                        let fn_name = name.to_str().unwrap_or("<bilinmeyen>").to_string();
                        let suspicious = is_suspicious_api(&fn_name);
                        functions.push(FunctionInfo { name: fn_name, suspicious });
                    }
                    pelite::pe64::imports::Import::ByOrdinal { ord } => {
                        functions.push(FunctionInfo {
                            name: format!("Ordinal({})", ord),
                            suspicious: false,
                        });
                    }
                }
            }
        }

        dll_data.push(DllImportInfo { dll_name, functions });
    }

    print_import_table(&dll_data);
}

fn analyze_imports_32(pe: &pelite::pe32::PeFile) {
    use pelite::pe32::Pe;

    let imports = match pe.imports() {
        Ok(imports) => imports,
        Err(_) => {
            println!("  [BİLGİ] Import tablosu bulunamadı veya okunamadı.");
            println!();
            return;
        }
    };

    let mut dll_data: Vec<DllImportInfo> = Vec::new();

    for desc in imports {
        let dll_name = match desc.dll_name() {
            Ok(name) => name.to_str().unwrap_or("<bilinmeyen>").to_string(),
            Err(_) => continue,
        };

        let int = match desc.int() {
            Ok(int) => int,
            Err(_) => continue,
        };

        let mut functions: Vec<FunctionInfo> = Vec::new();
        for import in int {
            if let Ok(import) = import {
                match import {
                    pelite::pe32::imports::Import::ByName { name, .. } => {
                        let fn_name = name.to_str().unwrap_or("<bilinmeyen>").to_string();
                        let suspicious = is_suspicious_api(&fn_name);
                        functions.push(FunctionInfo { name: fn_name, suspicious });
                    }
                    pelite::pe32::imports::Import::ByOrdinal { ord } => {
                        functions.push(FunctionInfo {
                            name: format!("Ordinal({})", ord),
                            suspicious: false,
                        });
                    }
                }
            }
        }

        dll_data.push(DllImportInfo { dll_name, functions });
    }

    print_import_table(&dll_data);
}

struct DllImportInfo {
    dll_name: String,
    functions: Vec<FunctionInfo>,
}

struct FunctionInfo {
    name: String,
    suspicious: bool,
}

fn print_import_table(dll_data: &[DllImportInfo]) {
    println!("  ── Import Address Table (IAT) Analizi ────────────────────");
    println!();

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

// ─────────────────────────────────────────────────────────────
//  STRINGS ANALİZİ — METİN AYIKLAMA & ŞÜPHELİ DESEN TARAMA
// ─────────────────────────────────────────────────────────────

/// Dosyanın ham byte verisinden ASCII stringleri ayıklar.
/// Minimum `MIN_STRING_LENGTH` uzunluğundaki yazdırılabilir ASCII dizilerini toplar.
/// Performans için en fazla `MAX_STRINGS_TO_SCAN` string döndürür.
fn extract_ascii_strings(data: &[u8]) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        // Yazdırılabilir ASCII aralığı: 0x20 (boşluk) – 0x7E (~)
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte);
        } else {
            if current.len() >= MIN_STRING_LENGTH {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                    if strings.len() >= MAX_STRINGS_TO_SCAN {
                        break;
                    }
                }
            }
            current.clear();
        }
    }

    // Son kalan buffer'ı kontrol et
    if current.len() >= MIN_STRING_LENGTH && strings.len() < MAX_STRINGS_TO_SCAN {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}

/// Şüpheli string bulgusu.
struct SuspiciousString {
    value: String,
    category: &'static str,
    severity: &'static str,
}

/// Ayıklanan stringleri regex ile şüpheli desenler için tarar.
fn scan_suspicious_patterns(strings: &[String]) -> Vec<SuspiciousString> {
    let mut findings: Vec<SuspiciousString> = Vec::new();

    // ── Regex Desenleri ──
    // IPv4 adresi: 1.2.3.4 formatı (0.x.x.x ve 255.x.x.x dahil)
    let re_ipv4 = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).expect("IPv4 regex derleme hatası");

    // URL: http:// veya https:// ile başlayan
    let re_url = Regex::new(
        r#"https?://[^\s<>"\x00-\x1f]{3,}"#
    ).expect("URL regex derleme hatası");

    // Çalıştırılabilir dosya uzantıları
    let re_exe_ext = Regex::new(
        r"(?i)\b\w+\.(exe|dll|sys|bat|cmd|ps1|vbs|scr|pif|com|msi)\b"
    ).expect("Dosya uzantısı regex derleme hatası");

    // E-posta adresi
    let re_email = Regex::new(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ).expect("E-posta regex derleme hatası");

    // Registry yolları
    let re_registry = Regex::new(
        r"(?i)(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s]+"
    ).expect("Registry regex derleme hatası");

    // Dosya yolları (C:\... veya \\...) 
    let re_filepath = Regex::new(
        r#"(?i)([A-Z]:\\[^\s<>"]{5,}|\\\\[^\s<>"]{5,})"#
    ).expect("Dosya yolu regex derleme hatası");

    for s in strings {
        // IP adresi tespiti
        for mat in re_ipv4.find_iter(s) {
            let ip = mat.as_str();
            // Loopback ve yaygın false-positive'leri atla
            if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "255.255.255.255" {
                findings.push(SuspiciousString {
                    value: ip.to_string(),
                    category: "IP Adresi",
                    severity: "KRİTİK",
                });
            }
        }

        // URL tespiti
        for mat in re_url.find_iter(s) {
            findings.push(SuspiciousString {
                value: mat.as_str().to_string(),
                category: "URL / Bağlantı",
                severity: "KRİTİK",
            });
        }

        // Çalıştırılabilir dosya uzantısı
        for mat in re_exe_ext.find_iter(s) {
            let matched = mat.as_str();
            // Çok kısa veya genel string'leri atla
            if matched.len() > 4 {
                findings.push(SuspiciousString {
                    value: matched.to_string(),
                    category: "Çalıştırılabilir Dosya",
                    severity: "ORTA",
                });
            }
        }

        // E-posta adresi
        for mat in re_email.find_iter(s) {
            findings.push(SuspiciousString {
                value: mat.as_str().to_string(),
                category: "E-Posta Adresi",
                severity: "ORTA",
            });
        }

        // Registry yolu
        for mat in re_registry.find_iter(s) {
            findings.push(SuspiciousString {
                value: mat.as_str().to_string(),
                category: "Registry Yolu",
                severity: "ORTA",
            });
        }

        // Dosya yolu
        for mat in re_filepath.find_iter(s) {
            findings.push(SuspiciousString {
                value: mat.as_str().to_string(),
                category: "Dosya Yolu",
                severity: "DÜŞÜK",
            });
        }
    }

    // Yinelenenleri kaldır (aynı value+category çifti)
    findings.sort_by(|a, b| a.value.cmp(&b.value));
    findings.dedup_by(|a, b| a.value == b.value && a.category == b.category);

    findings
}

/// Strings analizini çalıştırır ve sonuçları ekrana yazdırır.
fn analyze_strings(data: &[u8]) {
    println!("  ── Strings Analizi (Metin Ayıklama) ──────────────────────");
    println!();

    // 1. ASCII stringleri ayıkla
    let strings = extract_ascii_strings(data);
    let total_strings = strings.len();

    println!(
        "  ✔ {} okunabilir ASCII string ayıklandı (min {} karakter).",
        total_strings, MIN_STRING_LENGTH
    );

    if total_strings >= MAX_STRINGS_TO_SCAN {
        println!(
            "    ⓘ Performans limiti: İlk {} string tarandı.",
            MAX_STRINGS_TO_SCAN
        );
    }
    println!();

    // 2. Genel string örneklerini göster
    if !strings.is_empty() {
        let show_count = strings.len().min(MAX_STRINGS_TO_DISPLAY);
        let remaining = strings.len().saturating_sub(MAX_STRINGS_TO_DISPLAY);

        println!("  ── Ayıklanan Stringler (ilk {}) ────────────────────────", show_count);
        println!();

        for (i, s) in strings.iter().take(show_count).enumerate() {
            // Uzun stringleri kısalt
            let display = if s.len() > 80 {
                format!("{}...", &s[..77])
            } else {
                s.clone()
            };
            println!("    {:>4}. {}", i + 1, display);
        }

        if remaining > 0 {
            println!();
            println!("    ... ve {} string daha.", remaining);
        }
        println!();
    }

    // 3. Şüpheli desen taraması
    let findings = scan_suspicious_patterns(&strings);

    println!("  ── Şüpheli Metin Analizi ─────────────────────────────────");
    println!();

    if findings.is_empty() {
        println!("    ✔ Şüpheli metin deseni tespit edilmedi.");
        println!();
    } else {
        println!(
            "    ⚠ {} şüpheli bulgu tespit edildi!\n",
            findings.len()
        );

        // Bulguları önceliklere göre grupla
        let critical: Vec<&SuspiciousString> =
            findings.iter().filter(|f| f.severity == "KRİTİK").collect();
        let medium: Vec<&SuspiciousString> =
            findings.iter().filter(|f| f.severity == "ORTA").collect();
        let low: Vec<&SuspiciousString> =
            findings.iter().filter(|f| f.severity == "DÜŞÜK").collect();

        if !critical.is_empty() {
            println!("    ┌─ KRİTİK SEVİYE ──────────────────────────────────");
            for f in &critical {
                println!(
                    "    │ [!] KRİTİK: {} → {}",
                    f.category, f.value
                );
            }
            println!("    └──────────────────────────────────────────────────");
            println!();
        }

        if !medium.is_empty() {
            println!("    ┌─ ORTA SEVİYE ───────────────────────────────────");
            for f in &medium {
                println!(
                    "    │ [~] ORTA: {} → {}",
                    f.category, f.value
                );
            }
            println!("    └──────────────────────────────────────────────────");
            println!();
        }

        if !low.is_empty() {
            println!("    ┌─ DÜŞÜK SEVİYE ─────────────────────────────────");
            for f in &low {
                println!(
                    "    │ [·] DÜŞÜK: {} → {}",
                    f.category, f.value
                );
            }
            println!("    └──────────────────────────────────────────────────");
            println!();
        }
    }

    // 4. Strings Özeti
    println!("  ── Strings Özeti ─────────────────────────────────────────");
    println!("    ├─ Toplam String       : {}", total_strings);
    println!("    ├─ Şüpheli Bulgu      : {}", findings.len());

    let ip_count = findings.iter().filter(|f| f.category == "IP Adresi").count();
    let url_count = findings.iter().filter(|f| f.category == "URL / Bağlantı").count();
    let exe_count = findings.iter().filter(|f| f.category == "Çalıştırılabilir Dosya").count();
    let email_count = findings.iter().filter(|f| f.category == "E-Posta Adresi").count();
    let reg_count = findings.iter().filter(|f| f.category == "Registry Yolu").count();
    let path_count = findings.iter().filter(|f| f.category == "Dosya Yolu").count();

    if ip_count > 0 { println!("    │  ├─ IP Adresleri     : {}", ip_count); }
    if url_count > 0 { println!("    │  ├─ URL'ler          : {}", url_count); }
    if exe_count > 0 { println!("    │  ├─ Çalıştırılabilir  : {}", exe_count); }
    if email_count > 0 { println!("    │  ├─ E-Posta          : {}", email_count); }
    if reg_count > 0 { println!("    │  ├─ Registry Yolları : {}", reg_count); }
    if path_count > 0 { println!("    │  └─ Dosya Yolları    : {}", path_count); }

    let critical_total = findings.iter().filter(|f| f.severity == "KRİTİK").count();
    if critical_total > 0 {
        println!(
            "    └─ ⚠ {} kritik seviye bulgu — C2 sunucu bağlantısı veya payload indirme şüphesi!",
            critical_total
        );
    } else {
        println!("    └─ ✔ Kritik seviye bulgu tespit edilmedi.");
    }

    println!();
    println!("  [BİLGİ] Strings analizi tamamlandı.");
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
