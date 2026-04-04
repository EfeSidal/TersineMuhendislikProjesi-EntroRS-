use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  tersine — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
//  Aşama 1: Proje İskeleti & CLI Kurulumu
//  Aşama 2: PE (Portable Executable) Analizi
//  Aşama 3: Matematiksel Motor — Shannon Entropisi
//  Aşama 4: Import Address Table (IAT) Analizi
// ─────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════
//  ŞÜPHELİ API LİSTESİ — Zararlı Yazılımlarda Sık Kullanılan
// ═══════════════════════════════════════════════════════════════

/// Zararlı yazılımlarda sıkça kullanılan şüpheli Windows API fonksiyonları.
/// Bu listedeki fonksiyonlar tespit edildiğinde [!] KRİTİK API ÇAĞRISI uyarısı verilir.
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

/// Zararlı yazılım statik analiz aracı.
/// Verilen dosyanın entropi profilini çıkararak
/// potansiyel paketleme / şifreleme tespiti yapar.
#[derive(Parser, Debug)]
#[command(
    name = "tersine",
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
             \n  Kullanım: tersine --file <DOSYA_YOLU>\n",
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
///
/// Sonuç 0.0 (tamamen homojen veri) ile 8.0 (tamamen rastgele veri)
/// arasında bir f64 değer döner.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;

    // Her byte değerinin (0–255) frekansını say
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    // Shannon Entropisi: H = - Σ P(x) × log₂(P(x))
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

/// Verilen byte verisini PE formatı olarak parse eder ve
/// bölüm bilgilerini, entropi ve IAT analizini yazdırır.
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

/// Bölüm tablosu satırı için veri yapısı.
struct SectionRow {
    name: String,
    raw_size: u32,
    virtual_size: u32,
    entropy: f64,
}

/// Entropi değerine göre seviye etiketi döndürür.
fn entropy_label(entropy: f64) -> &'static str {
    if entropy > 7.0 {
        "[!] Yüksek Entropi (Paketlenmiş/Şifrelenmiş)"
    } else if entropy > 6.0 {
        "[~] Sıkıştırılmış/Yoğun Veri"
    } else {
        ""
    }
}

/// Bölüm tablosu çıktısını oluşturur.
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

    // ── Entropi Özet İstatistikleri ──
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

/// DLL başına gösterilecek maksimum fonksiyon sayısı.
const MAX_FUNCTIONS_PER_DLL: usize = 10;

/// Bir fonksiyon adının şüpheli API listesinde olup olmadığını kontrol eder.
fn is_suspicious_api(name: &str) -> bool {
    SUSPICIOUS_APIS.iter().any(|&api| api == name)
}

/// 64-bit PE dosyasının import tablosunu analiz eder.
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

        dll_data.push(DllImportInfo {
            dll_name,
            functions,
        });
    }

    print_import_table(&dll_data);
}

/// 32-bit PE dosyasının import tablosunu analiz eder.
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

        dll_data.push(DllImportInfo {
            dll_name,
            functions,
        });
    }

    print_import_table(&dll_data);
}

/// DLL import bilgisi.
struct DllImportInfo {
    dll_name: String,
    functions: Vec<FunctionInfo>,
}

/// Fonksiyon bilgisi.
struct FunctionInfo {
    name: String,
    suspicious: bool,
}

/// Import tablosunu ağaç yapısında yazdırır.
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

        // DLL'deki şüpheli fonksiyon sayısını hesapla
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
                println!(
                    "  {} {} {}",
                    child_prefix, fn_prefix, func.name
                );
            }
        }

        if remaining > 0 {
            println!(
                "  {} └─ ... ve {} fonksiyon daha",
                child_prefix, remaining
            );
        }

        println!();
    }

    // ── IAT Özet ──
    println!("  ── IAT Özeti ─────────────────────────────────────────────");
    println!("    ├─ Toplam DLL       : {}", total_dlls);
    println!("    ├─ Toplam Fonksiyon : {}", total_functions);

    if total_suspicious > 0 {
        println!(
            "    └─ ⚠ {} şüpheli/kritik API çağrısı tespit edildi!",
            total_suspicious
        );
        println!();

        // Şüpheli fonksiyonların özetini yazdır
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

/// Sayıları binlik ayracıyla formatlar (örn: 1024 → "1.024").
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

/// CLI aracı için ASCII banner yazdırır.
fn print_banner() {
    println!(
        r#"
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║    ████████╗███████╗██████╗ ███████╗██╗███╗   ██╗███████╗║
  ║    ╚══██╔══╝██╔════╝██╔══██╗██╔════╝██║████╗  ██║██╔════╝║
  ║       ██║   █████╗  ██████╔╝███████╗██║██╔██╗ ██║█████╗  ║
  ║       ██║   ██╔══╝  ██╔══██╗╚════██║██║██║╚██╗██║██╔══╝  ║
  ║       ██║   ███████╗██║  ██║███████║██║██║ ╚████║███████╗║
  ║       ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝║
  ║                                                          ║
  ║   Zararlı Yazılım Statik Analiz Aracı — Entropy Checker  ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
"#
    );
}
