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
    virtual_address: u64,
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
    let cli = Cli::parse();

    if !cli.json {
        print_banner();
    }

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
    if !cli.json {
        println!("  ✔ Analiz edilecek dosya yüklendi:");
        println!("    ├─ Dosya Adı : {}", file_name);
        println!("    ├─ Tam Yol   : {}", file_path.display());
        println!(
            "    └─ Boyut     : {} bytes ({:.2} KB)",
            file_size,
            file_size as f64 / 1024.0
        );
        println!();
    }

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

    // ── Dosya Analizi (goblin ile otomatik format tespiti) ──
    let (sections, entry_point, import_count) = analyze_executable(&file_data);

    // ── Sezgisel (Heuristic) Analiz Motoru ──
    let mut is_packed = false;
    let mut warnings = Vec::new();
    let mut entry_point_entropy = 0.0;

    for sec in &sections {
        // Entry point adresi bu section'ın sanal alanına (virtual address space) düşüyor mu?
        let is_ep_section = entry_point >= sec.virtual_address && entry_point < (sec.virtual_address + sec.virtual_size as u64);

        if is_ep_section {
            entry_point_entropy = sec.entropy;
            if sec.entropy > 7.0 {
                warnings.push("Kritik: Entry Point yüksek entropili bir bölümde".to_string());
            }
        }

        // YENİ KURAL: İsim umurumuzda değil. 
        // Eğer HERHANGİ bir bölümün entropisi > 7.2 ise VE import tablosu çok küçükse (< 10) bu %100 paketlenmiştir.
        if sec.entropy > 7.2 && import_count < 10 {
            is_packed = true;
            let msg = "Kesinlikle Sıkıştırılmış (Packed) - Antivirüs Atlatma Şüphesi".to_string();
            if !warnings.contains(&msg) {
                warnings.push(msg);
            }
        }
    }

    let heuristics = HeuristicResult {
        is_packed,
        entry_point_entropy,
        warnings,
    };

    let report = AnalysisReport {
        file_info,
        sections,
        heuristics,
    };

    // ── Çıktıyı Ekrana Yazdırma ──
    if cli.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json_output) => println!("{}", json_output),
            Err(e) => eprintln!("  [HATA] JSON oluşturulamadı: {}", e),
        }
    } else {
        println!("  ── Sezgisel Analiz Özeti ─────────────────────────────────");
        println!("    ├─ Hedef Dosya : {} ({})", report.file_info.dosya_adi, report.file_info.format);
        println!("    ├─ SHA-256     : {}", report.file_info.sha256_hash);
        println!("    ├─ Import API  : {}", import_count);
        println!("    ├─ EP Entropisi: {:.4}", report.heuristics.entry_point_entropy);
        println!("    ├─ Packed/Kripto: {}", if report.heuristics.is_packed { "EVET [!]" } else { "HAYIR" });
        println!("    └─ Bildirimler :");
        
        if report.heuristics.warnings.is_empty() {
            println!("       ✔ Temiz, olağandışı packer/kripto belirtisi yok.");
        } else {
            for warn in &report.heuristics.warnings {
                println!("       [!] {}", warn);
            }
        }
        println!();
    }
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

/// Ana analiz fonksiyonu — goblin ile dosya formatını tespit edip ilgili ayrıştırıcıya yönlendirir.
fn analyze_executable(data: &[u8]) -> (Vec<SectionInfo>, u64, usize) {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(pe)) => {
            analyze_pe(&pe, data)
        }
        Ok(goblin::Object::Elf(elf)) => {
            analyze_elf(&elf, data)
        }
        Ok(_) => {
            eprintln!("  [UYARI] Desteklenmeyen dosya formatı.");
            eprintln!("          Bu araç yalnızca PE ve ELF dosyalarını desteklemektedir.");
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

/// PE formatı için bölüm, giriş noktası ve import analizi.
fn analyze_pe(pe: &goblin::pe::PE, file_data: &[u8]) -> (Vec<SectionInfo>, u64, usize) {
    let mut sections = Vec::new();
    for s in &pe.sections {
        let isim = s.name().unwrap_or("<bilinmeyen>").to_string();
        let start = s.pointer_to_raw_data as usize;
        let raw_size = s.size_of_raw_data;
        let end = start + raw_size as usize;
        
        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };

        let entropy = calculate_entropy(section_data);
        
        sections.push(SectionInfo {
            isim,
            raw_size,
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address as u64,
            entropy,
        });
    }

    let entry_point_addr = pe.entry as u64;
    let import_count = pe.imports.len();

    (sections, entry_point_addr, import_count)
}

/// ELF formatı için bölüm, giriş noktası ve dinamik sembol analizi.
fn analyze_elf(elf: &goblin::elf::Elf, file_data: &[u8]) -> (Vec<SectionInfo>, u64, usize) {
    let mut sections = Vec::new();
    for s in &elf.section_headers {
        let isim = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("<bilinmeyen>").to_string();
        let start = s.sh_offset as usize;
        let raw_size = s.sh_size as usize;
        let end = start + raw_size;

        let section_data = if start < file_data.len() && end <= file_data.len() && start < end {
            &file_data[start..end]
        } else {
            &[]
        };

        let entropy = calculate_entropy(section_data);

        sections.push(SectionInfo {
            isim,
            raw_size: raw_size as u32,
            virtual_size: s.sh_size as u32,
            virtual_address: s.sh_addr as u64,
            entropy,
        });
    }

    let entry_point_addr = elf.entry;
    // ELF dosyalarında dışa bağımlılık listesi için dinamik semboller iyi bir göstergedir
    let import_count = elf.dynsyms.len();

    (sections, entry_point_addr, import_count)
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
