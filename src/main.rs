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

/// Verilen API isminin şüpheli (Suspicious) API listesinde olup olmadığını kontrol eder.
///
/// # Parametreler
/// * `api_name`: Kontrol edilecek API fonksiyon ismi.
///
/// # Dönüş Değeri
/// * `bool`: Liste içindeyse `true`, değilse `false`.
fn is_suspicious_api(api_name: &str) -> bool {
    SUSPICIOUS_APIS.contains(&api_name)
}

// ═══════════════════════════════════════════════════════════════
//  CI/CD UYUMLU VERİ YAPILARI (JSON Çıktı Şeması)
// ═══════════════════════════════════════════════════════════════

/// En dış analiz raporu yapısı — bir dosyanın tüm statik analiz sonuçlarını kapsar.
///
/// Bu yapı, JSON formatında serileştirilebilmesi için tasarlanmıştır. CI/CD
/// boru hatlarında ve SIEM gibi üçüncü parti güvenlik araçlarında kullanılabilir.
///
/// * `file_info`: Analiz edilen dosyanın yolları ve hash değerleri gibi temel kimlik bilgileri.
/// * `sections`: PE/ELF dosyasının içerdiği tüm bölümlerin ve entropi değerlerinin listesi.
/// * `heuristics`: Paketleyici veya şifreleyici şüphesi barındıran kritik uyarılar.
#[derive(Debug, Serialize)]
struct AnalysisReport {
    file_info: FileInfo,
    sections: Vec<SectionInfo>,
    heuristics: HeuristicResult,
}

/// Hedef dosyanın kimlik ve metadata bilgileri.
///
/// Dosyanın işletim sistemindeki yolundan kriptografik hash değerine kadar
/// temel tanımlayıcı özelliklerini taşır.
///
/// * `dosya_adi`: Hedef dosyanın adı (ör: `malware.exe`).
/// * `dosya_yolu`: Dosyanın bulunduğu dizinin tam yolu.
/// * `boyut`: Dosyanın byte cinsinden disk boyutu.
/// * `sha256_hash`: Zararlı yazılım analizinde kritik öneme sahip SHA-256 özeti.
/// * `format`: Dosyanın çalışma zamanı formatı (ör: `PE` veya `ELF`).
#[derive(Debug, Serialize)]
struct FileInfo {
    dosya_adi: String,
    dosya_yolu: String,
    boyut: u64,
    sha256_hash: String,
    format: String,
}

/// PE veya ELF dosyalarındaki çalıştırılabilir veya veri bölümlerine (sections) ait analiz bilgisi.
///
/// Her bir bölümün boyutunu ve içindeki verinin entropisini barındırır. Yüksek entropi,
/// bölümün muhtemelen paketlenmiş veya şifrelenmiş olduğuna işaret eder.
///
/// * `isim`: Bölümün adı (ör: `.text`, `.data`, `.rsrc`).
/// * `raw_size`: Disk üzerindeki ham boyutu (byte).
/// * `virtual_size`: Belleğe yüklendiğindeki boyutu (byte).
/// * `virtual_address`: Bölümün bellekteki sanal adres offset'i.
/// * `entropy`: Shannon entropi değeri (0.0 ile 8.0 arasında).
#[derive(Debug, Serialize)]
struct SectionInfo {
    isim: String,
    raw_size: u32,
    virtual_size: u32,
    virtual_address: u64,
    entropy: f64,
}

/// Sezgisel (Heuristic) analiz motorunun karar ve uyarılarını barındırır.
///
/// Analiz aracının şüpheli durumlar için yaptığı çıkarımları sunar.
///
/// * `is_packed`: İstatiksel verilere dayanarak dosyanın paketlenmiş/şifrelenmiş olup olmadığı durumu.
/// * `entry_point_entropy`: Kodun ilk çalışmaya başladığı (Entry Point) bölümün entropi değeri.
/// * `warnings`: Tespit edilen potansiyel zararlı yazılım tekniklerine dair uyarı mesajları listesi.
#[derive(Debug, Serialize)]
struct HeuristicResult {
    is_packed: bool,
    entry_point_entropy: f64,
    warnings: Vec<String>,
}

/// EntroRS zararlı yazılım statik analiz aracının komut satırı argümanları.
///
/// `clap` kütüphanesi kullanılarak tanımlanmıştır. Kullanıcıdan dosya yolu ve yapılandırma
/// ayarları (örn. JSON çıktı) almayı sağlar.
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

/// Belirtilen dosya yolundaki zararlı yazılım örneğini okur ve güvenlik/limit doğrulamalarını yapar.
///
/// OOM (Out of Memory) saldırılarına karşı `MAX_FILE_SIZE` limiti (örn: 256 MB) uygulayarak,
/// kasıtlı olarak devasa boyutlara ulaştırılmış (pumped) malware dosyalarının sistemi çökertmesini engeller.
///
/// # Parametreler
/// * `path`: Okunacak ve analiz edilecek dosyanın tam argüman yolu (`PathBuf` referansı).
///
/// # Dönüş Değeri
/// * `Vec<u8>`: Başarıyla okunmuş dosyanın byte dizisi. Herhangi bir hatada (dosya bulunamaması, okuma izni olmaması, boyut sınırının aşılması) programı `process::exit(1)` ile sonlandırır.
fn read_and_validate_file(path: &PathBuf) -> Vec<u8> {
    // ── Dosyanın var olup olmadığını kontrol et ──
    if !path.exists() {
        eprintln!(
            "\n  [HATA] Belirtilen dosya bulunamadı: \"{}\"\n\
             \n  Lütfen dosya yolunu kontrol edip tekrar deneyin.\n\
             \n  Kullanım: EntroRS --file <DOSYA_YOLU>\n",
            path.display()
        );
        process::exit(1);
    }

    // ── Bir dizin değil, dosya olduğundan emin ol ──
    if path.is_dir() {
        eprintln!(
            "\n  [HATA] Belirtilen yol bir dizin, dosya değil: \"{}\"\n\
             \n  Lütfen geçerli bir dosya yolu belirtin.\n",
            path.display()
        );
        process::exit(1);
    }

    // ── Dosya meta verisini oku ──
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "\n  [HATA] Dosya meta verisi okunamadı: \"{}\"\n\
                 \n  Sebep: {}\n",
                path.display(),
                e
            );
            process::exit(1);
        }
    };

    let file_size = metadata.len();

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

    // FIXME: Çok büyük dosyalar (örn: >2GB) için memory-mapped file (mmap) sistemine geçilmeli
    // ── Dosyayı belleğe oku ──
    match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!(
                "  [HATA] Dosya belleğe okunamadı: \"{}\"\n\
                 \n  Sebep: {}\n",
                path.display(),
                e
            );
            process::exit(1);
        }
    }
}

/// Uygulamanın giriş noktası (Entry Point).
///
/// Bu fonksiyon sırasıyla aşağıdaki adımları koordine eder:
/// 1. Komut satırı argümanlarını (CLI) ayrıştırır.
/// 2. Girdi dosyasını doğrular ve OOM limitlerine uygun şekilde belleğe yükler (`read_and_validate_file`).
/// 3. Dosyanın metaverilerini (boyut, SHA-256 hash) oluşturur.
/// 4. Magic bytes ile dosya formatını `PE` veya `ELF` olarak belirler.
/// 5. Elde edilen byte dizisini ayrıştırmak üzere `analyze_executable` motoruna gönderir.
/// 6. Çıkan sonuçlara göre sezgisel kuralları çalıştırır (örn. entropi ve IAT kontrolü).
/// 7. Sonucu kullanıcı tercihine göre JSON (`--json`) veya insan okuyabilir tablo formatında konsola basar.
fn main() {
    let cli = Cli::parse();

    if !cli.json {
        print_banner();
    }

    let file_path = &cli.file;

    let file_data = read_and_validate_file(file_path);

    let file_size = file_data.len() as u64;
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

    // ── SHA-256 Hash Hesaplama ──
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let sha256_hash = format!("{:x}", hasher.finalize());

    // ── Magic Bytes Kontrolü & Format Belirleme ──
    let format_str = match detect_format(&file_data) {
        Some(f) => f.to_string(),
        None => {
            eprintln!(
                "  [HATA] Desteklenmeyen Format.\n\
                 \n  Dosya PE veya ELF formatında değil (MZ veya \\x7FELF imzası bulunamadı).\n"
            );
            process::exit(1);
        }
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

/// Belirtilen bir byte dizisinin (veri yığınının) Shannon Entropisini (Shannon Entropy) hesaplar.
///
/// Entropi, veri içerisindeki "rastgelelik" (randomness) miktarını ölçen matematiksel bir kavramdır.
/// Normal program kodları genelde 4.0 - 6.0 arası bir değere sahipken, sıkıştırılmış (packed) 
/// veya şifrelenmiş (encrypted) bölümler 7.0 ile 8.0 arası değerler üretir.
///
/// Formül: H(X) = - Σ P(xᵢ) × log₂(P(xᵢ))
///
/// # Parametreler
/// * `data`: Entropisi hesaplanacak ham byte dizisi.
///
/// # Dönüş Değeri
/// * `f64`: 0.0 (tamamen tahmin edilebilir) ile 8.0 (tamamen rastgele) arasındaki entropi değeri.
// TODO: Performans için entropy hesaplaması paralel thread'lere (Rayon) taşınacak
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

/// Hedef çalıştırılabilir dosyanın (Executable) formatını dinamik olarak algılayan ve uygun ayrıştırıcıya yönlendiren motor.
///
/// `goblin` kütüphanesini kullanarak analiz sürecini başlatır. Dosyanın PE (Windows) veya ELF (Linux)
/// formatında olduğunu tespit ederek arka plandaki `analyze_pe` veya `analyze_elf` fonksiyonlarına yönlendirir.
/// Desteklenmeyen veya bozuk formatlarda programı güvenle kapatır.
///
/// # Parametreler
/// * `data`: Belleğe yüklenmiş hedefin byte dizisi (raw verisi).
///
/// # Dönüş Değeri
/// Bir tuple döndürür: `(Bölümler Listesi, Entry Point Adresi, Dışa Bağımlılık/Import Sayısı)`
/// * `Vec<SectionInfo>`: Analiz edilen dosya içerisindeki bölümler ve her birinin boyutu/entropisi.
/// * `u64`: Sürecin işletim sisteminde başlayacağı sanal Entry Point adresi.
/// * `usize`: IAT (Import Address Table) veya dinamik semboller tablosundaki dış kütüphane fonksiyonlarının sayısı.
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

/// Portable Executable (PE - Windows) dosyalarını ayrıştıran alt analiz motoru.
///
/// PE dosyasının içindeki `.text`, `.data`, `.rsrc` gibi bölümleri (section) ayıklar,
/// entropilerini hesaplar ve IAT (Import Address Table) tablosunun boyutunu ölçer.
///
/// # Parametreler
/// * `pe`: `goblin::pe::PE` türünde ayrıştırılmış Portable Executable yapısı referansı.
/// * `file_data`: Entropi hesaplamaları için gereken dosyanın orijinal ham bayt dizisi.
///
/// # Dönüş Değeri
/// * `(Vec<SectionInfo>, u64, usize)`: Sırasıyla bölümler, entry point adresi ve import sayısı.
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

/// Executable and Linkable Format (ELF - Linux) dosyalarını ayrıştıran alt analiz motoru.
///
/// Linux sistemlerinde kullanılan dosyaların Section Header tablolarını ayrıştırarak
/// bellek yapılarını inceler, boyut ve entropi ölçümlerini gerçekleştirir. Dışa bağımlılık 
/// listesini analiz etmek için `dynsyms` (dinamik semboller) sayısına bakar.
///
/// # Parametreler
/// * `elf`: `goblin::elf::Elf` türünde ayrıştırılmış yapı.
/// * `file_data`: Orijinal dosyanın ham byte dizisi.
///
/// # Dönüş Değeri
/// * `(Vec<SectionInfo>, u64, usize)`: Sırasıyla bölümler, entry point adresi ve import (sembol) sayısı.
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

/// Büyük sayıları binlik ayrımlarla formatlayan yardımcı fonksiyon.
///
/// Konsol çıktılarını daha okunabilir kılmak için kullanılır (örneğin 1048576 sayısını 1.048.576 yapar).
///
/// # Parametreler
/// * `n`: Formatlanacak pozitif tam sayı (u32).
///
/// # Dönüş Değeri
/// * `String`: Formatlanmış okunabilir String değeri.
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

/// Verilen byte dizisinin başındaki sihirli byte'ları (Magic Bytes) kontrol ederek formatı belirler.
///
/// # Parametreler
/// * `data`: Dosyanın ham byte içeriği.
///
/// # Dönüş Değeri
/// * `Option<&'static str>`: Bilinirse "PE" veya "ELF", aksi halde `None`.
fn detect_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"MZ") {
        Some("PE")
    } else if data.starts_with(b"\x7FELF") {
        Some("ELF")
    } else {
        None
    }
}

/// Uygulama başladığında ekrana basılan ASCII Art ve isim/sürüm bilgilerini (Banner) yazdıran fonksiyon.
///
/// `--json` bayrağı ile sessiz veya otomatik (CI/CD) modda çalıştırılmayan standart terminal oturumlarında 
/// aracın görsel kimliğini ve temel amacını konsola yansıtır.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        // Boş veri entropisi 0 olmalı
        let data: &[u8] = &[];
        assert_eq!(calculate_entropy(data), 0.0);
    }

    #[test]
    fn test_entropy_homogeneous() {
        // Tamamen aynı bytelardan oluşan (tekrar eden) verinin entropisi 0 olmalı (rastgelelik yok)
        let data = vec![0xAA; 100];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_maximum() {
        // 0'dan 255'e kadar tüm byteları tam olarak birer kez içeren dizi
        // Mükemmel dağılım, maksimum rastgelelik demektir (Entropi = 8.0)
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        
        // Kayan noktalı (float) sayılarda eşitlik epsilon (hata payı) ile kontrol edilir
        assert!((entropy - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_format_number() {
        // Çıktı formatlayıcı edge-case testleri
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1.000");
        assert_eq!(format_number(1048576), "1.048.576");
    }

    #[test]
    fn test_entropy_accuracy() {
        let entropy = calculate_entropy(b"AAABBBCCC");
        assert!((entropy - 1.5849625).abs() < 0.00001);
    }

    #[test]
    fn test_magic_byte_detection() {
        assert_eq!(detect_format(b"MZ\x90\x00"), Some("PE"));
        assert_eq!(detect_format(b"\x7FELF\x02"), Some("ELF"));
    }

    #[test]
    fn test_suspicious_api_detection() {
        assert!(is_suspicious_api("VirtualAlloc"));
        assert!(is_suspicious_api("IsDebuggerPresent"));
        assert!(!is_suspicious_api("printf"));
    }
}
