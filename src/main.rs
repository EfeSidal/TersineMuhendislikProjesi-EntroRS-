use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  tersine — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
//  Aşama 1: Proje İskeleti & CLI Kurulumu
//  Aşama 2: PE (Portable Executable) Analizi
//  Aşama 3: Matematiksel Motor — Shannon Entropisi
// ─────────────────────────────────────────────────────────────

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
///
/// - 0.0       : Tüm byte'lar aynı (sıfır bilgi içeriği)
/// - ~3.5–5.0  : Normal derlenmiş kod / yapılandırılmış veri
/// - ~6.0–7.0  : Sıkıştırılmış veri veya yoğun kod
/// - ~7.0–8.0  : Yüksek entropi — paketlenmiş, şifrelenmiş veya obfuscate edilmiş
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
/// bölüm (section) bilgilerini entropi ile birlikte yazdırır.
fn analyze_pe(data: &[u8]) {
    println!("  ── PE (Portable Executable) Analizi ──────────────────────");
    println!();

    // MZ imzası kontrolü (PE dosyasının ilk 2 byte'ı "MZ" olmalı)
    if data.len() < 2 || data[0] != b'M' || data[1] != b'Z' {
        eprintln!("  [UYARI] Bu geçerli bir Windows PE dosyası değil.");
        eprintln!("          Dosya \"MZ\" imzası ile başlamıyor.");
        eprintln!();
        eprintln!("  İpucu: Bu araç şu anda yalnızca Windows PE (.exe, .dll, .sys)");
        eprintln!("         dosyalarını desteklemektedir.");
        process::exit(1);
    }

    // pelite ile PE'yi parse et
    // Önce 64-bit (PE32+) olarak dene, başarısız olursa 32-bit (PE32) dene
    if let Ok(pe64) = pelite::pe64::PeFile::from_bytes(data) {
        println!("  ✔ Geçerli PE dosyası tespit edildi: PE32+ (64-bit)");
        println!();
        print_sections_64(&pe64, data);
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(data) {
        println!("  ✔ Geçerli PE dosyası tespit edildi: PE32 (32-bit)");
        println!();
        print_sections_32(&pe32, data);
    } else {
        eprintln!("  [UYARI] Bu geçerli bir Windows PE dosyası değil.");
        eprintln!("          Dosya MZ imzasına sahip ancak PE yapısı bozuk veya tanınmıyor.");
        eprintln!();
        eprintln!("  İpucu: Dosya korumalı, bozulmuş veya desteklenmeyen bir formatta olabilir.");
        process::exit(1);
    }
}

/// 64-bit PE dosyasının bölümlerini entropi ile birlikte yazdırır.
fn print_sections_64(pe: &pelite::pe64::PeFile, file_data: &[u8]) {
    use pelite::pe64::Pe;

    let sections = pe.section_headers();
    let section_count = sections.image().len();

    let rows: Vec<SectionRow> = sections.iter().map(|s| {
        let name = s.name().unwrap_or_else(|bytes| {
            std::str::from_utf8(bytes).unwrap_or("<bilinmeyen>")
        });

        // Bölümün diskteki ham verisini al (file_range)
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

/// Bölüm tablosu çıktısını oluşturur (hem 32 hem 64-bit için ortak).
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
