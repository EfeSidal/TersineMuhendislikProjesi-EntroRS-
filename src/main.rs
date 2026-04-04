use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process;

// ─────────────────────────────────────────────────────────────
//  tersine — Zararlı Yazılım Statik Analiz Aracı (Entropy Checker)
//  Aşama 1: Proje İskeleti & CLI Kurulumu
//  Aşama 2: PE (Portable Executable) Analizi
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
//  PE ANALİZ FONKSİYONLARI
// ═══════════════════════════════════════════════════════════════

/// Verilen byte verisini PE formatı olarak parse eder ve
/// bölüm (section) bilgilerini tablo formatında yazdırır.
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
        print_sections_64(&pe64);
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(data) {
        println!("  ✔ Geçerli PE dosyası tespit edildi: PE32 (32-bit)");
        println!();
        print_sections_32(&pe32);
    } else {
        eprintln!("  [UYARI] Bu geçerli bir Windows PE dosyası değil.");
        eprintln!("          Dosya MZ imzasına sahip ancak PE yapısı bozuk veya tanınmıyor.");
        eprintln!();
        eprintln!("  İpucu: Dosya korumalı, bozulmuş veya desteklenmeyen bir formatta olabilir.");
        process::exit(1);
    }
}

/// 64-bit PE dosyasının bölümlerini tablo formatında yazdırır.
fn print_sections_64(pe: &pelite::pe64::PeFile) {
    use pelite::pe64::Pe;

    let sections = pe.section_headers();

    // .image() ile &[IMAGE_SECTION_HEADER] slice'ına erişip len() alıyoruz
    let section_count = sections.image().len();

    // .iter() ile SectionHeader iterator'ü alıyoruz
    // SectionHeader, Deref<Target = IMAGE_SECTION_HEADER> implemente eder
    // bu sayede .Name, .SizeOfRawData, .VirtualSize alanlarına erişebiliriz
    print_section_table(section_count, sections.iter().map(|s| {
        let name = s.name().unwrap_or_else(|bytes| {
            std::str::from_utf8(bytes).unwrap_or("<bilinmeyen>")
        });
        (name.to_string(), s.SizeOfRawData, s.VirtualSize)
    }));
}

/// 32-bit PE dosyasının bölümlerini tablo formatında yazdırır.
fn print_sections_32(pe: &pelite::pe32::PeFile) {
    use pelite::pe32::Pe;

    let sections = pe.section_headers();
    let section_count = sections.image().len();

    print_section_table(section_count, sections.iter().map(|s| {
        let name = s.name().unwrap_or_else(|bytes| {
            std::str::from_utf8(bytes).unwrap_or("<bilinmeyen>")
        });
        (name.to_string(), s.SizeOfRawData, s.VirtualSize)
    }));
}

/// Bölüm tablosu çıktısını oluşturur (hem 32 hem 64-bit için ortak).
fn print_section_table(
    section_count: usize,
    sections: impl Iterator<Item = (String, u32, u32)>,
) {
    println!(
        "  ── Bölüm Tablosu ({} bölüm bulundu) ──────────────────",
        section_count
    );
    println!();
    println!(
        "  {:<4} {:<14} {:>18} {:>22}",
        "#", "Bölüm Adı", "Raw Size (Disk)", "Virtual Size (Bellek)"
    );
    println!("  {}", "─".repeat(62));

    for (i, (name, raw_size, virtual_size)) in sections.enumerate() {
        println!(
            "  {:<4} {:<14} {:>12} bytes {:>14} bytes",
            i + 1,
            name,
            format_number(raw_size),
            format_number(virtual_size)
        );
    }

    println!("  {}", "─".repeat(62));
    println!();
    println!("  [BİLGİ] PE bölüm analizi tamamlandı.");
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
