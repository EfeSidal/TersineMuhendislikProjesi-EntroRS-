# 🦀 EntroRS - Static Malware Analysis & PE Analyzer

[🇹🇷 Türkçe](#turkce) | [🇬🇧 English](#english)

---

<a id="turkce"></a>
## 🇹🇷 Türkçe

EntroRS, Rust diliyle geliştirilmiş, Windows PE (Portable Executable) dosyaları üzerinde çalışan, imza tabanlı ve sezgisel (heuristic) statik analiz gerçekleştiren yüksek performanslı bir güvenlik aracıdır.

### 🚀 Özellikler
*   **PE Header Analizi:** Dosya mimarisi (x86/x64) ve temel meta verilerin tespiti.
*   **Section Parsing:** Bölüm adları, Raw Size vs Virtual Size karşılaştırması (Potansiyel packing tespiti).
*   **Shannon Entropisi:** Veri yoğunluğu analizi ile şifrelenmiş (encrypted) veya paketlenmiş (packed) alanların matematiksel olarak deşifre edilmesi.
*   **IAT (Import Address Table) Analizi:** Dışarıdan çağrılan sistem DLL'lerinin ve alt fonksiyonlarının haritalandırılması.
*   **Şüpheli API Tespiti:** Anti-debugging (`IsDebuggerPresent`), bellek manipülasyonu (`VirtualAlloc`) ve dinamik yükleme (`LoadLibraryA`) gibi kritik fonksiyonların otomatik olarak bayraklanması.
*   **Strings Analysis:** Dosya içindeki hardcoded URL, IP adresi ve kritik dosya yollarının Regex motoruyla ayıklanması.

### 📊 Teknik Detaylar: Entropy Motoru
Bu araç, siber güvenlikte "Static Analysis" disiplini üzerine inşa edilmiştir. Zararlı yazılımların kod gizleme (obfuscation) tekniklerini tespit etmek için dosyanın her bir PE bölümüne **Shannon Entropisi** algoritmasını uygular:

$$H(X) = - \sum P(x_i) \log_2 P(x_i)$$

Bu matematiksel model, verinin rastgelelik seviyesini 0.0 ile 8.0 arasında puanlar. 7.0 üzerindeki değerler, analiz edilen bölümün yüksek ihtimalle sıkıştırılmış veya kriptografik bir işleme maruz kaldığını gösterir.

### 🛠 Kurulum ve Kullanım

**Derleme (Release Mode):**
```bash
cargo build --release
````

**Çalıştırma:**

```bash
./target/release/EntroRS.exe --file <analiz_edilecek_dosya_yolu>
```

-----

\<a id="english"\>\</a\>

## 🇬🇧 English

EntroRS is a high-performance static malware analysis tool developed in Rust, capable of signature-based and heuristic static analysis on Windows PE (Portable Executable) files.

### 🚀 Features

  * **PE Header Analysis:** File architecture (x86/x64) and basic metadata detection.
  * **Section Parsing:** Raw Size vs Virtual Size correlation to identify potential packing.
  * **Shannon Entropy:** Mathematical data density analysis to expose encrypted or packed sections.
  * **IAT (Import Address Table) Analysis:** Mapping of externally imported system DLLs and functions.
  * **Suspicious API Detection:** Automated flagging of critical functions such as anti-debugging (`IsDebuggerPresent`), memory manipulation (`VirtualAlloc`), and dynamic loading (`LoadLibraryA`).
  * **Strings Analysis:** Regex-based extraction of hardcoded URLs, IP addresses, and critical file paths.

### 📊 Technical Details: Entropy Engine

This tool is built upon the core principles of the "Static Analysis" discipline in cybersecurity. To detect malware code obfuscation techniques, it applies the **Shannon Entropy** algorithm to each PE section:

$$H(X) = - \sum P(x_i) \log_2 P(x_i)$$

This mathematical model scores the randomness of the data on a scale of 0.0 to 8.0. Values above 7.0 strongly indicate that the analyzed section has been subjected to compression or cryptographic routines.

### 🛠 Installation and Usage

**Build (Release Mode):**

```bash
cargo build --release
```

**Usage:**

```bash
./target/release/EntroRS.exe --file <target_file_path>
```
