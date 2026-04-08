<p align="center">
  <img src="istinye-logo.png" alt="İstinye Üniversitesi" width="220"/>
</p>





# 🦀 EntroRS - Static Malware Analysis & PE Analyzer

![Rust](https://img.shields.io/badge/Language-Rust-black?style=flat-square&logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)
![CI/CD](https://github.com/EfeSidal/TersineMuhendislikProjesi-EntroRS-/actions/workflows/ci.yml/badge.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)

[🇹🇷 Türkçe](#turkce) | [🇬🇧 English](#english)
### 👤 Proje Bilgileri

| | |
|---|---|
| **Öğrenci** | Efe Sidal |
| **Danışman Hoca** | Keyvan Arasteh |
| **Üniversite** | İstinye Üniversitesi |
| **Bölüm** | Bilişim Güvenliği Teknolojisi |
| **Ders** | Tersine Mühendislik |
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

### 🛡️ MITRE ATT&CK Matrisi

| ID | İsim | Açıklama |
| :--- | :--- | :--- |
| **T1027** | Obfuscated Files or Information | Entropi tabanlı paketlenmiş/şifrelenmiş bölüm tespiti. |
| **T1140** | Deobfuscate/Decode Files or Information | Yüksek entropili giriş noktaları üzerinden gizleme tespiti. |
| **T1129** | Shared Modules | IAT analizi ile dış kütüphane bağımlılıklarının tespiti. |
| **T1082** | System Information Discovery | Anti-debug/Anti-VM amaçlı kullanılan API'lerin tespiti. |

### 🦀 Neden Rust?
Rust, çöp toplayıcı (garbage collector) olmadan bellek güvenliği garantileri, maksimum performans için sıfır maliyetli soyutlamalar (zero-cost abstractions) ve modern bir sistem programlama dili olarak C/C++ hızını sunar. Bu özellikler, zararlı olabilecek ikili (binary) verileri güvenli ve hızlı bir şekilde işlemek için EntroRS'u ideal bir araç yapar.

### 📊 Teknik Detaylar: Entropy Motoru
Bu araç, siber güvenlikte "Static Analysis" disiplini üzerine inşa edilmiştir. Zararlı yazılımların kod gizleme (obfuscation) tekniklerini tespit etmek için dosyanın her bir PE bölümüne **Shannon Entropisi** algoritmasını uygular:

$$H(X) = - \sum P(x_i) \log_2 P(x_i)$$

Bu matematiksel model, verinin rastgelelik seviyesini 0.0 ile 8.0 arasında puanlar. 7.0 üzerindeki değerler, analiz edilen bölümün yüksek ihtimalle sıkıştırılmış veya kriptografik bir işleme maruz kaldığını gösterir.

## 🎬 Demo

Aracın çalışma anını, PE analiz sürecini ve risk skorlamasını aşağıdaki videodan izleyebilirsiniz:

[![Demo Video](https://img.youtube.com/vi/yfGaLHRuOGc/maxresdefault.jpg)](https://youtu.be/yfGaLHRuOGc)

### 🛠 Kurulum ve Kullanım

**Derleme (Release Mode):**
```bash
cargo build --release
```

**Çalıştırma:**

```bash
./target/release/EntroRS.exe --file <analiz_edilecek_dosya_yolu>
```

-----

<a id="english"></a>

<p align="center">
  <img src="istinye-logo.png" alt="İstinye Üniversitesi" width="220"/>
</p>


### 👤 Project Info

| | |
|---|---|
| **Student** | Efe Sidal |
| **Instructor** | Keyvan Arasteh |
| **University** | Istinye University |
| **Department** | Information Security Technology |
| **Course** | Reverse Engineering |

## 🇬🇧 English

EntroRS is a high-performance static malware analysis tool developed in Rust, capable of signature-based and heuristic static analysis on Windows PE (Portable Executable) files.

### 🚀 Features

  * **PE Header Analysis:** File architecture (x86/x64) and basic metadata detection.
  * **Section Parsing:** Raw Size vs Virtual Size correlation to identify potential packing.
  * **Shannon Entropy:** Mathematical data density analysis to expose encrypted or packed sections.
  * **IAT (Import Address Table) Analysis:** Mapping of externally imported system DLLs and functions.
  * **Suspicious API Detection:** Automated flagging of critical functions such such as anti-debugging (`IsDebuggerPresent`), memory manipulation (`VirtualAlloc`), and dynamic loading (`LoadLibraryA`).
  * **Strings Analysis:** Regex-based extraction of hardcoded URLs, IP addresses, and critical file paths.

### 🛡️ MITRE ATT&CK Matrix

| ID | Name | Description |
| :--- | :--- | :--- |
| **T1027** | Obfuscated Files or Information | Entropy-based detection of packed/encrypted sections. |
| **T1140** | Deobfuscate/Decode Files or Information | Identifying obfuscation logic through high-entropy entry points. |
| **T1129** | Shared Modules | IAT analysis to identify external library dependencies. |
| **T1082** | System Information Discovery | Detecting APIs used for anti-debug or anti-VM finger-printing. |

### 🦀 Why Rust?
Rust provides memory safety guarantees without a garbage collector, zero-cost abstractions for maximum performance, and the speed of C/C++ while being a modern and safe systems programming language. This makes it ideal for handling potentially malicious binary data safely and efficiently.

### 📊 Technical Details: Entropy Engine

This tool is built upon the core principles of the "Static Analysis" discipline in cybersecurity. To detect malware code obfuscation techniques, it applies the **Shannon Entropy** algorithm to each PE section:

$$H(X) = - \sum P(x_i) \log_2 P(x_i)$$

This mathematical model scores the randomness of the data on a scale of 0.0 to 8.0. Values above 7.0 strongly indicate that the analyzed section has been subjected to compression or cryptographic routines.

## 🎬 Demo

Watch the tool in action — PE analysis process and risk scoring:

[![Demo Video](https://img.youtube.com/vi/yfGaLHRuOGc/maxresdefault.jpg)](https://youtu.be/yfGaLHRuOGc)

### 🛠 Installation and Usage

**Build (Release Mode):**

```bash
cargo build --release
```

**Usage:**

```bash
./target/release/EntroRS.exe --file <target_file_path>
```
