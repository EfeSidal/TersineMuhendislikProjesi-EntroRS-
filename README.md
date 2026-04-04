
---

# 🦀 TERSİNE MÜHENDİSLİK - Static Malware Analysis & PE Analyzer

Tersine, Rust diliyle geliştirilmiş, Windows PE (Portable Executable) dosyaları üzerinde statik analiz gerçekleştiren yüksek performanslı bir güvenlik aracıdır.

## 🚀 Özellikler

*   **PE Header Analizi:** Dosya mimarisi (x86/x64) ve temel meta verilerin tespiti.
*   **Section Parsing:** Bölüm adları, Raw Size vs Virtual Size karşılaştırması (Packing tespiti için).
*   **Shannon Entropisi:** Veri yoğunluğu analizi ile şifrelenmiş veya paketlenmiş alanların tespiti.
*   **IAT (Import Address Table) Analizi:** Dışarıdan çağrılan DLL ve fonksiyonların listelenmesi.
*   **Şüpheli API Tespiti:** Anti-debugging (`IsDebuggerPresent`) ve dinamik yükleme (`LoadLibrary`) gibi kritik fonksiyonların otomatik bayraklanması.
*   **Strings Analysis:** Dosya içindeki URL, IP adresi ve dosya yollarının Regex tabanlı tespiti.

## 🛠 Kurulum ve Kullanım

### Gereksinimler
*   Rust Toolchain (Cargo)

### Derleme
```bash
cargo build --release
```

### Çalıştırma
```bash
./target/release/tersine.exe --file <analiz_edilecek_dosya_yolu>
```

## 📊 Teknik Detaylar
Bu araç, siber güvenlikte "Static Analysis" disiplini üzerine inşa edilmiştir. Özellikle **Entropy analizi** sayesinde aşağıdaki formülü kullanarak verinin rastgeleliğini ölçer ve zararlı yazılımların gizlenme tekniklerini deşifre eder:

$$H(X) = - \sum P(x_i) \log_2 P(x_i)$$

---
