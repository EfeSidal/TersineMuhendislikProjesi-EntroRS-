# EntroRS Analiz Raporu — Vize Ön Gereksinimleri

Bu rapor, EntroRS projesinin ödev/vize gereksinimlerini nasıl karşıladığını ve projenin teknik temellerini açıklamaktadır.

## 1. Proje Özeti ve Gereksinim Uyumu

EntroRS, Windows (PE) ve Linux (ELF) çalıştırılabilir dosyalarını analiz etmek için geliştirilmiş, yüksek performanslı ve güvenli bir statik analiz aracıdır.

| Gereksinim | EntroRS Çözümü | Durum |
| :--- | :--- | :--- |
| **Statik Analiz** | Dosya çalıştırılmadan byte seviyesinde incelenir. | Tamamlandı |
| **Entropi Hesaplama** | Shannon Entropisi algoritması ile rastgelelik ölçümü. | Tamamlandı |
| **PE Header Analizi** | `goblin` kütüphanesi ile Header yapısı çözümlenir. | Tamamlandı |
| **IAT Analizi** | Dış kütüphane bağımlılıkları ve şüpheli API'ler taranır. | Tamamlandı |
| **Hız ve Güvenlik** | Rust dili ile bellek güvenliği ve OOM koruması sağlanır. | Tamamlandı |

## 2. Shannon Entropisi: Matematiksel Açıklama

Entropi, bir veri kümesindeki rastgelelik veya belirsizlik miktarını ölçer. Zararlı yazılım analizinde, bir dosya bölümünün (section) sıkıştırılmış (packed) veya şifrelenmiş (encrypted) olup olmadığını anlamak için kullanılır.

### Matematiksel Formül
Shannon Entropisi ($H$), aşağıdaki formül ile hesaplanır:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Burada:
- **$P(x_i)$**: Belirli bir byte değerinin ($0-255$) veri içindeki görülme olasılığıdır.
- **$\log_2$**: Bilginin "bit" cinsinden ölçülmesini sağlar.

### Yorumlama
- **0.0 - 4.0**: Düşük entropi. Genellikle yapılandırılmış veri veya boş alanlar.
- **4.0 - 6.5**: Normal entropi. Standart kod (x86/x64) ve metin verileri.
- **7.0 - 8.0**: Yüksek entropi. Verinin %90+ ihtimalle paketlendiğini veya şifrelendiğini gösterir.

## 3. Teknik Detaylar

### PE Header Analizi
Taşınabilir Çalıştırılabilir (Portable Executable) formatı, Windows'un temel dosya yapısıdır. EntroRS:
- **DOS Header**: `MZ` imzasını kontrol ederek başlar.
- **COFF Header**: Dosyanın mimarisini (32-bit/64-bit) ve bölüm sayısını belirler.
- **Optional Header**: Giriş noktası (Entry Point) ve bellek adresleme bilgilerini sunar.

### IAT (Import Address Table) Analizi
Zararlı yazılımlar genellikle işletim sistemi özelliklerini kullanmak için API'lere ihtiyaç duyar. EntroRS, IAT tablosunu tarayarak:
- Dosyanın hangi DLL'lere (örn: `kernel32.dll`, `ws2_32.dll`) bağımlı olduğunu listeler.
- `VirtualAlloc`, `CreateRemoteThread` gibi süreç enjeksiyonu için kullanılan şüpheli API'leri tespit eder.

### Strings (Dizgi) Analizi
(Planlanan/Geliştirilen): Dosya içindeki okunabilir karakter dizileri (IP adresleri, dosya yolları, hata mesajları) statik analizde dosyanın amacını belli eden en büyük ipuçlarından biridir.

---
**Hazırlayan:** Efe Sidal
**Proje:** EntroRS - Tersine Mühendislik Projesi
