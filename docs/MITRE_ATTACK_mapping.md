# MITRE ATT&CK Mapping | MITRE ATT&CK Eşleşmesi

| ID | Name | Description (English) | Açıklama (Türkçe) |
| :--- | :--- | :--- | :--- |
| **[T1027](https://attack.mitre.org/techniques/T1027/)** | **Obfuscated Files or Information** | EntroRS calculates Shannon Entropy to detect obfuscation and encrypted sections. | Shannon Entropisi ile şifrelenmiş veya gizlenmiş bölümleri tespit eder. |
| **[T1140](https://attack.mitre.org/techniques/T1140/)** | **Deobfuscate/Decode Files or Information** | The heuristic engine identifies the likely presence of custom or commercial packers. | Sezgisel analizle packer'lar (paketleyiciler) ve dekoderlar belirlenir. |
| **[T1129](https://attack.mitre.org/techniques/T1129/)** | **Shared Modules** | EntroRS parses IAT (Import Address Table) to identify external code dependencies. | IAT tablosu üzerinden dosyanın kullandığı dış modülleri ve API'leri listeler. |

---

## Detailed Technique Coverage | Teknik Detay Analizi

### T1027: Obfuscation Detection | Obfuscation Tespiti
Zararlı yazılımlar genellikle statik analizi zorlaştırmak için bölümlerini (sections) rastgele verilerle "karıştırır" (obfuscate). 
- **EntroRS Solution:** Yüksek entropi (> 7.2), verinin doğal dilden veya yapılandırılmış koddan uzak olduğunu kanıtlar.

### T1140: Packer Identification | Paketleyici Tanımlama
Zararlı yazılımlar, kendilerini UPX, Packer veya Themida gibi araçlarla paketleyerek korumaya çalışır.
- **EntroRS Solution:** Bir dosya bölümünün entropisi yüksekse ve IAT tablosu çok küçükse ( < 10 import), bu durum bir paketleyicinin varlığıdır.

### T1129: Shared Modules | Ortak Modüller / API Analizi
Yazılımlar çalışmak için sistem API'lerini (örn. `kernel32.dll`, `user32.dll`) kullanır.
- **EntroRS Solution:** Şüpheli API listesi (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`) üzerinden IAT analizi yaparak, zararlı yazılımın bellekte kod yürütme niyetini statik olarak deşifre eder.
