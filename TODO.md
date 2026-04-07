# Todo | Yapılacaklar

## Milestones | Kilometre Taşları (English)

### v2.1.0 — Completed | Tamamlandı ✅
- **PE & ELF Parsing**: Comprehensive support for Windows (PE) and Linux (ELF) binaries using `goblin`.
- **Shannon Entropy**: Mathematical engine for calculating data randomness and flagging high entropy.
- **IAT Analysis**: Identification of external dependencies and suspicious API mappings.
- **Automated CI/CD**: Integration of GitHub Actions for testing, linting, and formatting.
- **JSON Output**: Structured reporting for automated analysis pipelines.

### v2.2.0 — Planned | Planlanan 🚀
- **YARA Rule Integration**: Engine support for scanning binaries using custom YARA rules.
- **Signature Detection**: Identifying known packers like UPX or VMProtect by signature.
- **Enhanced Reporting (HTML)**: Interactive HTML format exports for human-readable intelligence reports.

### v2.3.0 — Planned | Planlanan 🚀
- **Mach-O (macOS) Support**: Expanding the parsing engine to support Apple ecosystem binaries.
- **EDR/SIEM Integration Hooks**: Webhook capabilities to directly feed analysis results into enterprise security solutions.
- **Advanced Deobfuscation Helpers**: Basic static unpacking heuristics for common crypters.

### v3.0.0 — Long-term | Uzun Vade 📅
- **Universal Static Engine**: Support for multiple file formats with a unified heuristic engine.
- **WebAssembly (WASM) Port**: Compiling the core Rust engine to WASM for browser-based, client-side static analysis.
- **ML-Based Anomaly Detection**: Replacing basic threshold heuristics with lightweight machine learning models to detect unknown packers.

---

## Kilometre Taşları (Türkçe)

### v2.1.0 — Completed | Tamamlandı ✅
- **PE ve ELF Analizi**: Windows (PE) ve Linux (ELF) çalıştırılabilir dosyaları için kapsamlı ayrıştırma.
- **Shannon Entropisi**: Veri rastgeleliğini hesaplayan ve yüksek entropiyi tespit eden matematiksel motor.
- **IAT Analizi**: Dış bağımlılıkların ve şüpheli API çağrılarının tespiti.
- **Otomatik CI/CD**: Test, lint ve formatlama için GitHub Actions entegrasyonu.
- **JSON Çıktısı**: Otomatik analiz sistemleri için yapılandırılmış veri dışa aktarımı.

### v2.2.0 — Planlanan 🚀
- **YARA Kuralı Entegrasyonu**: Özel YARA kuralları ile binary tarama desteği.
- **İmza Tespiti**: UPX, VMProtect gibi bilinen paketleyicilerin imza ile tanımlanması.
- **Gelişmiş Raporlama (HTML)**: İnsan tarafından okunabilir, etkileşimli HTML rapor çıktısı desteği.

### v2.3.0 — Planlanan 🚀
- **Mach-O (macOS) Desteği**: Apple ekosistemi dosyalarını desteklemek için ayrıştırma motorunun genişletilmesi.
- **EDR/SIEM Entegrasyon Kancaları**: Analiz sonuçlarını doğrudan kurumsal güvenlik çözümlerine iletmek için Webhook desteği.
- **Gelişmiş Deobfuscation Yardımcıları**: Yaygın şifreleyiciler (crypter) için temel statik paket açma (unpacking) sezgiselleri.

### v3.0.0 — Uzun Vade 📅
- **Evrensel Statik Motor**: Tek bir motor ile birden fazla dosya formatına destek.
- **WebAssembly (WASM) Portu**: Tarayıcı tabanlı, istemci tarafı statik analiz için çekirdek Rust motorunun WASM'a derlenmesi.
- **ML Tabanlı Anomali Tespiti**: Bilinmeyen paketleyicileri tespit etmek için temel eşik değerlerinin yerini hafif makine öğrenimi modellerinin alması.