# Usage Examples | Kullanım Örnekleri

## Simple Scan | Basit Dosya Taraması (English)
To perform a standard static scan on a Windows PE file:

```bash
cargo run -- --file malware_sample.exe
```

### Explaining Terminal Output:
- **`✔ Analiz edilecek dosya yüklendi`**: Successful file read.
- **`✔ Sezgisel Analiz Özeti`**: High-level result of the heuristic engine.
- **`EP Entropisi`**: The entropy value at the file's Entry Point.
- **`Packed/Kripto: EVET [!]`**: High entropy detected in critical sections.

---

## JSON Output | JSON Çıktı Modu (Türkçe)
Otomasyon sistemleri (CI/CD) veya veri analizi için JSON çıktısını kullanabilirsiniz:

```bash
cargo run -- --file test.dll --json
```

### JSON Örneği Açıklaması:
```json
{
  "file_info": {
    "dosya_adi": "test.dll",
    "sha256_hash": "a1b2c3d4...",
    "format": "PE"
  },
  "sections": [
    {
      "isim": ".text",
      "entropy": 6.4523
    },
    {
      "isim": ".rsrc",
      "entropy": 7.8912
    }
  ],
  "heuristics": {
    "is_packed": true,
    "warnings": ["Kritik: Entry Point yüksek entropili bir bölümde"]
  }
}
```
*Bu çıktı, `jq` gibi araçlar ile işlenebilir.*

---

## Troubleshooting | Problem Çözme
- **`File not found`**: Ensure the relative/absolute file path is correct.
- **`File size too large`**: EntroRS currently limits file analysis to **256MB** to prevent OOM (Out of Memory) crashes on large 'pumped' malware files.
- **`Unsupported format`**: Ensure the target is a valid Windows PE (Portable Executable) or Linux ELF file.
