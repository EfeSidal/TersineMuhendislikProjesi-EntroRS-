# Troubleshooting | Sorun Giderme

## Build Errors | Derleme Hataları (English)
If `cargo build` fails, common reasons include:
- **Rust is not installed**: Visit [rust-lang.org](https://www.rust-lang.org/learn/get-started) to install the Rust toolchain.
- **Cargo.toml dependencies**: Ensure you have an internet connection to download `goblin`, `clap`, and other crates.

## Derleme Hataları (Türkçe)
Eğer `cargo build` başarısız olursa, yaygın nedenler şunlardır:
- **Rust yüklü değil**: Rust toolchain'ini kurmak için [rust-lang.org](https://www.rust-lang.org/tr/learn/get-started) adresini ziyaret edin.
- **Bağımlılıklar**: `goblin`, `clap` ve diğer paketleri indirmek için internet bağlantınız olduğundan emin olun.

---

## File Not Found on Windows | Windows'ta Dosya Bulunamadı (English)
When using the `--file` flag, if you get a "file not found" error:
1. Ensure the path is correct.
2. Use **double backslashes** in the path: `cargo run -- --file C:\\Users\\Name\\Desktop\\file.exe`
3. Or use a relative path: `cargo run -- --file ./test.exe`

## Windows'ta Dosya Bulunamadı (Türkçe)
`--file` bayrağını kullanırken "dosya bulunamadı" hatası alırsanız:
1. Yolun doğru olduğundan emin olun.
2. Yollarda **çift ters eğik çizgi** kullanın: `cargo run -- --file C:\\Kullanici\\Masaustu\\dosya.exe`
3. Veya göreceli bir yol belirtin: `cargo run -- --file ./test.exe`

---

## High Entropy False Positives | Yüksek Entropi (False Positive) (English)
An entropy score of **> 7.2** usually indicates packing, but some legitimate files can also have high entropy:
- **Resource files**: Large images, encrypted game assets, or heavily compressed media.
- **Setup files**: Installers (NSIS, InnoSetup) often look like packed malware.
- **EntroRS Solution**: Always check the **Import Count**. If entropy is high and imports are **< 10**, it's much more likely to be a custom packer.

## Yüksek Entropi (False Positive) (Türkçe)
**7.2**'nin üzerindeki entropi puanı genellikle paketlenmiş (packed) bir dosyayı gösterir, ancak bazı meşru dosyalar da yüksek entropiye sahip olabilir:
- **Kaynak dosyaları**: Büyük resimler, şifrelenmiş oyun varlıkları veya ağır şekilde sıkıştırılmış medya dosyaları.
- **Kurulum dosyaları**: Yükleyiciler (NSIS, InnoSetup) genellikle paketlenmiş zararlı yazılım gibi görünür.
- **EntroRS Çözümü**: Daima **Import Sayısını** kontrol edin. Entropi yüksekse ve import sayısı **10'dan azsa**, bu durum bir paketleyicinin varlığına dair çok daha güçlü bir işarettir.

---

## Rust Toolchain Issues | Rust Toolchain Sorunları (English)
If you encounter toolchain conflicts:
- Run `rustup update` to ensure you are on the latest stable version.
- Use `rustc --version` to check your current installation.

## Rust Toolchain Sorunları (Türkçe)
Toolchain çakışmalarıyla karşılaşırsanız:
- En son kararlı sürümde olduğunuzdan emin olmak için `rustup update` komutunu çalıştırın.
- Mevcut kurulumunuzu kontrol etmek için `rustc --version` komutunu kullanın.
