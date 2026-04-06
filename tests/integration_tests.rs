use std::process::Command;

#[test]
fn test_binary_help_output() {
    // EntroRS ikili dosyasının (binary) yardım mesajını basıp basmadığını kontrol eder.
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("cargo run --help komutu başarısız oldu");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EntroRS"));
    assert!(stdout.contains("Usage:"));
}

#[test]
fn test_invalid_file_error() {
    // Mevcut olmayan bir dosya verildiğinde hata döndürüp döndürmediğini kontrol eder.
    let output = Command::new("cargo")
        .args(&["run", "--", "--file", "non_existent_file.txt"])
        .output()
        .expect("cargo run başarısız oldu");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[HATA]"));
}
