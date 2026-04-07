<p align="center">
  <img src="https://github.com/user-attachments/assets/5f914303-57e1-4d37-99bd-c368da9900bc" alt="İstinye Üniversitesi" width="300"/>
</p>

### 👤 Proje Bilgileri

| | |
|---|---|
| **Öğrenci** | Gizem Kızılay |
| **Danışman Eğitmen** | Keyvan Arasteh Abbasabad |
| **Üniversite** | İstinye Üniversitesi |
| **Ders** | Tersine Mühendislik (Reverse Engineering) |

# 🛡️ Anti-Debug Trap - Dynamic Analysis Evasion & Memory Protection

![C++](https://img.shields.io/badge/Language-C++17-00599C?style=flat-square&logo=c%2B%2B)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)
[![CI/CD](https://github.com/gizemkizilay/Anti-Debug-Kapani/actions/workflows/build.yml/badge.svg)](https://github.com/gizemkizilay/Anti-Debug-Kapani/actions)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)

[🇹🇷 Türkçe](#turkce) | [🇬🇧 English](#english)

---

<a id="turkce"></a>
## 🇹🇷 Türkçe

Anti-Debug Trap, C++17 ile Windows x64 mimarisi için geliştirilmiş; uygulamanın kendi çalışma zamanı (runtime) ortamını analiz ederek bir hata ayıklayıcı (debugger) tarafından izlenip izlenmediğini otonom olarak tespit eden ileri seviye bir "Evasion" (Sakınma) mekanizmasıdır.

### 🚀 Özellikler
* **PEB (Process Environment Block) Analizi:** Windows çekirdeğinin süreç için tuttuğu `BeingDebugged` bayrağının anlık olarak sorgulanması.
* **Software Breakpoint Avı:** Bellek üzerinde dinamik tarama yapılarak x64dbg/WinDbg gibi araçların enjekte ettiği `0xCC` (INT 3) opcode'larının tespiti.
* **Dinamik Disassembly:** `Capstone Engine` kütüphanesi kullanılarak, çalışma anında kritik fonksiyonların de-compile edilmesi ve bütünlük doğrulaması.
* **Silent Exit (Sessiz İnfaz):** Analiz tespit edildiğinde `exit(0)` çağrısı ile analiste hiçbir uyarı, hata mesajı veya "exception" vermeden sürecin anında sonlandırılması.

### 🛡️ MITRE ATT&CK Matrisi

| ID | İsim | Açıklama |
| :--- | :--- | :--- |
| **T1622** | Debugger Evasion | PEB blokları üzerinden sürecin bir debugger ile kancalanıp (hook) kancalanmadığının tespiti. |
| **T1497** | Virtualization/Sandbox Evasion | Çalışma ortamının bir analist tarafından manipüle edildiğinin anlaşılması ve silent-exit uygulanması. |
| **T1027** | Obfuscated Files or Information | Yazılım kesmelerinin (Software Breakpoints - INT3) tespit edilerek dinamik analizin bloke edilmesi. |
| **T1012** | Query Registry / System | Windows iç yapılarına (API seviyesinin altına) inerek sistem durumunun doğrulanması. |

### ⚙️ Neden C++ ve Capstone?
Modern siber güvenlikte sadece geleneksel API çağrılarına (örneğin `IsDebuggerPresent`) güvenmek yeterli değildir; bu çağrılar kolayca yamalanabilir (patching). C++ dili, işletim sistemi çekirdeğine (Windows Kernel) ve bellek adreslerine en alt seviyeden doğrudan erişim sağlar. `Capstone Engine` entegrasyonu ise, bellekteki makine kodunun çalışma anında okunmasını ve dışarıdan yapılan "inline patching" müdahalelerinin tespit edilmesini mümkün kılar.

### 📊 Teknik Detaylar: Opcode Doğrulama ve INT3 Tarama
Bu araç, tersine mühendislerin kod akışını durdurmak için kullandığı yazılımsal kesmeleri matematiksel ve yapısal olarak analiz eder. Bellek üzerindeki fonksiyonlar byte dizileri halinde okunur:

* Eğer okunan bellek adresinde `0xCC` (INT 3 kesmesi) tespit edilirse.
* Sistem anında **"Evasion"** moduna geçer ve "Exception Handling" süreçlerine yakalanmamak için standart C kütüphanesi üzerinden süreci yok eder.

### 🛠 Kurulum ve Derleme (Release Mode)

Projeyi bağımlılıklarıyla (Capstone) beraber derlemek için:

```bash
git clone [https://github.com/gizemkizilay/Anti-Debug-Kapani.git](https://github.com/gizemkizilay/Anti-Debug-Kapani.git)
cd Anti-Debug-Kapani
mkdir build && cd build
cmake ..
cmake --build . --config Release
