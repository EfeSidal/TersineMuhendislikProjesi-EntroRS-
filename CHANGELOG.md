# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-04-07

### Added
- **PE & ELF Parsing Engine**: Initial implementation for extracting file metadata and section headers using the `goblin` crate.
- **Shannon Entropy Algorithm**: Integrated robust mathematical engine to calculate entropy for individual executable sections to identify potential obfuscation or packing.
- **IAT Analysis**: Added mechanism to parse the Import Address Table and specifically detect suspicious, security-relevant Windows APIs (e.g., process injection, anti-debugging, cryptography).
- **Heuristics & Packer Detection**: Implemented logic to flag files with high entropy (> 7.2) and low import count (< 10) typical of packers and cryptors.
- **CI/CD Pipeline**: Configured GitHub Actions workflow for automated testing, linting (`clippy`), formatting (`rustfmt`), and continuous integration.
- **JSON Output Mode**: Introduced structured JSON reporting (`-j` / `--json`) to facilitate integration with automated malware analysis pipelines and SIEM platforms.
