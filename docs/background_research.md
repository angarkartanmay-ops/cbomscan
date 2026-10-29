# Background research: quantum threat to ESP32 firmware, PQC, CBOM
Compiled 29 Oct 2026 at the start of the project. It is the literature base the design decisions refer to; facts may have moved since, so re-check the [S]-tagged sources before citing them in a report.

Confidence tags: [S] sourced from a retrieved page, [B] background knowledge (textbook-level, not re-verified today), [I] my inference, flagged for the team to test.

---

## 1. Quantum foundations (what matters for the project)

- [B] A qubit holds a superposition; n qubits span 2^n amplitudes. Algorithms win by interference (amplifying right answers, cancelling wrong ones), not by "trying everything at once".
- [B] Shor (1994): period finding via the Quantum Fourier Transform. Solves integer factoring (RSA) and discrete log (DH, ECDH, ECDSA, ECC) in polynomial time. This is the algorithm that breaks identity, signatures and key exchange.
- [B] Grover (1996): quadratic speed-up for unstructured search. Halves effective symmetric key strength (AES-128 -> ~64-bit work, AES-256 -> ~128-bit). Does not break AES or SHA-2/3. Grover parallelises badly, so practical impact is smaller than the headline.
- [B] "Noisy" physical qubits need error correction. Logical qubits are built from many physical ones (surface code, now qLDPC). Resource estimates are always "physical qubits x runtime under stated error-rate assumptions".
- [B] CRQC = cryptographically relevant quantum computer. Q-Day = the day one exists. Nobody knows the date.

## 2. How close is the threat (resource estimates)

- [S] 2012 Fowler et al: RSA-2048 ~1 billion physical qubits. 2019 Gidney-Ekera: ~20 million qubits, 8 hours. May 2025 Gidney: under 1 million noisy qubits, under a week (same hardware assumptions; gains from approximate residue arithmetic, yoked surface codes, magic state cultivation).
- [S] Feb 2026 Iceberg Quantum "Pinnacle" architecture claims RSA-2048 with under 100,000 physical qubits using qLDPC codes (different architecture, not like-for-like with Gidney).
- [S] ECC-256 needs far fewer Toffoli gates than RSA-2048 (cited as ~70-90 million vs ~6.5 billion) so ECC falls faster once hardware exists. Cited figure of under 500,000 qubits for ECC-256 comes from a secondary news summary: verify before using in a report.
- [S] Caveat from analysts: these assume decoders, control electronics, cryogenics and fab yield scale to ~1M qubits, none demonstrated; Shor on RSA-2048 needs days of unbroken operation.
- [I] Safe framing for a report: estimates are falling faster than hardware is improving, so planning dates are policy-driven, not prediction-driven.

## 3. Standards and deadlines

- [S] Aug 2024 NIST final: FIPS 203 ML-KEM (Kyber), FIPS 204 ML-DSA (Dilithium), FIPS 205 SLH-DSA (SPHINCS+). FN-DSA (Falcon, FIPS 206) in progress. HQC selected Mar 2025 as backup KEM (draft 2026, final expected 2027).
- [S] NIST IR 8547 (draft, Nov 2024): 112-bit quantum-vulnerable algorithms (RSA-2048, P-256 class) deprecated after 2030, all quantum-vulnerable public-key disallowed after 2035. Dates are calendar-fixed, not tied to any quantum milestone, and the doc is still a draft.
- [S] CNSA 2.0: firmware/software signing should use LMS or XMSS (NIST SP 800-208); an FAQ update later allowed ML-DSA-87 for firmware signing. ASD recommends ceasing RSA/ECDH/ECDSA by end of 2030.
- [S] One source says Executive Order 14412 (June 2026) accelerated the US federal timeline and another page cites 2030 key-establishment / 2031 signature deadlines. Single-source, unverified: check on whitehouse.gov or Federal Register before citing.
- [S] NIST CSWP 39 (crypto agility): a cryptographic inventory is the first step of any agility program.
- [S] Forescout (Aug 2025 - Apr 2026): PQC-capable TLS in enterprise networks ~8% IT, 5.6% IoT/IoMT, 0.8% OT; nearly half of IoT devices carry critical risk with no PQC capability.

## 4. ESP32 specifics

### 4.1 Where public-key crypto lives
- [S] Secure Boot V2: ROM verifies 2nd-stage bootloader, bootloader verifies app. RSA-PSS (RSA-3072) or ECDSA (P-256/P-384, chip dependent). A SHA-256 digest of the public key is stored in eFuse; the public key itself sits in the signature block appended to every signed image. Up to a few key digests, with permanent revocation of individual keys. Classic ESP32 needs ECO V3+ for Secure Boot V2 and supports RSA-3072 with a single key.
- [S] ECDSA Secure Boot V2 is flagged "not functional for certain input vectors" on ESP32-P4 and ESP32-C5 docs; Espressif recommends RSA there.
- [B] TLS/mTLS to cloud brokers: ECDHE key exchange plus ECDSA or RSA certificates, via mbedTLS in ESP-IDF. OTA uses HTTPS plus the signed-image check.

### 4.2 Corrections and nuances to the pasted document
- [I] The eFuse stores a digest of the key, not the key. Shor still applies because every signed image carries the full public key in its signature block, so a hash commitment does not hide it.
- [S] Revoking an eFuse key slot does not help if every slot holds a classical key. The real blocker: Mask ROM supports only classical verification and cannot be patched.
- [S] "2030-2035 timeline" in the document is NIST's policy deadline, not a forecast of when a CRQC arrives.
- [S] "Resource starvation" is partly outdated. See 4.3: some 2026 results show PQC beating classical on ESP32. The sharper constraint is sizes (see 4.3) and SRAM for TLS buffers, plus signing-side key management.
- [I] Open gap worth testing: Espressif's hybrid boot puts the PQ check in the 2nd-stage bootloader, which ROM verifies only with a classical signature. An attacker who can forge classical signatures and write the bootloader region could replace the bootloader and drop the PQ check. Practical exposure depends on bootloader-OTA support and flash write access. Needs verification against the esp-pqc docs before claiming it.

### 4.3 PQC on ESP32: measured data
- [S] Espressif esp-pqc (blog 14 Oct 2026): software component on a liboqs fork plus mbedTLS override; needs ESP-IDF v6.0+; TLS examples on all SoCs; PQ bootloader verification supports ESP32-C3, C5, C6 only. Hybrid TLS 1.3 uses X25519MLKEM768 and ML-DSA-65 certificates.
- [S] Sizes: ML-KEM-768 hybrid key share 1,216 B (X25519: 32 B); ML-DSA-65 public key 1,952 B, signature 3,309 B (ECDSA-P256 ~64 B each); example CA cert 7,571 B. Larger mbedTLS I/O buffers needed.
- [S] ESP32-C5 at 80 MHz, RSA-3072 partner: hybrid boot verify ~91 ms total (SHA-256 ~30 ms hardware, ML-DSA-65 verify ~44 ms software, RSA verify ~13 ms hardware). PQ adds ~78 ms boot time and 8 KB flash (12 KB total signature footprint). ML-DSA-65 verify ~22 ms in a FreeRTOS task. Hybrid TLS handshake ~300 ms on C5. Espressif says dedicated PQC hardware is planned for future SoCs.
- [S] arXiv 2603.10274 (ESP32 DTLS 1.3): ML-KEM-512 handshake ~313 ms, 35% faster than ECDHE P-256; with ML-DSA-44 ~225 ms; certificate verification ~17 ms (ML-DSA-44) vs ~194 ms (ECDSA).
- [S] Preprint (ESP32-WROOM, Kyber/Dilithium/Falcon/SPHINCS+): high-security ML-DSA variants carry significant memory and compute overhead on constrained hardware.
- [S] PMC13485069: ML-KEM, ML-DSA, SLH-DSA all run on ESP32-C6 without external memory. (Full text blocked by a bot check; only the abstract was read.)
- [S] Conflict: an Elsevier-indexed study reports ML-KEM trials on ESP32 DevKit, ESP32 Super Mini, ESP8266 and Pico failed from memory limits. Results depend on implementation, parameter set and IDF config.
- [S] Hash-based boot: LMS verify cost is dominated by hashing, which suits ESP32's SHA accelerator; wolfSSL ranks verify speed LMS > XMSS > SLH-DSA; stateful keys need careful state management (NIST suggests HSM-side signing).
- [S] Other tooling: krypteia-quantica (pure-Rust no_std ML-KEM/ML-DSA/SLH-DSA, targets ESP32-C3), liboqs_mlkem ESP-IDF component, wolfSSL.

## 5. CBOM and crypto discovery

- [S] CBOM = inventory of cryptographic assets (algorithms, keys, certificates, protocols, libraries) in CycloneDX. CycloneDX 1.6 added it (Apr 2024), became Ecma-424 (Jul 2024), 1.7 added more (Oct 2025), 2.0 will add behaviours/profiles.
- [S] Schema bits: cryptographic-asset with assetType (algorithm, protocol, certificate, related-crypto-material); algorithmProperties (primitive, algorithmFamily, parameterSetIdentifier, cryptoFunctions, executionEnvironment, nistQuantumSecurityLevel 0-5); evidence with occurrences, methods and confidence in [0,1]. nistQuantumSecurityLevel = 0 marks quantum-vulnerable.
- [S] IBM (MAgiCS, May 2026) lists CBOM generation challenges: detection accuracy (false negatives from reflection, dynamic loading, stripped binaries), naming ambiguity (secp256r1 = prime256v1 = P-256), hybrid vs plain ECC, config-driven crypto, transitive dependencies. Tooling: CBOMkit (hyperion for source, theia for artifacts), Linux Foundation PQCA.
- [S] Existing tools and their gaps: cryptoscan-pqc (repo/source rule-based, CycloneDX 1.6, PQ risk classes, notes existing tooling misses firmware); IIFVDCAS (ESP32/Arduino pipeline, CBOM from binary strings only, flags AES-128/DES/MD5/SHA-1/RC4/SSLv3, no quantum-vulnerability classification of RSA/ECC detected from code).
- [S] Research on binary crypto detection: FoC (LLM summarising/retrieving crypto functions in stripped binaries, evaluated on firmware, not Xtensa-specific); earlier signature/graph methods (GRAP, constant and loop-feature matching).
- [I] Gap this implies: no public tool that (a) parses ESP32 app images, (b) identifies crypto in stripped Xtensa code including inlined/accelerator-backed calls, and (c) emits a CBOM with PQ-risk and migration-feasibility.

## 6. ESP32 firmware analysis pipeline facts

- [S] Dump: esptool read_flash; app image starts at 0xE9 magic; partition table at 0x8000; factory/ota apps e.g. 0x10000; esptool image_info lists segments (IRAM/DRAM/IROM/DROM) and load addresses.
- [S] Ghidra: needs ghidra-xtensa plus an ESP32 flash loader; Ghidra decompiles Xtensa poorly in places (a CTF writeup notes failed decompilation of a simple XOR loop); radare2 supports Xtensa; windowed ABI (ENTRY/RETW) is the default on classic ESP32/S3.
- [S] binwalk needs ESP32 magic definitions for ESP-IDF images.
- [S] ESP32 ROM exports symbols (esp_rom/ld files), so ROM-resident routines can be matched by address.
- [B] Hardware crypto goes through peripheral registers (SHA, AES, RSA/MPI accelerators). A scanner that only looks for software constants will miss accelerator-backed use. Register-access patterns are a detection feature. Compilers inline and unroll, erasing function boundaries.

## 7. RVCE Experiential Learning

- [S] RVCE's NAAC EL document describes EL as hands-on and PBL-based (Kolb's cycle: concrete experience, reflective observation, abstract conceptualisation, active experimentation), emphasising reflection, collaboration and feedback, with EL topics and "EL evaluation rubrics" per department and semester.
- [S] RVCE academic calendars show EL as: topic finalisation early in the semester, then Phase I and Phase II evaluations alongside CIE (continuous internal evaluation).
- [S] Course catalogues for CSE are public for older schemes (2018, 2021). The current-scheme III-sem CSE EL rubric was not found publicly.
- NOT FOUND: exact weightage and rubric for III-sem CSE EL under the current scheme. Team reports three graded phases and a publication/notable-outcome target. Need: the EL guideline sheet from the course faculty.
- Note: a rubric found on the way (UNF) belongs to another university. Do not use it as RVCE's.

## 8. Open questions for the team
1. Exact EL rubric: weightage per phase, deliverables, publication expectation.
2. Hardware available: which ESP32 variants (classic LX6, S3, C3, C6)? How many boards?
3. Does the team want a security-research contribution (novel detection) or a systems/benchmark contribution?
4. Verify items marked unverified: EO 14412, ECC-256 qubit figure, bootloader-replacement gap.

## Sources
- Espressif, Post-Quantum Cryptography on ESP32 (Oct 2026): https://developer.espressif.com/blog/2026/10/esp32-post-quantum-cryptography/
- ESP-IDF Secure Boot v2 docs: https://docs.espressif.com/projects/esp-idf/en/latest/esp32c5/security/secure-boot-v2.html
- Gidney, 2048-bit RSA with under a million noisy qubits: https://arxiv.org/abs/2505.15917
- Quantum Insider, Q-Day papers summary: https://thequantuminsider.com/2026/03/31/q-day-just-got-closer-three-papers-in-three-months-are-rewriting-the-quantum-threat-timeline/
- postquantum.com, how to read quantum roadmaps: https://postquantum.com/quantum-for-cybersecurity/how-to-read-quantum-roadmaps/
- NIST IR 8547 explainer: https://www.encryptionconsulting.com/nist-ir-8547-2030-2035-action-plan/
- PQC migration hard realities (CNSA 2.0, LMS/XMSS): https://www.encryptionconsulting.com/pqc-migration-the-hard-realities/
- HQC selection: https://utimaco.com/news/blog-posts/pqc-news-nist-announces-hqc-fifth-algorithm-be-standardized
- PQ TLS on ESP32 (arXiv 2603.10274): https://arxiv.org/abs/2603.10274
- ML-KEM/ML-DSA/SLH-DSA on ESP32-C6: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC13485069/
- Kyber/Dilithium/Falcon/SPHINCS+ on ESP32-WROOM: https://www.preprints.org/manuscript/202605.1386/v1
- wolfSSL, LMS vs XMSS vs SLH-DSA: https://www.wolfssl.com/lms-versus-xmss-versus-slh-dsa-for-secure-boot/
- Hash-based secure boot (JCEN): https://springerlink.bibliotecabuap.elogim.com/content/pdf/10.1007/s13389-024-00362-4.pdf
- IBM, Anatomy of CBOMs (MAgiCS 2026): https://magics-workshop.cs.hs-rm.de/slides/The%20Anatomy%20of%20Cryptography%20Bills%20of%20Materials.pdf
- CycloneDX CBOM: https://cyclonedx.org/capabilities/cbom/
- cryptoscan-pqc: https://pypi.org/project/cryptoscan-pqc/
- IIFVDCAS: https://github.com/sudoNaji/IIFVDCAS
- FoC (LLM crypto function ID in stripped binaries): https://arxiv.org/abs/2403.18403
- Crypto agility / NIST CSWP 39 summary: https://promwad.com/news/crypto-agility-long-lifecycle-embedded-devices-pqc-transition
- NXP PQC embedded white paper: https://nxp.com/docs/en/white-paper/POSTQUANCOMPWPA4.pdf
- Forescout PQC adoption data: https://postquantum.com/security-pqc/forescout-pqc-adoption-data-2026/
- ESP32 Ghidra/RE: https://olof-astrand.medium.com/analyzing-an-esp32-flash-dump-with-ghidra-e70e7f89a57f , https://datanoisetv.github.io/practical-reverse-engineering/part3/14-xtensa-esp32
- RVCE EL (NAAC): https://naac.rvce.edu.in/sites/default/files/2024-05/2.3.1%20EL%20-%20ICT.pdf
