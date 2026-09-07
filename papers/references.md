# P4 — XTS-AES Side-Channel CPA: References

1. Mangard, S., Oswald, E., & Popp, T. "Power Analysis Attacks: Revealing the Secrets of Smart Cards." Springer, 2007.
   - CPA/DPA theory, leakage models, countermeasures.

2. NIST SP 800-38E. "Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Block-Oriented Storage Devices." 2010.
   - XTS-AES construction, tweakable block cipher.

3. Coron, J.-S. "Resistance of Some AES Implementations against Side Channel Attacks." CHES 2005.
   - S-box leakage model, Hamming weight hypothesis.

4. Kocher, P., Jaffe, J., & Jun, B. "Differential Power Analysis." CRYPTO 1999.
   - Foundational DPA/CPA paper.

5. Brier, E., Clavier, C., & Olivier, F. "Correlation Power Analysis with a Leakage Model." CHES 2004.
   - Pearson correlation CPA formulation.

6. Espressif. "ESP32-C6 Technical Reference Manual." 2023.
   - AES hardware accelerator, timing, flash encryption.

7. Standaert, F.-X. et al. "A Unified Framework for the Analysis of Side-Channel Key Recovery Attacks." EUROCRYPT 2009.
   - Key rank metrics, guessing entropy.

8. General-purpose CPA tool references: ChipWhisperer documentation (https://github.com/newaetech/chipwhisperer).
   - Open-source CPA reference implementation.
