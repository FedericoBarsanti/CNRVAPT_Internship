# Automotive Mobile Application Security Testing

**Sanitized research artifact** from an automotive mobile app penetration test. Documents a complete methodology for assessing connected vehicle mobile apps with custom tooling.

> **Scope:** Android mobile app + cloud API layers
> **Focus:** Authentication, authorization, rate limiting, replay protection
> **Status:** Fully sanitized - no PII, tokens, or production data

## Contents

**📄 `methodology/EV_VAPT_Methodology.pdf`** - 9-phase security assessment methodology covering attack chains, technical foundations, and standards mapping (UNECE R155/R156, ISO/SAE 21434, NIST CSF, OWASP Mobile Top 10)

**🛠️ Tools:**
- `split_burp_xml.py` - Split large Burp Suite XML exports for analysis
- `pin_bruteforce.py` - PIN authentication security testing (rate limiting, lockout)
- `sanitize_for_github.py` - Remove sensitive data before publication
- `requirements.txt` - Python dependencies

---

## Methodology Overview

**Standards Alignment:** UNECE R155/R156, ISO/SAE 21434, NIST CSF, OWASP Mobile Top 10

**Technical Stack:** OAuth2, Android security model, SSL pinning bypass (Frida), Burp Suite, JADX, Android Studio

**9-Phase Workflow:**
1. Environment setup (emulator/device, CA, proxy)
2. Reconnaissance & feature mapping
3. SSL pinning bypass
4. Traffic capture & AI-assisted analysis
5. Static analysis (APK decompilation, secrets)
6. Dynamic exploitation & validation
7. Tool development & automation
8. Compliance mapping
9. Reporting & responsible disclosure

**Key Findings:** Weak PIN protections, missing replay protection, hardcoded credentials, token lifecycle vulnerabilities

---

## Tool Usage

**Installation:**
```bash
pip install -r tools/requirements.txt
```

### `split_burp_xml.py`
Split large Burp Suite XML exports into manageable chunks for analysis.

```bash
python3 tools/split_burp_xml.py http_history.xml --items-per-chunk 35 --output-dir chunks/
```

### `pin_bruteforce.py`
Evaluate PIN authentication security (rate limiting, lockout, timing patterns). Features ethical rate limiting (5 attempts/300s), evidence-grade JSONL logging, and OAuth2 token management.

```bash
python3 tools/pin_bruteforce.py \
  --api https://api.placeholder.test \
  --access-token TOKEN \
  --device-id DEVICE_ID \
  --min-pin 0000 --max-pin 9999
```

⚠️ **Authorization required** - Use only on systems you have explicit permission to test.

### `sanitize_for_github.py`
Remove sensitive data (emails, VINs, tokens, device IDs, IPs) before publication.

```bash
python3 tools/sanitize_for_github.py --input raw_logs/ --output sanitized/
```

---

## Legal & Ethical Notice

⚠️ **Authorization Required** - All tools are for **authorized security research and educational purposes only**.

- Testing performed under explicit authorization in controlled research environment
- All data fully sanitized (no PII, VINs, tokens, credentials)
- Findings responsibly disclosed following CVD practices
- **Unauthorized system access is illegal** (CFAA, Computer Misuse Act, etc.)

**Use only on systems you own or have written permission to test.**

---

## Use Cases

- **Portfolio** - Demonstrates automotive cybersecurity methodology development
- **Education** - Reference for Android app security, OAuth2 patterns, API testing
- **Research** - SSL pinning bypass, traffic analysis, compliance mapping (R155/R156, 21434)

---

## License

Educational and authorized security research purposes only. See individual tool files for specific terms.

