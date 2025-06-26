import yara
import os
import hashlib

# === COMPILE RULES ===
def compile_yara_rules(rules_dir="yara_rules"):
    rules = {
        "malware": {},
        "benign": {},
        "suspicious": {}
    }

    if not os.path.exists(rules_dir):
        print(f"[!] YARA rules directory not found at: {rules_dir}")
        return rules

    for filename in os.listdir(rules_dir):
        if filename.endswith(".yar"):
            path = os.path.join(rules_dir, filename)
            try:
                rule = yara.compile(filepath=path)

                # Categorize based on filename or metadata
                if "benign" in filename.lower():
                    category = "benign"
                elif "suspicious" in filename.lower():
                    category = "suspicious"
                else:
                    category = "malware"

                rules[category][filename] = rule
                print(f"[+] Loaded {category} rule: {filename}")
            except yara.YaraSyntaxError as e:
                print(f"[!] Syntax error in {filename}: {e}")
            except Exception as e:
                print(f"[!] Error loading {filename}: {e}")
    return rules

# === FILE PROPERTIES ANALYSIS ===
def analyze_file_properties(file_path):
    try:
        file_size = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()

        is_pe = content.startswith(b'MZ')
        _, ext = os.path.splitext(file_path.lower())
        is_executable = ext in ['.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.pif']

        return {
            'size': file_size,
            'hash': file_hash,
            'is_pe': is_pe,
            'is_executable': is_executable,
            'extension': ext
        }
    except Exception as e:
        print(f"[!] Error analyzing file properties: {e}")
        return None

# === FILE SCAN ===
def scan_file_with_yara(file_path, rules):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return None

    print(f"[+] Scanning file: {file_path}")
    file_props = analyze_file_properties(file_path)
    if not file_props:
        return None

    malware_matches = []
    benign_matches = []
    suspicious_matches = []

    for category in ["malware", "benign", "suspicious"]:
        for rule_name, rule in rules[category].items():
            try:
                matches = rule.match(filepath=file_path)
                if matches:
                    print(f"[+] {category.title()} rule '{rule_name}' matched!")
                    if category == "malware":
                        malware_matches.extend(matches)
                    elif category == "benign":
                        benign_matches.extend(matches)
                    else:
                        suspicious_matches.extend(matches)
            except Exception as e:
                print(f"[!] Error scanning with {category} rule {rule_name}: {e}")

    is_malware = len(malware_matches) > 0
    is_benign = len(benign_matches) > 0
    is_suspicious = len(suspicious_matches) > 0

    final_classification = "UNKNOWN"
    confidence = "LOW"

    if is_malware and not is_benign:
        final_classification = "MALWARE"
        confidence = "HIGH"
    elif is_benign and not is_malware:
        final_classification = "BENIGN"
        confidence = "HIGH"
    elif is_malware and is_benign:
        final_classification = "LIKELY_MALWARE"
        confidence = "MEDIUM"
    elif is_suspicious:
        final_classification = "SUSPICIOUS"
        confidence = "MEDIUM"
    elif not file_props['is_pe'] or not file_props['is_executable']:
        final_classification = "NON_EXECUTABLE"
        confidence = "HIGH"

    malware_families = []
    benign_labels = []

    for match in malware_matches:
        if hasattr(match, 'meta') and 'family' in match.meta:
            malware_families.append(match.meta['family'])
        else:
            malware_families.append("unknown")

    for match in benign_matches:
        if hasattr(match, 'meta') and 'family' in match.meta:
            benign_labels.append(match.meta['family'])
        else:
            benign_labels.append("benign")

    return {
        "file_path": file_path,
        "file_hash": file_props['hash'],
        "file_size": file_props['size'],
        "file_extension": file_props['extension'],
        "is_pe": file_props['is_pe'],
        "is_executable": file_props['is_executable'],
        "final_classification": final_classification,
        "confidence": confidence,
        "is_malware": is_malware,
        "is_benign": is_benign,
        "is_suspicious": is_suspicious,
        "malware_families": list(set(malware_families)),
        "benign_labels": list(set(benign_labels)),
        "malware_matches": [str(m) for m in malware_matches],
        "benign_matches": [str(m) for m in benign_matches],
        "suspicious_matches": [str(m) for m in suspicious_matches]
    }
