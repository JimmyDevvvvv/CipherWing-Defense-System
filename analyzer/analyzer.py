import pefile
import numpy as np
import os
import re

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * np.log2(p_x)
    return entropy


def extract_ascii_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()
    strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    return [s.decode(errors="ignore") for s in strings]


def extract_pe_features(file_path):
    features = {}

    try:
        pe = pefile.PE(file_path)

        
        entropies = []
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip('\x00')
            entropy = section.get_entropy()
            entropies.append(entropy)
        features["mean_section_entropy"] = np.mean(entropies)
        features["max_section_entropy"] = np.max(entropies)

        # Suspicious import detection
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode(errors="ignore"))

        features["num_imports"] = len(imports)
        features["suspicious_imports"] = int(any(api in imports for api in [
            "CreateRemoteThread", "VirtualAlloc", "WinExec", "ShellExecute", "WriteProcessMemory"
        ]))

        # Crypto detection
        features["crypto_api_detected"] = int(any(api in imports for api in [
            "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext"
        ]))

    except Exception as e:
        print(f"[!] Failed to parse {file_path}: {e}")
        return None

    return features


def analyze(file_path):
    features = {}

    # File size
    features["file_size"] = os.path.getsize(file_path)

    # Entropy of full file
    with open(file_path, 'rb') as f:
        data = f.read()
    features["file_entropy"] = calculate_entropy(data)

    # Strings
    ascii_strings = extract_ascii_strings(file_path)
    features["num_strings"] = len(ascii_strings)

    # PE-specific features
    if file_path.endswith(".exe") or file_path.endswith(".dll"):
        pe_feats = extract_pe_features(file_path)
        if pe_feats:
            features.update(pe_feats)

    return features
