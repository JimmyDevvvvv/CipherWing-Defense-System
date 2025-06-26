# agent/entropy_checker.py
import math

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    entropy = 0
    for count in freq:
        if count:
            p = count / len(data)
            entropy -= p * math.log2(p)
    return entropy

def check_entropy(file_path: str) -> float:
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 100)  # read first 100KB
        return calculate_entropy(data)
    except Exception as e:
        return 0.0
