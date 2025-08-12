import hashlib
import base64
import re
from datetime import datetime
import csv
import os
from collections import Counter
import numpy as np

def generate_key_from_pin(pin):
    key = hashlib.sha256(pin.encode()).digest()
    return base64.urlsafe_b64encode(key)

def check_pin_strength(pin):
    strength = "Weak"
    if len(pin) >= 8:
        if re.search(r'[A-Z]', pin) and re.search(r'[a-z]', pin) and re.search(r'\d', pin) and re.search(r'[!@#$%^&*(),.?":{}|<>]', pin):
            strength = "Strong"
        elif re.search(r'[A-Za-z]', pin) and re.search(r'\d', pin):
            strength = "Medium"
    elif len(pin) >= 5 and re.search(r'[A-Za-z]', pin) and re.search(r'\d', pin):
        strength = "Medium"
    
    log_event(f"PIN Strength Checked: {strength}")
    return strength

def get_file_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def log_event(event):
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", "activity_log.csv")
    file_exists = os.path.isfile(log_path)

    with open(log_path, "a", newline='') as log_file:
        writer = csv.writer(log_file)
        if not file_exists:
            writer.writerow(["Timestamp", "Event"])
        writer.writerow([datetime.now().strftime('%Y-%m-%d %H:%M:%S'), event])

def calculate_entropy(image):
    grayscale = image.convert("L")
    pixel_values = list(grayscale.getdata())
    total_pixels = len(pixel_values)
    frequency = Counter(pixel_values)
    entropy = -sum((count / total_pixels) * np.log2(count / total_pixels) for count in frequency.values())
    return round(entropy, 4)

def get_file_size_kb(path):
    return round(os.path.getsize(path) / 1024, 2)
