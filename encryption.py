from cryptography.fernet import Fernet
import io, os
from PIL import Image
from tkinter import filedialog, messagebox

from matplotlib import pyplot as plt
from pixel_shift import reverse_shift_pixels
from key_utils import generate_key_from_pin, get_file_hash, log_event, calculate_entropy, get_file_size_kb

def encrypt_image(image_path, pin):
    if not image_path:
        messagebox.showwarning("Warning", "No image selected!")
        return
    if not pin:
        messagebox.showwarning("Warning", "Enter a PIN for encryption!")
        return

    try:
        image = Image.open(image_path).convert('RGB')
        entropy_before = calculate_entropy(image)
        size_before = get_file_size_kb(image_path)

        shifted_img = reverse_shift_pixels(image)
        entropy_after = calculate_entropy(Image.fromarray(shifted_img))

        buffer = io.BytesIO()
        Image.fromarray(shifted_img).save(buffer, format='PNG')
        img_bytes = buffer.getvalue()

        original_hash = get_file_hash(img_bytes)
        log_event(f"Image selected: {image_path}")
        log_event(f"Pre-encryption SHA256: {original_hash}")

        key = generate_key_from_pin(pin)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(img_bytes)

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
            size_after = get_file_size_kb(save_path)

            # Save meta file
            meta_path = save_path + ".meta"
            with open(meta_path, "w") as meta_file:
                meta_file.write(original_hash)

            log_event(f"Image encrypted and saved to: {save_path}")
            log_event(f"Hash saved to: {meta_path}")

            messagebox.showinfo("Original Image Stats", f"Entropy: {entropy_before}\nSize: {size_before} KB")

            # === COMBINED CHART ===
            fig, axes = plt.subplots(1, 2, figsize=(10, 4))

            # Entropy chart
            bars1 = axes[0].bar(["Original", "Encrypted"], [entropy_before, entropy_after], color=["skyblue", "orange"])
            axes[0].set_title("Entropy Comparison")
            axes[0].set_ylabel("Entropy")
            axes[0].set_ylim(0, 8.5)
            for bar, val in zip(bars1, [entropy_before, entropy_after]):
                axes[0].text(bar.get_x() + bar.get_width() / 2, val + 0.1, f"{val:.2f}", ha='center')

            # File size chart
            bars2 = axes[1].bar(["Original (KB)", "Encrypted (KB)"], [size_before, size_after], color=["green", "red"])
            axes[1].set_title("File Size Comparison")
            axes[1].set_ylabel("Size (KB)")
            axes[1].set_ylim(0, max(size_before, size_after) * 1.3)
            for bar, val in zip(bars2, [size_before, size_after]):
                axes[1].text(bar.get_x() + bar.get_width() / 2, val + 1, f"{val:.2f} KB", ha='center')

            plt.tight_layout()
            plt.show()

            messagebox.showinfo("Success", "Image Encrypted and Saved!")

    except Exception as e:
        log_event(f"Encryption failed: {e}")
        messagebox.showerror("Error", f"Encryption failed: {e}")
