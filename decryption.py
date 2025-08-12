from cryptography.fernet import Fernet
from PIL import Image, UnidentifiedImageError
import io, os
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
from pixel_shift import reverse_unshift_pixels
from key_utils import generate_key_from_pin, get_file_hash, get_file_size_kb, log_event, calculate_entropy

def decrypt_image(encrypted_file_path, pin):
    if not encrypted_file_path:
        messagebox.showwarning("Warning", "No encrypted file selected!")
        return
    if not pin:
        messagebox.showwarning("Warning", "Enter the correct PIN to decrypt!")
        return

    key = generate_key_from_pin(pin)
    fernet = Fernet(key)

    try:
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        # Get encrypted file size BEFORE deleting it
        size_before = get_file_size_kb(encrypted_file_path)

        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_hash = get_file_hash(decrypted_data)
        log_event(f"Encrypted file loaded: {encrypted_file_path}")
        log_event(f"Post-decryption SHA256: {decrypted_hash}")

        # Check integrity
        meta_path = encrypted_file_path + ".meta"
        if os.path.exists(meta_path):
            with open(meta_path, "r") as meta_file:
                original_hash = meta_file.read().strip()
                if original_hash != decrypted_hash:
                    log_event("WARNING: Decrypted image hash mismatch!")
                    messagebox.showwarning("Integrity Alert", "Hash mismatch detected! File may be tampered with or wrong PIN used.")
                else:
                    log_event("Image integrity verified successfully.")
        else:
            log_event("No .meta file found. Skipping integrity check.")

        # Load and process image
        img = Image.open(io.BytesIO(decrypted_data)).convert('RGB')
        entropy_after = calculate_entropy(img)

        # Reverse pixel shift
        unshifted_img = reverse_unshift_pixels(img)

        # Ask where to save
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if save_path:
            Image.fromarray(unshifted_img).save(save_path)

            # Show preview
            Image.fromarray(unshifted_img).show()

            # Get size after save
            size_after = get_file_size_kb(save_path)

            # Clean up
            os.remove(encrypted_file_path)
            if os.path.exists(meta_path):
                os.remove(meta_path)

            log_event(f"Image decrypted and saved to: {save_path}")
            log_event("Encrypted and meta files deleted after successful decryption.")
            messagebox.showinfo("Success", f"Image decrypted and saved to: {save_path}\nEncrypted file deleted.")

            # === CHART: Entropy + File Size ===
            entropy_before = 8.0  # Approximate for encrypted
            fig, axes = plt.subplots(1, 2, figsize=(10, 4))

            # Entropy
            bars1 = axes[0].bar(["Encrypted", "Decrypted"], [entropy_before, entropy_after], color=["red", "skyblue"])
            axes[0].set_title("Entropy Comparison")
            axes[0].set_ylabel("Entropy")
            axes[0].set_ylim(0, 8.5)
            for bar, val in zip(bars1, [entropy_before, entropy_after]):
                axes[0].text(bar.get_x() + bar.get_width() / 2, val + 0.1, f"{val:.2f}", ha='center')

            # File size
            bars2 = axes[1].bar(["Encrypted (KB)", "Decrypted (KB)"], [size_before, size_after], color=["green", "orange"])
            axes[1].set_title("File Size Comparison")
            axes[1].set_ylabel("Size (KB)")
            axes[1].set_ylim(0, max(size_before, size_after) * 1.3)
            for bar, val in zip(bars2, [size_before, size_after]):
                axes[1].text(bar.get_x() + bar.get_width() / 2, val + 1, f"{val:.2f} KB", ha='center')

            plt.tight_layout()
            plt.show()

    except UnidentifiedImageError:
        log_event("Decryption failed: Invalid image or wrong PIN.")
        messagebox.showerror("Error", "Decryption failed: Invalid image or wrong PIN.")
    except Exception as e:
        log_event(f"Decryption failed: {e}")
        messagebox.showerror("Error", f"Decryption failed. {e}")
