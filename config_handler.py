import os
import json
import base64
import secrets
import hashlib
import pyotp
import qrcode  # ← Required for QR generation

CONFIG_FILE = "config.json"
QR_FOLDER = "qrcodes"
QR_FILE = "totp_qr.png"

def generate_device_secret():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def hash_master_password(password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode()

def setup_config():
    if os.path.exists(CONFIG_FILE):
        print("[!] Config already exists.")
        return

    master_password = input("Set your Master Password: ").strip()
    confirm = input("Confirm Master Password: ").strip()
    
    if master_password != confirm:
        print("Passwords do not match.")
        return

    device_secret = generate_device_secret()
    hashed_password = hash_master_password(master_password, device_secret)

    totp_secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name="SecurePassVault", issuer_name="SPV")

    print("\n[!] Scan this QR code using Google Authenticator or similar:")

    # 🖼️ Generate QR code
    img = qrcode.make(uri)

    # 📁 Ensure folder exists
    os.makedirs(QR_FOLDER, exist_ok=True)

    # 💾 Save QR code to file
    qr_path = os.path.join(QR_FOLDER, QR_FILE)
    img.save(qr_path)

    # 👁️ Show QR code
    img.show()

    config_data = {
        "device_secret": device_secret,
        "master_hash": hashed_password,
        "totp_secret": totp_secret
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

    print(f"\n[+] Config successfully saved. QR code saved at: {qr_path}")

if __name__ == "__main__":
    setup_config()
