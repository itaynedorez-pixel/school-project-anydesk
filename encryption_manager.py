import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class EncryptionManager:
    """
    מנהל מערך ההצפנה (סייבר) של הפרויקט.
    משתמש בהצפנה היברידית: RSA להעברת מפתחות ראשונית, ו-AES לתקשורת השוטפת.
    """

    # === הצפנה אסימטרית (RSA) ===

    @staticmethod
    def generate_rsa_keys():
        """מייצרת זוג מפתחות RSA (פרטי וציבורי) עבור השרת."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """ממירה את המפתח הציבורי למערך בתים (Bytes) כדי שיהיה אפשר לשלוח ברשת."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key(pem_data):
        """טוענת מפתח ציבורי מתוך מערך בתים (הופכת אותו לאובייקט פעיל)."""
        return serialization.load_pem_public_key(bytes(pem_data), backend=default_backend())

    @staticmethod
    def encrypt_with_rsa(public_key, plaintext):
        """מצפינה מידע באמצעות מפתח RSA ציבורי."""
        # התיקון: בדיקה אם המידע הוא טקסט (מחרוזת) וקידוד נכון
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        else:
            plaintext = bytes(plaintext)

        return public_key.encrypt(
            plaintext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def decrypt_with_rsa(private_key, ciphertext):
        """מפענחת מידע באמצעות מפתח RSA פרטי."""
        return private_key.decrypt(
            bytes(ciphertext),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    # === הצפנה סימטרית (AES) ===

    @staticmethod
    def generate_aes_key():
        """מייצרת מפתח סשן AES אקראי באורך 256 ביט (32 בתים)."""
        return os.urandom(32)

    @staticmethod
    def aes_encrypt(key, plaintext):
        """
        מצפינה מידע בעזרת AES-CFB.
        מייצרת וקטור אתחול (IV) אקראי ומדביקה אותו בתחילת ההודעה.
        """
        if plaintext is None:
            return b""

        # התיקון: המרה בטוחה של טקסט לבתים
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        else:
            plaintext = bytes(plaintext)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def aes_decrypt(key, ciphertext):
        """
        מפענחת מידע שהוצפן ב-AES.
        קוראת את 16 הבתים הראשונים כ-IV ואת השאר כמחרוזת מוצפנת.
        """
        if not ciphertext or len(ciphertext) < 16:
            return b""
        ciphertext = bytes(ciphertext)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(actual_ciphertext) + decryptor.finalize()