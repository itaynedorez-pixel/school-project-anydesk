import socket
import json
from network_utils import NetworkNode
from encryption_manager import EncryptionManager


class RemoteControlClient:
    """
    מחלקת הלקוח שמנהלת את התקשורת מול השרת (שליחה וקבלת מידע).
    מטפלת בלחיצת היד (Handshake), התחברות (Login), והרשמה (Register).
    """

    def __init__(self, server_ip="127.0.0.1", server_port=9999):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # יצירת מפתח AES אקראי שילווה את הלקוח לאורך כל הסשן
        self.aes_key = EncryptionManager.generate_aes_key()
        self.is_connected = False

    def connect_to_server(self):
        """
        מבצעת התחברות לשרת ולחיצת יד (Handshake) להחלפת מפתחות הצפנה בלבד.
        לא עושה אימות משתמש בשלב זה, כדי לאפשר הרשמה או לוגין בהמשך.
        """
        # אם כבר מחוברים, אין צורך להתחבר שוב
        if self.is_connected:
            return True

        try:
            self.sock.connect((self.server_ip, self.server_port))

            # שלב 1: מחכים לקבל את המפתח הציבורי (RSA) של השרת (הודעה סוג 99)
            msg_type, payload = NetworkNode.recv_packet(self.sock)
            if msg_type != 99 or not payload:
                return False

            # טוענים את מפתח ה-RSA, מצפינים באמצעותו את מפתח ה-AES שלנו, ושולחים חזרה
            server_rsa_pub = EncryptionManager.load_public_key(payload)
            encrypted_aes_key = EncryptionManager.encrypt_with_rsa(server_rsa_pub, self.aes_key)
            NetworkNode.send_packet(self.sock, 99, encrypted_aes_key)

            self.is_connected = True
            return True
        except Exception as e:
            print(f"[!] Connection Error: {e}")
            return False

    def login(self, username, password):
        """שולחת בקשת אימות (Login) לשרת באמצעות מפתח ה-AES."""
        try:
            # אורזים את השם והסיסמה כמילון של JSON ומצפינים
            login_dict = {"username": username, "password": password}
            enc_login = EncryptionManager.aes_encrypt(self.aes_key, json.dumps(login_dict))

            # שולחים הודעה מסוג 1 (בקשת התחברות)
            NetworkNode.send_packet(self.sock, 1, enc_login)

            # מחכים לתשובה מהשרת (סוג 2 = תשובת התחברות)
            msg_type, enc_response = NetworkNode.recv_packet(self.sock)
            if msg_type == 2:
                response = EncryptionManager.aes_decrypt(self.aes_key, enc_response).decode()
                return response == "OK"  # מחזיר True אם השרת אישר
            return False
        except Exception:
            return False

    def register(self, username, password):
        """שולחת בקשת הרשמה (Register) למשתמש חדש בשרת."""
        try:
            # אורזים ומצפינים את פרטי הרישום
            reg_dict = {"username": username, "password": password}
            enc_reg = EncryptionManager.aes_encrypt(self.aes_key, json.dumps(reg_dict))

            # שולחים הודעה מסוג 3 (בקשת הרשמה)
            NetworkNode.send_packet(self.sock, 3, enc_reg)

            # מחכים לתשובה מהשרת (סוג 4 = תשובת הרשמה)
            msg_type, enc_response = NetworkNode.recv_packet(self.sock)
            if msg_type == 4:
                # יחזיר "OK" אם הצליח, או "EXISTS" אם המשתמש כבר תפוס
                return EncryptionManager.aes_decrypt(self.aes_key, enc_response).decode()
            return "ERROR"
        except Exception:
            return "ERROR"