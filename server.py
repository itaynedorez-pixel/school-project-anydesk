import socket
import threading
import json
import random
from network_utils import NetworkNode
from encryption_manager import EncryptionManager
from db_manager import DBManager


class RemoteControlServer:
    """
    השרת המרכזי שמאזין לכל הלקוחות, מנהל את מסד הנתונים,
    ומנתב את התקשורת המוצפנת בין מחשב שולט למחשב נשלט.
    """

    def __init__(self, ip="0.0.0.0", port=9999):
        self.ip = ip
        self.port = port
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.db = DBManager()  # יצירת חיבור למסד הנתונים

        # מילונים לשמירת מידע על הלקוחות המחוברים והקודים שלהם
        self.active_clients = {}
        self.code_to_user = {}

        # השרת מייצר לעצמו זוג מפתחות RSA פעם אחת בעת עלייתו
        self.rsa_private, self.rsa_public = EncryptionManager.generate_rsa_keys()
        self.rsa_public_bytes = EncryptionManager.serialize_public_key(self.rsa_public)

    def start(self):
        """הפעלת השרת והאזנה מתמדת לחיבורים חדשים."""
        try:
            # SO_REUSEADDR עוזר למנוע שגיאות של "פורט תפוס" כשעושים ריסטארט לשרת
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.ip, self.port))
            self.server_sock.listen(10)
            print(f"[*] Server started on {self.ip}:{self.port}")

            while True:
                client_sock, addr = self.server_sock.accept()
                # לכל לקוח שמתחבר, פותחים Thread (תהליכון) נפרד שלא יתקע את השרת
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            print(f"[!] Server crash: {e}")

    def handle_client(self, client_sock, addr):
        """הפונקציה שמטפלת בכל לקוח בנפרד לאורך כל חיי הסשן שלו."""
        print(f"[+] New connection from {addr}")
        user_id = None
        client_aes_key = None

        try:
            # --- שלב 1: Handshake (החלפת מפתחות) ---
            # השרת שולח את המפתח הציבורי שלו ללקוח
            NetworkNode.send_packet(client_sock, 99, self.rsa_public_bytes)
            # השרת מקבל מהלקוח את מפתח ה-AES שהוצפן ב-RSA
            msg_type, encrypted_aes_key = NetworkNode.recv_packet(client_sock)
            if msg_type != 99: return

            # מפענחים את מפתח ה-AES בעזרת המפתח הפרטי של השרת
            client_aes_key = EncryptionManager.decrypt_with_rsa(self.rsa_private, encrypted_aes_key)

            # --- שלב 2: אימות (Login) או הרשמה (Register) ---
            authenticated = False
            while not authenticated:  # לולאה שרצה עד שהלקוח עושה לוגין מוצלח
                msg_type, enc_payload = NetworkNode.recv_packet(client_sock)
                if msg_type is None: return

                # טיפול בבקשת התחברות (msg_type = 1)
                if msg_type == 1:
                    data = json.loads(EncryptionManager.aes_decrypt(client_aes_key, enc_payload).decode())
                    user_id = self.db.verify_user(data['username'], data['password'])

                    if user_id:
                        # המשתמש קיים והסיסמה נכונה - רושמים אותו במילון הפעילים
                        self.active_clients[user_id] = {
                            'sock': client_sock, 'aes_key': client_aes_key,
                            'username': data['username'], 'partner_id': None
                        }
                        NetworkNode.send_packet(client_sock, 2, EncryptionManager.aes_encrypt(client_aes_key, "OK"))
                        authenticated = True  # שוברים את הלולאה ועוברים לשלב השליטה
                    else:
                        NetworkNode.send_packet(client_sock, 2, b"FAIL")

                # טיפול בבקשת הרשמה (msg_type = 3)
                elif msg_type == 3:
                    data = json.loads(EncryptionManager.aes_decrypt(client_aes_key, enc_payload).decode())
                    # מנסים להוסיף את המשתמש למסד הנתונים
                    success = self.db.add_user(data['username'], data['password'])
                    response = "OK" if success else "EXISTS"

                    # שולחים תשובה ללקוח אם ההרשמה הצליחה או שהשם תפוס
                    NetworkNode.send_packet(client_sock, 4, EncryptionManager.aes_encrypt(client_aes_key, response))

            # --- שלב 3: לולאת הודעות AnyDesk (שליטה וניתוב) ---
            # כאן המשתמש כבר מחובר ומאומת, ואנחנו מטפלים בפקודות שליטה וקודים.
            while True:
                msg_type, payload = NetworkNode.recv_packet(client_sock)
                if msg_type is None: break

                decrypted_payload = EncryptionManager.aes_decrypt(client_aes_key, payload)

                if msg_type == 20:  # לקוח ביקש לייצר קוד שיתוף חדש (Generate Code)
                    code = str(random.randint(100000000, 999999999))
                    self.code_to_user[code] = user_id  # מקשרים את הקוד ל-ID של הלקוח
                    enc_code = EncryptionManager.aes_encrypt(client_aes_key, code)
                    NetworkNode.send_packet(client_sock, 21, enc_code)

                elif msg_type == 22:  # לקוח אחר מנסה להתחבר לקוד שהוזן
                    target_code = decrypted_payload.decode()
                    if target_code in self.code_to_user:
                        target_id = self.code_to_user[target_code]

                        # קישור הדדי: מגדירים מי השותף של מי
                        self.active_clients[user_id]['partner_id'] = target_id
                        self.active_clients[target_id]['partner_id'] = user_id

                        # מודיעים לשולט שההתחברות הצליחה
                        NetworkNode.send_packet(client_sock, 23,
                                                EncryptionManager.aes_encrypt(client_aes_key, "SUCCESS"))

                        # מודיעים לנשלט שהוא צריך להתחיל לצלם ולשדר את המסך
                        target_sock = self.active_clients[target_id]['sock']
                        target_key = self.active_clients[target_id]['aes_key']
                        NetworkNode.send_packet(target_sock, 24,
                                                EncryptionManager.aes_encrypt(target_key, "START_STREAMING"))
                    else:
                        # הקוד שגוי או לא קיים
                        NetworkNode.send_packet(client_sock, 23,
                                                EncryptionManager.aes_encrypt(client_aes_key, "INVALID_CODE"))

                elif msg_type == 100:  # ניתוב פריים וידאו מהנשלט לשולט
                    partner_id = self.active_clients[user_id]['partner_id']
                    if partner_id and partner_id in self.active_clients:
                        partner_info = self.active_clients[partner_id]
                        # מצפינים מחדש עם מפתח ה-AES של הצד השני ומעבירים
                        re_encrypted = EncryptionManager.aes_encrypt(partner_info['aes_key'], decrypted_payload)
                        NetworkNode.send_packet(partner_info['sock'], 100, re_encrypted)

                elif msg_type == 50:  # ניתוב פקודות שליטה (עכבר/מקלדת) מהשולט לנשלט
                    partner_id = self.active_clients[user_id]['partner_id']
                    if partner_id and partner_id in self.active_clients:
                        partner_info = self.active_clients[partner_id]
                        re_encrypted = EncryptionManager.aes_encrypt(partner_info['aes_key'], decrypted_payload)
                        NetworkNode.send_packet(partner_info['sock'], 50, re_encrypted)

        except Exception as e:
            print(f"[!] Error with client {addr}: {e}")
        finally:
            # פעולות ניקוי כשלקוח מתנתק (למנוע קריסות של השרת)
            if user_id in self.active_clients:
                self.code_to_user = {k: v for k, v in self.code_to_user.items() if v != user_id}
                del self.active_clients[user_id]
            client_sock.close()


if __name__ == "__main__":
    server = RemoteControlServer()
    server.start()