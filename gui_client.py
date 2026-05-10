import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import threading
import time
import json
import io
from PIL import Image, ImageTk

# ייבוא המחלקות שלנו משאר הקבצים
from client import RemoteControlClient
from network_utils import NetworkNode
from encryption_manager import EncryptionManager
from system_controller import SystemController

# הגדרות עיצוב כלליות לממשק
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class DashboardWindow(ctk.CTkToplevel):
    """חלון צפייה ושליטה (המחשב השולט שרואה את המסך של הנשלט)"""

    def __init__(self, client, username, parent_hub):
        super().__init__()
        self.client = client
        self.parent_hub = parent_hub
        self.title(f"Itay Nedorez C&C - Controlling Remote Device")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.protocol("WM_DELETE_WINDOW", self.close_dashboard)  # טיפול בסגירת חלון

        self.canvas_frame = ctk.CTkFrame(self)
        self.canvas_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.screen_canvas = tk.Canvas(self.canvas_frame, bg="black", cursor="crosshair")
        self.screen_canvas.pack(fill="both", expand=True)

        # כאן בעתיד נחבר את תנועות העכבר
        self.screen_canvas.bind("<Motion>", self.on_mouse_move)
        self.screen_canvas.bind("<Button-1>", self.on_mouse_click)

    def update_frame(self, frame_bytes):
        """מקבלת תמונה (Bytes) מהרשת, מעבדת אותה ומציירת אותה על ה-Canvas"""
        try:
            if not frame_bytes: return
            image = Image.open(io.BytesIO(frame_bytes))
            # שינוי גודל התמונה בהתאם לגודל החלון
            image = image.resize((self.winfo_width(), self.winfo_height()), Image.Resampling.LANCZOS)
            self.photo = ImageTk.PhotoImage(image)
            self.screen_canvas.create_image(0, 0, image=self.photo, anchor="nw")
        except Exception:
            pass

    def on_mouse_move(self, event):
        pass

    def on_mouse_click(self, event):
        pass

    def close_dashboard(self):
        """סוגרת את החלון ומחזירה אותנו לחלון ההאב"""
        self.destroy()
        self.parent_hub.deiconify()


class HubWindow(ctk.CTkToplevel):
    """חלון הבית של המשתמש לאחר ההתחברות (Hub). מאפשר לייצר קוד או להתחבר לקוד."""

    def __init__(self, client, username, parent_login):
        super().__init__()
        self.client = client
        self.username = username
        self.parent_login = parent_login

        self.title(f"Itay Nedorez System - Hub ({username})")
        self.geometry("500x450")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.quit_app)

        self.label = ctk.CTkLabel(self, text="Remote Control Hub", font=("Roboto", 24, "bold"))
        self.label.pack(pady=20)

        # אזור השיתוף (מחשב נשלט)
        self.share_frame = ctk.CTkFrame(self)
        self.share_frame.pack(pady=10, padx=20, fill="x")
        self.share_label = ctk.CTkLabel(self.share_frame, text="Allow Remote Control", font=("Roboto", 16, "bold"))
        self.share_label.pack(pady=5)
        self.my_code_var = tk.StringVar(value="--- --- ---")
        self.code_display = ctk.CTkLabel(self.share_frame, textvariable=self.my_code_var, font=("Roboto", 32, "bold"),
                                         text_color="cyan")
        self.code_display.pack(pady=10)
        self.gen_code_btn = ctk.CTkButton(self.share_frame, text="Generate Code", command=self.generate_code, width=200)
        self.gen_code_btn.pack(pady=10)

        # אזור ההתחברות (מחשב שולט)
        self.connect_frame = ctk.CTkFrame(self)
        self.connect_frame.pack(pady=20, padx=20, fill="x")
        self.connect_label = ctk.CTkLabel(self.connect_frame, text="Control Remote Computer",
                                          font=("Roboto", 16, "bold"))
        self.connect_label.pack(pady=5)
        self.target_code_entry = ctk.CTkEntry(self.connect_frame, placeholder_text="Enter 9-digit code",
                                              justify="center", width=200, height=35)
        self.target_code_entry.pack(pady=10)
        self.connect_btn = ctk.CTkButton(self.connect_frame, text="Connect", command=self.connect_to_target, width=200,
                                         fg_color="green", hover_color="darkgreen")
        self.connect_btn.pack(pady=10)

        self.dashboard = None
        self.is_streaming = False
        self.sys_controller = SystemController()

        # הפעלת Thread (תהליכון) שמקשיב להודעות מהשרת ברקע
        self.listening = True
        threading.Thread(target=self.listen_to_server, daemon=True).start()

    def generate_code(self):
        """בקשת קוד חדש מהשרת"""
        enc_msg = EncryptionManager.aes_encrypt(self.client.aes_key, "GET_CODE")
        NetworkNode.send_packet(self.client.sock, 20, enc_msg)

    def connect_to_target(self):
        """נסיון התחברות למחשב מרוחק באמצעות הקוד שהוזן"""
        code = self.target_code_entry.get().replace(" ", "")
        if len(code) != 9 or not code.isdigit():
            messagebox.showerror("Error", "Please enter a valid 9-digit code.")
            return
        enc_code = EncryptionManager.aes_encrypt(self.client.aes_key, code)
        NetworkNode.send_packet(self.client.sock, 22, enc_code)

    def listen_to_server(self):
        """מאזינה כל הזמן לפקודות שמגיעות מהשרת ומטפלת בהן בהתאם"""
        while self.listening:
            try:
                msg_type, payload = NetworkNode.recv_packet(self.client.sock)
                if msg_type is None: break

                # השרת שלח לנו את הקוד שנוצר
                if msg_type == 21:
                    decrypted = EncryptionManager.aes_decrypt(self.client.aes_key, payload).decode()
                    formatted_code = f"{decrypted[:3]} {decrypted[3:6]} {decrypted[6:]}"  # עיצוב יפה לקוד
                    self.my_code_var.set(formatted_code)

                # השרת מאשר (או דוחה) את הקוד שהזנו כדי להתחבר למישהו
                elif msg_type == 23:
                    decrypted = EncryptionManager.aes_decrypt(self.client.aes_key, payload).decode()
                    if decrypted == "SUCCESS":
                        self.after(0, self.open_dashboard)  # מעבר למסך השליטה
                    else:
                        messagebox.showerror("Connection Failed", "Invalid or expired code.")

                # השרת אומר לנו להתחיל לשדר (מישהו התחבר לקוד שלנו)
                elif msg_type == 24:
                    self.after(0, lambda: self.my_code_var.set("🔴 LIVE - SHARED"))
                    self.is_streaming = True
                    threading.Thread(target=self.start_target_stream, daemon=True).start()

                # קיבלנו פריים של וידאו מהמחשב שאנחנו שולטים עליו
                elif msg_type == 100:
                    if payload and len(payload) > 16:
                        decrypted_frame = EncryptionManager.aes_decrypt(self.client.aes_key, payload)
                        if self.dashboard and decrypted_frame:
                            self.after(0, self.dashboard.update_frame, decrypted_frame)

                # קיבלנו פקודת עכבר/מקלדת מהמחשב ששולט עלינו
                elif msg_type == 50:
                    decrypted_cmd = EncryptionManager.aes_decrypt(self.client.aes_key, payload).decode()
                    print(f"[*] Command: {json.loads(decrypted_cmd)}")

            except Exception:
                break

    def open_dashboard(self):
        """פותחת את חלון השליטה (Dashboard) במקרה של התחברות מוצלחת ליעד"""
        self.withdraw()  # מסתיר את ה-Hub
        self.dashboard = DashboardWindow(self.client, self.username, self)

    def start_target_stream(self):
        """לולאה שרצה ברקע במחשב הנשלט, מצלמת ושולחת וידאו כל הזמן"""
        while self.is_streaming:
            try:
                screen_data = self.sys_controller.take_screenshot()
                if screen_data:
                    encrypted_frame = EncryptionManager.aes_encrypt(self.client.aes_key, screen_data)
                    NetworkNode.send_packet(self.client.sock, 100, encrypted_frame)
                time.sleep(0.05)  # המתנה קלה כדי לא להעמיס על הרשת (בערך 20 פריימים בשנייה)
            except Exception:
                break

    def quit_app(self):
        """כיבוי מסודר של הכל בעת סגירת האפליקציה"""
        self.listening = False
        self.is_streaming = False
        self.parent_login.destroy()


class RegisterWindow(ctk.CTkToplevel):
    """חלון הרישום למשתמש חדש במערכת"""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Create New Account")
        self.geometry("400x450")
        self.resizable(False, False)

        ctk.CTkLabel(self, text="Sign Up", font=("Roboto", 24, "bold")).pack(pady=30)

        # שדות ההזנה לשם וסיסמה
        self.reg_user = ctk.CTkEntry(self, placeholder_text="New Username", width=250, height=40)
        self.reg_user.pack(pady=10)

        self.reg_pass = ctk.CTkEntry(self, placeholder_text="New Password", show="*", width=250, height=40)
        self.reg_pass.pack(pady=10)

        # כפתור אישור שמפעיל את הלוגיקה
        self.confirm_btn = ctk.CTkButton(self, text="Register", command=self.handle_registration, width=250, height=40,
                                         fg_color="green", hover_color="darkgreen")
        self.confirm_btn.pack(pady=30)

    def handle_registration(self):
        """שואב את הנתונים ומעביר ללקוח התקשורת לשליחה לשרת"""
        user = self.reg_user.get()
        pwd = self.reg_pass.get()

        # בדיקה שהמשתמש באמת הזין משהו
        if not user or not pwd:
            messagebox.showwarning("Error", "Please fill all fields")
            return

        # וידוא שיש לנו חיבור לשרת (Handshake)
        client = self.parent.get_active_client()
        if not client:
            messagebox.showerror("Error", "Cannot connect to server")
            return

        # שליחה לשרת ובדיקת תשובה
        result = client.register(user, pwd)

        if result == "OK":
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
            self.destroy()  # סוגר את חלון ההרשמה
        elif result == "EXISTS":
            messagebox.showerror("Error", "Username already exists. Please choose another.")
        else:
            messagebox.showerror("Error", "Connection to server failed.")


class LoginWindow(ctk.CTk):
    """חלון הכניסה הראשי של האפליקציה (הראשון שעולה)"""

    def __init__(self):
        super().__init__()
        self.title("Itay Nedorez System login")
        self.geometry("400x550")
        self.resizable(False, False)

        self.label = ctk.CTkLabel(self, text="Itay Nedorez System login", font=("Roboto", 24, "bold"))
        self.label.pack(pady=40)

        # שדה שם משתמש
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=250, height=40)
        self.username_entry.pack(pady=10)

        # יצירת Frame לשדה הסיסמה ולכפתור העין ביחד
        self.pass_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.pass_frame.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.pass_frame, placeholder_text="Password", show="*", width=200, height=40)
        self.password_entry.pack(side="left", padx=(0, 5))

        self.show_pass_btn = ctk.CTkButton(self.pass_frame, text="👁", width=45, height=40, command=self.toggle_password)
        self.show_pass_btn.pack(side="right")

        # כפתור לוגין
        self.login_button = ctk.CTkButton(self, text="Login", command=self.handle_login, width=250, height=40)
        self.login_button.pack(pady=10)

        # כפתור מעבר להרשמה (פותח חלון נפרד)
        self.register_button = ctk.CTkButton(self, text="Create New Account", fg_color="transparent", border_width=2,
                                             text_color="white", width=250, height=40, command=self.open_register)
        self.register_button.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="Disconnected", text_color="gray")
        self.status_label.pack(side="bottom", pady=10)
        self.client = None

    def toggle_password(self):
        """פונקציה שמציגה או מסתירה את הסיסמה (כפתור העין)"""
        if self.password_entry.cget("show") == "*":
            self.password_entry.configure(show="")
            self.show_pass_btn.configure(text="🙈")
        else:
            self.password_entry.configure(show="*")
            self.show_pass_btn.configure(text="👁")

    def get_active_client(self):
        """
        פונקציית עזר שמוודאת שיש לנו חיבור בסיסי לשרת (כולל מפתחות).
        משמשת גם את הלוגין וגם את הרישום.
        """
        if self.client is None or not self.client.is_connected:
            self.client = RemoteControlClient()
            if not self.client.connect_to_server():
                return None
        return self.client

    def open_register(self):
        """פותח את חלון ההרשמה"""
        RegisterWindow(self)

    def handle_login(self):
        """תהליך אימות מול השרת לפתיחת האפליקציה"""
        user = self.username_entry.get()
        pwd = self.password_entry.get()

        if not user or not pwd:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return

        self.status_label.configure(text="Attempting to connect...", text_color="yellow")
        self.update()

        client = self.get_active_client()
        if not client:
            self.status_label.configure(text="Server Offline", text_color="red")
            messagebox.showerror("Error", "Server is down.")
            return

        # בדיקת אימות בשרת
        if client.login(user, pwd):
            self.status_label.configure(text="Connected Successfully!", text_color="green")
            self.withdraw()  # העלמת חלון הלוגין
            self.hub = HubWindow(self.client, user, self)  # פתיחת חלון ההאב
        else:
            self.status_label.configure(text="Login Failed", text_color="red")
            messagebox.showerror("Error", "Invalid credentials.")
            self.client = None  # מאפסים את הלקוח למקרה שינסה שוב


if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()