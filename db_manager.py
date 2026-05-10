import sqlite3
import hashlib


class DBManager:
    """
    מחלקה האחראית על ניהול מסד הנתונים המקומי (SQLite).
    מטפלת ברישום משתמשים ואימות הרשאות באמצעות סיסמאות מגובבות (Hashed)
    כדי לא לשמור סיסמאות כטקסט גלוי.
    """

    def __init__(self, db_name="system_db.db"):
        self.db_name = db_name
        self._init_db()  # הפעלת פונקציית האתחול בעת יצירת האובייקט

    def _init_db(self):
        """יוצרת את טבלת המשתמשים אם היא אינה קיימת."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # יצירת טבלה עם מזהה ייחודי (ID), שם משתמש שחייב להיות ייחודי, וסיסמה מגובבת
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users
                       (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT UNIQUE NOT NULL,
                           password_hash TEXT NOT NULL
                       )
                       ''')
        conn.commit()
        conn.close()

        # יצירת משתמש ברירת מחדל כדי שיהיה אפשר להתחבר מיד לבדיקות
        self.add_user("admin", "1234")

    def _hash_password(self, password):
        """מגבבת (מצפינה לכיוון אחד) את הסיסמה באלגוריתם SHA-256 לאבטחת מידע."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def add_user(self, username, password):
        """
        מוסיפה משתמש חדש.
        מחזירה True אם הצליח, False אם השם כבר קיים במערכת (בגלל אילוץ ה-UNIQUE בטבלה).
        """
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            # הכנסת הנתונים לטבלה (הסיסמה עוברת גיבוב לפני השמירה)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, self._hash_password(password)))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # שגיאה זו קופצת אם מנסים להכניס שם משתמש שכבר קיים
            return False
        finally:
            conn.close()  # תמיד נסגור את החיבור למסד הנתונים בסוף

    def verify_user(self, username, password):
        """
        מאמתת פרטי משתמש בעת התחברות (לוגין).
        מחזירה את ה-ID של המשתמש אם הפרטים נכונים, או None אם משהו שגוי.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        # חיפוש המשתמש לפי השם והסיסמה (המגובבת)
        cursor.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?",
                       (username, self._hash_password(password)))
        result = cursor.fetchone()
        conn.close()

        # אם result לא ריק, נחזיר את האינדקס ה-0 (שזה ה-ID). אחרת נחזיר None.
        return result[0] if result else None