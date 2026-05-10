import mss
import pyautogui
import io
from PIL import Image


class SystemController:
    """
    מחלקה האחראית על פעולות ברמת מערכת ההפעלה של המחשב הנשלט.
    מטפלת בצילום המסך ושליחת פקודות מערכת.
    """

    def __init__(self):
        # הגדרת הגנת Fail-Safe של pyautogui (מונע קריסה אם העכבר בפינת המסך)
        pyautogui.FAILSAFE = False

        # הערה: הסרנו מפה את self.sct = mss.mss() כדי למנוע את שגיאת ה-Threads
        # הצילום יבוצע כעת באופן בטוח בתוך הפונקציה עצמה.

    def take_screenshot(self):
        """
        מצלם את המסך, דוחס ל-JPEG ומחזיר את המידע כבייט-אראי.
        השימוש ב- 'with mss.mss() as sct' מבטיח תאימות מלאה לסביבה מרובת-תהליכונים.
        """
        try:
            # פתיחת אובייקט הצילום באופן מקומי ל-Thread שקורא לו
            with mss.mss() as sct:
                # צילום המסך הראשי (מוניטור 1)
                monitor = sct.monitors[1]
                sct_img = sct.grab(monitor)

                # המרה לאובייקט תמונה של PIL לצורך דחיסה
                img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")

                # יצירת אובייקט זיכרון (RAM) כדי לא לשמור קבצים פיזית על הדיסק הקשיח
                img_byte_arr = io.BytesIO()

                # דחיסה ושמירה. איכות 60% מאזנת היטב בין איכות תמונה לתעבורת רשת חלקה
                img.save(img_byte_arr, format='JPEG', quality=60)

                return img_byte_arr.getvalue()

        except Exception as e:
            # אם יש שגיאה, נדפיס אותה ונחזיר רצף ריק כדי לא להקריס את הלקוח
            print(f"[-] Screenshot error: {e}")
            return b""