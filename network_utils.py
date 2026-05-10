import socket
import struct

class NetworkNode:
    """
    מחלקה האחראית על ניהול התקשורת הבסיסית ברשת (שכבת התעבורה).
    משתמשת בפרוטוקול מותאם אישית (TLV - Type, Length, Value) כדי למנוע קיטוע נתונים.
    """

    @staticmethod
    def send_packet(sock, msg_type, payload=b""):
        """
        אורזת ושולחת הודעה על גבי הרשת.
        מוודאת שהמידע מומר למערך בתים (Bytes) לפני השליחה כדי למנוע קריסות.
        """
        try:
            # הגנת סוגי משתנים (מונע את שגיאות ה-None וה-String)
            if payload is None:
                payload = b""
            elif isinstance(payload, str):
                payload = payload.encode('utf-8')
            elif not isinstance(payload, (bytes, bytearray)):
                payload = str(payload).encode('utf-8')

            # אריזת ה-Header: סוג ההודעה (4 בתים) וגודל התוכן (4 בתים)
            header = struct.pack("!II", msg_type, len(payload))
            sock.sendall(header + payload)
        except Exception as e:
            pass # התעלמות שקטה במקרה של ניתוק כדי לא לקרוס

    @staticmethod
    def recv_packet(sock):
        """
        קוראת הודעה מהרשת בצורה בטוחה.
        קוראת קודם 8 בתים (Header) כדי לדעת כמה בתים נוספים לקרוא.
        """
        try:
            header = NetworkNode._recv_all(sock, 8)
            if not header:
                return None, None

            msg_type, length = struct.unpack("!II", header)

            if length == 0:
                return msg_type, b""

            payload = NetworkNode._recv_all(sock, length)
            if payload is None:
                return None, None

            return msg_type, bytes(payload)
        except Exception:
            return None, None

    @staticmethod
    def _recv_all(sock, n):
        """קוראת מספר מדויק של בתים מהרשת."""
        data = bytearray()
        while len(data) < n:
            try:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            except Exception:
                return None
        return bytes(data)