"""Hebrew wording for health-scan findings (the status page, Home Assistant).

Findings are built in English inside the code; `localize` rewrites a finding
for language "he". Unknown text is left as it is.
"""

from __future__ import annotations

import re

_TITLES: list[tuple[re.Pattern, str]] = [(re.compile(p), h) for p, h in [
    (r"^Disk (.+) has (\d+) unreadable sectors$", "בדיסק {0} יש {1} סקטורים שלא ניתן לקרוא"),
    (r"^Disk (.+) SMART: (.+)$", "דיסק {0}: בדיקת SMART במצב {1}"),
    (r"^Disk (.+) status: (.+)$", "דיסק {0}: מצב {1}"),
    (r"^Disk (.+) is hot: (.+)$", "דיסק {0} חם מדי: {1}"),
    (r"^Storage pool (.+) status: (.+)$", "מאגר האחסון {0}: מצב {1}"),
    (r"^Storage pool (.+) has no disk protection$", "למאגר האחסון {0} אין הגנה מכשל דיסק"),
    (r"^Volume (.+) is (\d+)% full$", "הווליום {0} מלא ב-{1}%"),
    (r"^Volume (.+) status: (.+)$", "הווליום {0}: מצב {1}"),
    (r"^Data scrubbing schedule is paused on (.+)$", "התזמון של בדיקת הנתונים (scrubbing) מושהה ב-{0}"),
    (r"^DSM update available ?(.*)$", "יש עדכון ל-DSM {0}"),
    (r"^Could not read storage: (.+)$", "לא הצלחתי לקרוא את נתוני האחסון: {0}"),
    (r"^DSM checks skipped: (.+)$", "בדיקות DSM דולגו: {0}"),
    (r"^Backup '(.+)' is (.+)$", "הגיבוי '{0}' במצב {1}"),
    (r"^No backup targets configured to watch$", "לא הוגדרו גיבויים למעקב"),
    (r"^Containers not checked: (.+)$", "המכולות לא נבדקו: {0}"),
    (r"^(.+) broke after an update$", "{0} נשברה אחרי עדכון"),
]]

_ADVICE = {
    "Resume it in Storage Manager > Storage > Data Scrubbing; it finds silent disk errors while they can still be repaired.":
        "אפשר לחדש אותו מכאן (בקשה מ-Claude) או ב-Storage Manager. הבדיקה מוצאת שגיאות שקטות בדיסקים כל עוד אפשר לתקן אותן.",
    "If its disk fails, everything on it is lost: keep a backup of it.":
        "אם הדיסק שלו נכשל, כל מה שעליו אובד. כדאי לגבות אותו.",
    "Install it from Control Panel > Update & Restore.":
        "מתקינים מ-Control Panel > Update & Restore.",
    "Use the rollback button in the alert, or ask Claude to roll back.":
        "לחץ על כפתור ההחזרה בהתראה, או בקש מ-Claude להחזיר לגרסה הקודמת.",
}

# Container findings, by diagnose code: (title, advice). {c} is the container.
_CODES = {
    "restart_loop": ("{c}: נכנסה ללולאת קריסות", "הסיבה בדרך כלל בשגיאה שחוזרת ביומן שלה."),
    "stopped": ("{c}: כבויה", ""),
    "no_restart_policy": ("{c}: לא תעלה לבד אחרי הפעלה מחדש של ה-NAS", "להוסיף restart: unless-stopped."),
    "never_started": ("{c}: נוצרה ואף פעם לא הופעלה", ""),
    "docker_error": ("{c}: Docker דיווח על שגיאה בהפעלה", ""),
    "unhealthy": ("{c}: בדיקת התקינות שלה נכשלת", ""),
    "repeated_error": ("{c}: אותה שגיאה חוזרת שוב ושוב ביומן", ""),
    "broke_after_update": ("{c}: נשברה אחרי עדכון", "אפשר להחזיר לגרסה הקודמת."),
    "standalone": ("{c}: לא שייכת לפרויקט Compose", "כדאי ליצור אותה מחדש כפרויקט עם אותן הגדרות."),
    "latest_tag": ("{c}: משתמשת בגרסה latest", ""),
    "no_auth": ("{c}: השירות פתוח בלי סיסמה", "כל מי שברשת הבית יכול להשתמש בו."),
    "deprecated_image": ("{c}: האימג' שלה כבר לא מתוחזק", "כדאי לעבור לאימג' החלופי."),
    "privileged": ("{c}: רצה עם הרשאות מלאות (privileged)", ""),
    "docker_socket": ("{c}: יש לה גישה ישירה ל-Docker", ""),
    "orphan_compose_rename": ("{c}: שם שבור אחרי בנייה מחדש של הפרויקט", ""),
}


def localize(f: dict, code: str = "", container: str = "") -> dict:
    """Return the finding with Hebrew title/advice where a translation exists."""
    out = dict(f)
    if code:
        key = "log" if code.startswith("log_") else code
        if key in _CODES:
            t, a = _CODES[key]
            out["title"] = t.format(c=container)
            if a:
                out["advice"] = a
            return out
        if key == "log":
            out["title"] = f"{container}: שגיאה ביומן ({f['title'].split(': ', 1)[-1]})"
            return out
    for rx, he in _TITLES:
        m = rx.match(f.get("title", ""))
        if m:
            out["title"] = he.format(*m.groups()).strip()
            break
    if f.get("advice") in _ADVICE:
        out["advice"] = _ADVICE[f["advice"]]
    return out
