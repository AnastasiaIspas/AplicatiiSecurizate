"""
RE-TEST — Verificare ca atacurile nu mai functioneaza pe v2_fixed
=================================================================
Ruleaza toate re-testele pe http://127.0.0.1:5001 (versiunea securizata)
si afiseaza un raport final.
"""

import requests
import hashlib
import time
import sqlite3
import os

BASE_URL = "http://127.0.0.1:5001"

rezultate = []

def log(test, trecut, detaliu=""):
    simbol = "BLOCAT ✓" if trecut else "VULNERABIL ✗"
    rezultate.append((test, trecut, detaliu))
    print(f"  [{simbol}] {test}")
    if detaliu:
        print(f"           → {detaliu}")


print("=" * 65)
print("  RE-TEST — Versiunea securizata (v2) pe port 5001")
print("=" * 65)


# -------------------------------------------------------
# RE-TEST 4.1 — Parole slabe blocate
# -------------------------------------------------------
print("\n[4.1] Testare politica parola...")

parole_slabe = ["1", "abc", "1234", "password", "qwerty"]
toate_blocate = True

for parola in parole_slabe:
    r = requests.post(
        f"{BASE_URL}/register",
        data={"email": f"retest_{parola}@test.com", "password": parola},
        allow_redirects=True
    )
    if "Cont creat" in r.text or r.url.endswith("/login"):
        toate_blocate = False
        print(f"           Parola '{parola}' → ACCEPTATA (vulnerabil!)")
    else:
        print(f"           Parola '{parola}' → blocata")

log("4.1 Parole slabe", toate_blocate,
    "Toate parolele slabe au fost respinse" if toate_blocate else "Unele parole slabe au fost acceptate")


# -------------------------------------------------------
# RE-TEST 4.2 — Hash MD5 nu mai e in baza de date
# -------------------------------------------------------
print("\n[4.2] Testare stocare parole (bcrypt vs MD5)...")

# Cream un cont nou cu parola valida
email_test = "retest_hash@test.com"
parola_test = "Parola123"

requests.post(
    f"{BASE_URL}/register",
    data={"email": email_test, "password": parola_test},
    allow_redirects=True
)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "v2_fixed", "authx_v2.db")
try:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT password_hash FROM users WHERE email = ?", (email_test,)).fetchone()
    conn.close()

    if user:
        hash_val = user["password_hash"]
        este_md5 = len(hash_val) == 32 and all(c in "0123456789abcdef" for c in hash_val)
        este_bcrypt = hash_val.startswith("$2b$") or hash_val.startswith("$2a$")

        if este_bcrypt:
            log("4.2 Stocare bcrypt", True, f"Hash: {hash_val[:20]}... (bcrypt cu salt)")
        elif este_md5:
            log("4.2 Stocare bcrypt", False, "Parola stocata ca MD5!")
        else:
            log("4.2 Stocare bcrypt", False, f"Hash necunoscut: {hash_val[:20]}")
    else:
        log("4.2 Stocare bcrypt", False, "Utilizatorul nu a fost creat")
except Exception as e:
    log("4.2 Stocare bcrypt", False, f"Eroare DB: {e}")


# -------------------------------------------------------
# RE-TEST 4.4 — Mesaj unic (inainte de 4.3 ca sa nu fie blocat de rate limiting)
# -------------------------------------------------------
print("\n[4.4] Testare mesaj unic (anti user enumeration)...")

r_inexistent = requests.post(
    f"{BASE_URL}/login",
    data={"email": "inexistent_total@fake.com", "password": "ceva"},
    allow_redirects=True
)

r_existent = requests.post(
    f"{BASE_URL}/login",
    data={"email": "retest_hash@test.com", "password": "gresita"},
    allow_redirects=True
)


# -------------------------------------------------------
# RE-TEST 4.3 — Rate limiting activ
# -------------------------------------------------------
print("\n[4.3] Testare rate limiting (6 incercari gresite)...")

blocat = False
for i in range(6):
    r = requests.post(
        f"{BASE_URL}/login",
        data={"email": "retest_ratelimit@test.com", "password": "gresita"},
        allow_redirects=True
    )
    if "Prea multe incercari" in r.text:
        blocat = True
        print(f"           Incercarea {i+1} → BLOCAT de rate limiting")
        break
    else:
        print(f"           Incercarea {i+1} → neautorizat (normal)")

log("4.3 Rate limiting", blocat,
    "Blocat dupa 5 incercari" if blocat else "Nu a fost blocat dupa 6 incercari!")

mesaj_inexistent = "Credentiale invalide" in r_inexistent.text
mesaj_existent   = "Credentiale invalide" in r_existent.text

mesaje_identice = mesaj_inexistent and mesaj_existent

log("4.4 Mesaj unic", mesaje_identice,
    "Ambele cazuri returneaza 'Credentiale invalide'" if mesaje_identice
    else "Mesaje diferite — user enumeration posibil!")


# -------------------------------------------------------
# RE-TEST 4.5 — Cookie-uri securizate
# -------------------------------------------------------
print("\n[4.5] Testare flaguri cookie sesiune...")

# Cream un cont valid si ne logam
email_cookie = "retest_cookie@test.com"
requests.post(f"{BASE_URL}/register",
              data={"email": email_cookie, "password": "Parola123"},
              allow_redirects=True)

r_login = requests.post(
    f"{BASE_URL}/login",
    data={"email": email_cookie, "password": "Parola123"},
    allow_redirects=False
)

set_cookie = r_login.headers.get("Set-Cookie", "")
httponly = "HttpOnly" in set_cookie
samesite = "SameSite" in set_cookie

cookie_securizat = httponly and samesite
log("4.5 Cookie HttpOnly + SameSite", cookie_securizat,
    f"Set-Cookie: {set_cookie[:80]}..." if set_cookie else "Niciun cookie setat")


# -------------------------------------------------------
# RE-TEST 4.6 — Token random, nu mai poate fi ghicit
# -------------------------------------------------------
print("\n[4.6] Testare token resetare (nu mai e predictibil)...")

timestamp_inainte = int(time.time())

requests.post(
    f"{BASE_URL}/forgot-password",
    data={"email": email_cookie}
)

timestamp_dupa = int(time.time())

token_gasit = False
for token_candidat in range(timestamp_inainte - 1, timestamp_dupa + 2):
    r = requests.post(
        f"{BASE_URL}/reset-password",
        data={"token": str(token_candidat), "password": "Hacked123"},
        allow_redirects=True
    )
    if "Parola a fost resetata" in r.text:
        token_gasit = True
        break

log("4.6 Token random (nu predictibil)", not token_gasit,
    "Tokenul nu poate fi ghicit prin timestamp" if not token_gasit
    else "Tokenul a fost ghicit!")


# -------------------------------------------------------
# RAPORT FINAL
# -------------------------------------------------------
print()
print("=" * 65)
print("  RAPORT FINAL RE-TEST")
print("=" * 65)
trecute = sum(1 for _, t, _ in rezultate if t)
total = len(rezultate)
for test, trecut, detaliu in rezultate:
    simbol = "✓" if trecut else "✗"
    print(f"  [{simbol}] {test}")
print()
print(f"  Rezultat: {trecute}/{total} teste trecute")
if trecute == total:
    print("  Toate vulnerabilitatile au fost remediate!")
else:
    print(f"  {total - trecute} vulnerabilitati inca prezente!")
print("=" * 65)
