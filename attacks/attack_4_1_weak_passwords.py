"""
ATAC 4.1 — Politica slaba de parole
=====================================
Demonstreaza ca aplicatia accepta parole extrem de slabe la inregistrare.

Vulnerabilitate: aplicatia nu valideaza complexitatea sau lungimea parolei.
Impact: utilizatorii pot crea conturi cu parole triviale, usor de ghicit.
"""

import requests

BASE_URL = "http://127.0.0.1:5000"

# Parole extrem de slabe pe care le vom incerca
PAROLE_SLABE = [
    "1",
    "a",
    "12",
    "abc",
    "1234",
    "password",
    "qwerty",
]

print("=" * 55)
print("  ATAC 4.1 — Testare politica slaba de parole")
print("=" * 55)
print(f"  Target: {BASE_URL}/register")
print("=" * 55)

for parola in PAROLE_SLABE:
    email = f"victim_{parola}@test.com"

    response = requests.post(
        f"{BASE_URL}/register",
        data={"email": email, "password": parola},
        allow_redirects=True
    )

    # Daca inregistrarea a reusit, suntem redirectionati la /login
    # sau vedem mesajul de succes
    if "Cont creat" in response.text or response.url.endswith("/login"):
        status = "VULNERABIL ✗ — cont creat cu succes"
    elif "exista deja" in response.text:
        status = "DEJA EXISTA (rulat anterior)"
    else:
        status = "BLOCAT ✓"

    print(f"  Parola: {parola!r:12}  →  {status}")

print()
print("[!] Concluzie: aplicatia accepta parole de 1 caracter.")
print("[!] Nicio validare de lungime sau complexitate nu exista.")
print("[!] Risc: brute force si credential stuffing triviale.")
