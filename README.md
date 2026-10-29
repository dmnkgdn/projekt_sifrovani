# Secure Chat Architecture (C++ Core & Python TUI)

Tento repozitář obsahuje semestrální projekt zaměřený na bezpečnou síťovou komunikaci a cross-language kryptografickou interoperabilitu. Projekt rozšiřuje původní nízkoúrovňovou C++ architekturu o moderní asynchronní terminálové rozhraní (TUI) v jazyce Python.

## Aktuální stav projektu (Work in Progress)

Projekt se nachází ve fázi architektonické přípravy a integrace:
- [x] **C++ Backend & CLI (`cpp_core/`):** Plně funkční asynchronní server (`epoll` v Edge-Triggered módu) a referenční CLI klient. Šifrování postavené na OpenSSL EVP API.
- [ ] **Python Kryptografický modul (`python_client/`):** *Ve vývoji* – implementace kompatibilního RSA-2048 handshaku a AES-256-CBC šifrování.
- [ ] **Python TUI Klient (`python_client/`):** *Plánováno* – asynchronní uživatelské rozhraní postavené na frameworku `Textual` a `asyncio`.

## Architektura a Bezpečnostní specifikace

Komunikační protokol je navržen jako jazykově nezávislý:
1. **Handshake (Asymetrická fáze):** Server po navázání TCP spojení odesílá veřejný klíč (RSA-2048, PEM). Klient generuje 256bitový symetrický klíč, který zašifruje pomocí veřejného klíče serveru se striktním využitím **OAEP paddingu** a odešle zpět.
2. **Přenos dat (Symetrická fáze):** Veškerá další komunikace probíhá šifrovaně pomocí **AES-256 v módu CBC**. Každá jednotlivá zpráva využívá unikátní, kryptograficky bezpečný 16bajtový Inicializační Vektor (IV).

## Struktura repozitáře

* `cpp_core/` – Původní implementace serveru a klienta v C++ (OpenSSL, POSIX sockety, `epoll`).
* `python_client/` – Nová implementace multiplatformního TUI klienta v jazyce Python.

## Kompilace a spuštění (C++ Core)

Pro sestavení stávající serverové části je vyžadován kompilátor s podporou C++17 a knihovna OpenSSL (`libssl-dev` / `openssl`).
