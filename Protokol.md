# Návrh protokolu pro přenos souborů přes ICMP

Tento protokol je vlastní implementací spolehlivého přenosu souborů nad ICMP/ICMPv6, inspirovaný principy TCP, ale přizpůsobený pro skrytý kanál.

---

## 1. FLAGY protokolu

Pro přehlednost jsou definovány flagy jako `enum`:

| Enum hodnota | Název      | Význam |
|-------------:|:-----------|:-------|
| 0            | FLAG_HELLO | Počáteční paket (SYN) / HELLO |
| 1            | FLAG_READY | Odpověď serveru (SYN-ACK) / READY |
| 2            | FLAG_ACK   | Acknowledgement (krátké potvrzení) |
| 3            | FLAG_META  | Metadata paket (filename, filesize, total_fragments, hash) |
| 4            | FLAG_DATA  | Data paket (obsahuje fragment souboru) |
| 5            | FLAG_FIN   | Klient ukončuje přenos (FIN) |
| 6            | FLAG_OK    | Server: přenos OK (vše přijato a validováno) |
| 7            | FLAG_FAIL  | Server: přenos selhal / chybí fragmenty — v těle seznam chybějících seq_num nebo kód chyby |

---

## 2. Handshake (navázání spojení)

1. **Klient** pošle první ICMP paket typu `FLAG_HELLO`.
2. **Server** odpoví paketem typu `FLAG_READY` (potvrzení dostupnosti a připravenosti přijímat).
3. **Klient** potvrdí paketem typu `FLAG_ACK`.

**Výsledek:** logické navázání spojení mezi klientem a serverem.

---

## 3. Metadata paket (první paket)

- Flag: `FLAG_META`
- Obsahuje informace o souboru:
  - `filename` – název souboru
  - `filesize` – velikost souboru v bajtech
  - `total_fragments` – počet fragmentů
  - `seq_num` – počáteční sekvenční číslo (většinou 1)
  - Volitelně: `hash` (např. SHA256) pro kontrolu integrity

**Účel:** server připraví buffer a určí počet očekávaných fragmentů.

---

## 4. Data pakety

- Flag: `FLAG_DATA`
- Obsahuje:
  - `seq_num` – pořadové číslo fragmentu
  - `data` – fragment šifrovaných dat souboru
- Fragmentace: každý fragment přibližně 1400 B (pro standardní MTU)
- Server ukládá fragmenty podle `seq_num`.

**Doporučení:** přidat kontrolní součet (CRC/checksum) pro každý fragment.

---

## 5. Loučící paket (terminace spojení)

- Flag: `FLAG_FIN`
- Klient posílá poslední paket typu `FLAG_FIN`.
- Server provede:
  - Kontrolu přijetí všech fragmentů (`seq_num` 1..total_fragments)
  - Kontrolu integrity souboru (pokud se posílal hash)
- Server odpoví:
  - `FLAG_OK` – vše přijato a validováno
  - `FLAG_FAIL` – chybějící/neplatné fragmenty, případně seznam chybějících seq_num

**Výsledek:** jasné ukončení spojení a kontrola completeness přenosu.

---

## 6. Shrnutí protokolu

- Protokol simuluje spolehlivý přenos nad ICMP (handshake, seq_num, kontrola integrity, ukončení spojení)
- Klient i server šifrují payload pomocí AES (klíč = login uživatele)
- Retransmise nejsou povinné, ale lze je implementovat
- Struktura paketů umožňuje flexibilní rozšíření pro další metadata nebo kontrolní mechanismy

---

## 7. Ukázka přenosu souboru

| Čas | Odesílatel | Flag       | Poznámka |
|-----|------------|-----------|----------|
| t0  | Klient     | FLAG_HELLO | Začínáme spojení |
| t1  | Server     | FLAG_READY | Potvrzení dostupnosti |
| t2  | Klient     | FLAG_META  | Posíláme metadata (filename, filesize, total_fragments) |
| t3  | Server     | FLAG_ACK   | Potvrzení přijetí metadata |
| t4  | Klient     | FLAG_DATA  | Fragment 1 |
| t5  | Klient     | FLAG_DATA  | Fragment 2 |
| ... | Klient     | FLAG_DATA  | Další fragmenty |
| tn  | Klient     | FLAG_FIN   | Konec přenosu |
| tn+1| Server     | FLAG_OK / FLAG_FAIL | Výsledek přenosu |
