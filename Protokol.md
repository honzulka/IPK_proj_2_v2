# Návrh protokolu pro Reliable Data Transfer over UDP

Tento protokol implementuje spolehlivý a uspořádaný přenos dat nad UDP. Je inspirován principy TCP, ale je zjednodušen tak, aby splňoval požadavky zadání.

---

## 1. Základní principy

Protokol zajišťuje:

* spolehlivý přenos (retransmise ztracených paketů)
* uspořádané doručení dat (sequence numbers)
* detekci duplicitních paketů
* odolnost vůči ztrátě, reorderingu a jitteru
* explicitní navázání a ukončení spojení
* průběžné potvrzování přijatých dat (ACK)
* ochranu integrity pomocí checksumu

---

## 2. Formát paketu

Každý UDP datagram obsahuje hlavičku a payload.

### Header

| Pole     | Velikost | Popis                                         |
| -------- | -------- | --------------------------------------------- |
| conn_id  | 32 bit   | Identifikátor spojení                         |
| seq      | 32 bit   | Sekvenční číslo (index segmentu)              |
| ack      | 32 bit   | Kumulativní ACK (nejbližší očekávaný segment) |
| len      | 16 bit   | Délka payloadu                                |
| flags    | 8 bit    | Typ paketu                                    |
| checksum | 16 bit   | Kontrolní součet (header + payload)           |

### Payload

* DATA paket: obsahuje data
* META paket: obsahuje metadata - velikost dat, celkový počet segmentů
* SYN paket: může obsahovat metadata 
* ACK/FIN: bez payloadu

---

## 3. Flagy

| Flag | Hodnota | Význam           |
| ---- | ------- | ---------------- |
| SYN  | 0x01    | Navázání spojení |
| ACK  | 0x02    | Potvrzení        |
| FIN  | 0x04    | Ukončení spojení |
| DATA | 0x08    | Přenos dat       |
| META | 0x10    | Metadata         |

Flagy lze kombinovat (např. SYN+ACK).

---

## 4. Navázání spojení (3-way handshake)

1. Klient → Server: `SYN`

   * nastaví `conn_id`
   * nastaví počáteční `seq`

2. Server → Klient: `SYN + ACK`

   * potvrzuje klienta (`ack = client_seq + 1`)
   * nastaví vlastní `seq`

3. Klient → Server: `ACK`

   * potvrzení serveru

**Výsledek:** spojení je navázáno a obě strany znají identifikátor spojení i počáteční sekvence.

---

## 5. Přenos dat

### METADATA paket

Prvním zaslaným paketem je tzv. META paket. Ten nese informaci o velikosti přenášeného souboru a počet segmentů.

* Flag: META
* Obsah:
  * asdf

---

### DATA pakety

* Flag: `DATA`
* Obsah:

  * `seq` – pořadové číslo segmentu
  * `len` – velikost dat
  * payload – data

---

### ACK (kumulativní potvrzení)

Receiver udržuje proměnnou `expected_seq`.

* pokud `seq == expected_seq`:

  * paket je přijat
  * data se zapíší
  * `expected_seq++`
* pokud `seq < expected_seq`:

  * duplicitní paket → ignorován
* pokud `seq > expected_seq`:

  * out-of-order paket → ignorován (Go-Back-N)

Receiver odesílá ACK:

```
ACK = expected_seq
```

---

## 6. Pipelining (Sliding Window)

Sender může mít více paketů současně „in-flight“.

* velikost okna: např. 5–10 paketů
* nové pakety jsou odesílány bez čekání na ACK

Receiver:

* zpracovává pakety sekvenčně
* potvrzuje kumulativně

---

## 7. Retransmise

Sender uchovává odeslané, ale nepotvrzené pakety.

### Timeout:

* pokud ACK nepřijde včas:

  * paket je znovu odeslán

### Strategie:

* Go-Back-N:

  * při ztrátě se znovu odešlou všechny pakety od prvního nepotvrzeného

---

## 8. Kontrola integrity

Každý paket obsahuje checksum:

* počítán přes header + payload
* receiver:

  * při chybě paket zahodí
  * neposílá ACK

---

## 9. Duplicitní a out-of-order pakety

Receiver:

* `seq < expected_seq` → duplicitní → ignorovat
* `seq > expected_seq` → mimo pořadí → ignorovat (Go-Back-N)

---

## 10. Ukončení spojení

1. Klient → Server: `FIN`
2. Server:

   * ověří úplnost dat
   * odešle `ACK`
3. Server → Klient: `FIN`
4. Klient → Server: `ACK`

**Výsledek:** spojení je korektně ukončeno.

---

## 11. Timeout a ukončení

Pokud po dobu `TIMEOUT` nedojde k žádnému progressu:

* aplikace se ukončí s chybou

Progress znamená:

* přijetí nových dat
* přijetí nového ACK
* krok handshake/teardown

---

## 12. Omezení velikosti

* maximální UDP payload: 1200 B
* velikost headeru: ~17 B
* maximální payload: ~1100 B

---

## 13. Ukázka přenosu

| Čas | Odesílatel | Flag    | seq | ack | Poznámka                       |
| --- | ---------- | ------- | --- | --- | ------------------------------ |
| t0  | Klient     | SYN     | 0   | 0   | Zahájení spojení               |
| t1  | Server     | SYN+ACK | 0   | 1   | Potvrzení klienta              |
| t2  | Klient     | ACK     | 1   | 1   | Dokončení handshake            |
| t3  | Klient     | META    | 1   | 1   | Metadata (file_size, segments) |
| t4  | Server     | ACK     | -   | 2   | Potvrzení Metadat              |
| t5  | Klient     | DATA    | 2   | 1   | Segment 1                      |
| t6  | Klient     | DATA    | 3   | 1   | Segment 2                      |
| t7  | Server     | ACK     | -   | 3   | Potvrzen segment 1             |
| t8  | Klient     | DATA    | 4   | 1   | Segment 3                      |
| t9  | Server     | ACK     | -   | 4   | Potvrzen segment 2             |
| t10 | Server     | ACK     | -   | 5   | Potvrzen segment 3             |
| t11 | Klient     | FIN     | 5   | 5   | Konec přenosu                  |
| t12 | Server     | ACK     | -   | 6   | Potvrzení FIN                  |
| t13 | Server     | FIN     | 0   | 6   | Ukončení ze strany serveru     |
| t14 | Klient     | ACK     | 6   | 1   | Spojení ukončeno               |
