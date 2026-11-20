# Stato del progetto Shielded Bitcoin

## 1. Cosa è già fissato e cosa manca

Il paper contiene una specifica logica piuttosto dettagliata, ma non definisce completamente una suite crittografica concreta. È quindi necessario distinguere tra le scelte già indicate dal paper e le decisioni tecniche ancora da prendere.

### 1.1 Scelte già presenti nel paper

| Elemento | Scelta del paper |
|---|---|
| Gerarchia delle chiavi | HKDF-SHA256 con label domain-separated |
| ZK proof system | Groth16 (profilo Appendix A) |
| Publication carrier del profilo A | Un singolo output OP_RETURN |
| Serializzazione | Encoding canonico definito in Appendix A.5 |
| Anchor window raccomandata | W = 100, K_min = 1 |
| Wallet seed raccomandato | 32 byte casuali |
| Diversifier | 11 byte |

### 1.2 Scelte ancora da definire concretamente

| Elemento | Decisione necessaria |
|---|---|
| `H_body` | Definire la funzione hash concreta |
| `H_leaf` | Definire hash e parametri per il Merkle tree |
| Proof backend | Scegliere curva e backend Groth16 |
| Circuit implementation | Definire gadget e aritmetizzazione |
| AEAD | Scegliere una costruzione concreta compatibile con i requisiti |
| KDF delle cifrature | Definire una key schedule concreta |
| Nullifier derivation | Istanziare concretamente la funzione richiesta |
| Encoding | Definire parametri e convenzioni complete per la suite scelta |

## 2. Regole di codifica

| Elemento | Regola di codifica |
|---|---|
| Interi a larghezza fissa | Little-endian |
| Conteggi dei vettori | Bitcoin-style CompactSize canonico |
| Elementi del campo finito | Codifica canonica a larghezza fissa |
| Punti di curva | Un'unica codifica compressa canonica |
| Ciphertext | Lunghezza fissa definita dal formato |
| Vettori | Ordine crescente degli indici |

## 3. Piano di lavoro

| Fase | Attività | Obiettivo |
|---|---|---|
| 1 | Data model e serializzazione | Definire note, envelope, leaf e stato |
| 2 | Key derivation | Implementare seed, chiavi e diversifier |
| 3 | Note encryption | Implementare recipient e sender-recovery channel |
| 4 | Merkle tree | Costruire append, root e Merkle witness |
| 5 | Nullifier | Implementare derivazione e controllo anti-double-spend |
| 6 | Transfer construction | Costruire body e `h_body` |
| 7 | Circuit | Tradurre gli otto blocchi di Appendix B in vincoli |
| 8 | Groth16 | Implementare setup, proving e verification |
| 9 | Replay engine | Implementare acceptance pipeline e aggiornamenti atomici |
| 10 | Wallet recovery | Decifrare e riconoscere le note |

## 4. Fase 1 — Data model e serializzazione

### 4.1 Componenti e stato aggiornato

| Componente | Stato / attività |
|---|---|
| `Note` | Modello logico implementato |
| `TransferEnvelope` (`models/envelope.py`) | Modello e validazione strutturale implementati; validazione dei punti ancora da finalizzare |
| `NoteLeaf` | Modello logico implementato |
| `ReplayState` | Modello logico implementato |
| `CanonicalSerializer` (`serialization/encoder.py`) | Implementato e sottoposto a test di round-trip e CompactSize |
| `CanonicalParser` (`serialization/decoder.py`) | Implementato: canonicalità strutturale, conteggi, troncamenti, trailing bytes; punti/field non ancora validati crittograficamente |
| `models/header.py` | Aggiunto localmente, header v1 di 6 byte |

### 4.2 Struttura del progetto

```text
shielded_bitcoin/
├── models/
│   ├── note.py
│   ├── header.py
│   ├── envelope.py
│   ├── leaf.py
│   └── replay_state.py
├── serialization/
│   ├── encoder.py
│   └── decoder.py
├── tests/
│   ├── test_models.py
│   ├── test_envelope.py
│   ├── test_header.py
│   ├── test_replay_state.py
│   └── test_serialization.py
└── main.py
```

### 4.3 Obiettivo della fase

Completare i modelli logici e implementare il serializzatore e il parser canonici. La fase si considera completata quando i modelli rispettano il formato definito e i test verificano la correttezza della serializzazione e della deserializzazione, inclusi i casi non validi e i vincoli di canonicalità.

**Stato:** parte strutturale completata, secondo i test locali riferiti dall'utente (tutti superati). La piena canonicalità dei punti e degli elementi di campo dipende dalla scelta della suite; non dichiarare questa porzione completata.

### 4.4 Decisioni BitPolito già adottate

- Header v1: `b"btc\x01\x00\x01"` = `btc` (3 byte) + version `uint16 little-endian` (2 byte) + type `0x01` (1 byte). La struttura dei sottocampi su 6 byte è una **scelta di profilo BitPolito**, non una suddivisione dei byte espressamente imposta dal paper.
- Trasferimenti con **N >= 1, M >= 1**; arità strutturalmente variabili; nessun massimo N/M ancora fissato. È una **scelta BitPolito**, non un limite universale del paper.
- Dimensioni provvisorie ricavate dalla stima 2→2 dell'Appendix A.4: nullifier 32 B, `pk_eph` 32 B, `ct_note` 67 B, `ct_out` `64M+16` B, proof 192 B. Il formato dovrà essere riesaminato rispetto alle primitive definitive.

---

## 5. Decisioni crittografiche ancora aperte

**Stato al 20 novembre 2026:** la struttura dei dati della Fase 1 è implementata e testata, ma non abbiamo ancora scelto tutte le primitive necessarie a validare crittograficamente gli Envelope. La Fase 2 (key derivation) è iniziata su un branch separato, ma dipende soprattutto dalla scelta della curva e della codifica delle chiavi.

**Nessuna delle tre alternative esaminate sotto è stata approvata da BitPolito.** Le caratteristiche attribuite alla PoC di bitsagarob derivano da `PROFILE.md` e dai file sorgente del suo repository; non significano che quella PoC sia sicura o perfettamente conforme al paper.

### 5.1 Prima di confrontare le opzioni: cinque termini essenziali

- **Curva delle note:** la curva ellittica usata per generare gli indirizzi di ricezione, le chiavi pubbliche effimere (`pk_eph`) e il segreto condiviso ECDH usato per cifrare le note. Non è necessariamente la curva usata per Groth16.
- **Curva di Groth16:** la curva *pairing-friendly* usata dal sistema di prove zero-knowledge. Determina, fra l'altro, la dimensione della prova e il **campo del circuito**, cioè l'insieme di numeri sui quali vengono eseguite direttamente le operazioni del circuito.
- **Campo nativo / non nativo:** quando le coordinate della curva delle note appartengono al campo del circuito, le operazioni sono più semplici da verificare. Altrimenti occorre rappresentare ogni numero con più parti e simulare le operazioni modulari, aumentando la complessità.
- **Gadget:** implementazione di un'operazione (per esempio SHA-256, moltiplicazione di un punto o cifratura) tramite vincoli del circuito Groth16. Una funzione veloce in Python non è necessariamente veloce *dentro* una prova.
- **Codifica canonica:** un unico modo valido per convertire un punto o un numero in byte. Verificare che una chiave occupi 32 byte **non basta**: occorre anche verificare che rappresenti un punto valido nel sottogruppo richiesto.

### 5.2 Tre architetture possibili per le curve

Il paper non impone la curva delle note né la curva di Groth16. Le tre combinazioni che intendiamo valutare sono:

| Alternativa | Come funziona e perché considerarla | Limiti e conseguenze concrete |
|---|---|---|
| **A — Jubjub + BLS12-381** | **Jubjub** gestisce indirizzi, ECDH e `pk_eph`; **BLS12-381** gestisce Groth16. Il campo delle coordinate di Jubjub coincide con il campo del circuito: i gadget sui punti risultano relativamente naturali. È una combinazione con precedente in Zcash Sapling. | Richiede implementazioni affidabili di Jubjub e dei gadget, disponibili più facilmente in ecosistemi nativi che in puro Python. Le chiavi pubbliche compresse possono occupare **32 byte** e le prove Groth16 compresse **192 byte**: sono compatibili con le dimensioni del nostro modello attuale, ma non rendono automaticamente corretti gli altri campi. |
| **B — Baby Jubjub + BN254** | **Baby Jubjub** gestisce le chiavi; **BN254** gestisce Groth16. Anche qui il campo delle coordinate della curva delle note coincide con quello del circuito. L'ecosistema Circom mette a disposizione componenti utili alla sperimentazione. | Il pairing BN254 offre un margine di sicurezza inferiore a quello generalmente attribuito a BLS12-381 (circa **100 bit**, come stima indicativa, non garanzia). Una chiave compressa può occupare **32 byte**; una prova Groth16 compressa circa **128 byte**, quindi il nostro campo `proof` da 192 byte andrebbe rivisto. |
| **C — secp256k1 + BLS12-381** | **secp256k1** è la curva usata da Bitcoin per le chiavi e le firme; **BLS12-381** resta la curva di Groth16. La familiarità con Bitcoin e le librerie ECC diffuse sono i vantaggi principali. | Il campo di secp256k1 è diverso da quello del circuito BLS12-381: verificare ECDH e moltiplicazioni di punti richiede aritmetica **non nativa**, normalmente più complessa e costosa. Una chiave compressa SEC1 misura **33 byte**; un formato x-only da 32 byte richiederebbe convenzioni aggiuntive. La prova BLS12-381 compressa resta **192 byte**. |

**Sicurezza:** secp256k1 e Jubjub sono gruppi progettati per un livello di sicurezza dell'ordine di 128 bit nelle rispettive applicazioni, ma la sicurezza dell'intero sistema dipende anche dalla curva della prova, dalle primitive cifranti, dai gadget, dalla validazione dei punti e dal setup. Non è corretto attribuire “128 bit di sicurezza” al protocollo completo soltanto perché si è scelta una curva.

**Prestazioni:** A e B evitano una parte dell'aritmetica non nativa richiesta da C. Non abbiamo benchmark equivalenti delle tre alternative sullo stesso circuito: quindi **non riportiamo tempi o numeri di vincoli inventati per B e C**. In tutti i casi, HKDF-SHA256 e l'algoritmo di cifratura da verificare nel circuito potrebbero dominare il costo della prova.

**Python:** per tutte e tre le alternative possiamo continuare a sviluppare in Python modelli, wallet, serializzazione, replay e test. Per i gadget e Groth16 è però necessario verificare se usare un backend nativo richiamato da Python. L'esistenza di librerie Python per la semplice moltiplicazione su curva non implica la disponibilità di un prover Groth16 completo.

**Valutazione provvisoria:** A è la candidata più coerente con il formato attuale e con la PoC studiata; B è l'alternativa pratica più interessante; C richiede una motivazione specifica per giustificare i costi dell'aritmetica non nativa. **Non è ancora una decisione.**

### 5.3 Cosa ha scelto davvero la PoC `bitsagarob/shielded-btc-probe`

La PoC è scritta in **Rust** e utilizza **arkworks**. Ho confrontato le dichiarazioni di [PROFILE.md](https://github.com/bitsagarob/shielded-btc-probe/blob/master/PROFILE.md) con i file `src/keys.rs`, `src/note.rs`, `src/envelope.rs`, `src/circuit.rs`, `src/prover.rs`, `src/poseidon.rs` e `tests/gadget_costs.rs`.

| Componente | Scelta della PoC | Perché è importante per noi |
|---|---|---|
| **Curve e prova** | Jubjub per chiavi/ECDH; BLS12-381 per Groth16; prova compressa da **192 byte**. | Dimostra una possibile integrazione concreta dell'**alternativa A**, ma in Rust, non in Python. |
| **Hash Poseidon** | Utilizza Poseidon per varie funzioni: note, nullifier, foglie, `H_body` e operazioni nel circuito. Configurazione dichiarata: larghezza 3, rate 2, 8 round completi, 57 parziali, esponente 5. | Poseidon consente gadget aritmetici più agevoli di molte primitive byte-oriented; i **parametri e i tag** devono comunque essere definiti e verificati. |
| **Gerarchia delle chiavi** | HKDF-SHA256 in alcuni passaggi esterni al circuito; sostituzione con **Poseidon** per derivare `sk_nf`, `vk_in` e `sk_view` nel circuito. | **Divergenza dal paper:** la gerarchia richiede HKDF-SHA256. Non possiamo copiare la soluzione della PoC mantenendo una dichiarazione di piena conformità. |
| **Scalari** | Scalar Jubjub codificati su **32 byte little-endian**; riduzione modulare per alcune derivazioni, estrazione dei 250 bit bassi per altre. | Il branch del nostro collega usa attualmente **32 byte big-endian** e ordine secp256k1 provvisorio: sono convenzioni da unificare prima dell'integrazione. |
| **`DiversifyHash`** | Ricerca deterministica di un punto Jubjub a partire dal diversifier, con Poseidon, tentativi successivi e trattamento del cofattore. | È **una scelta della PoC**, non l'algoritmo imposto dal paper. Occorrono specifica, controlli sul sottogruppo e test del gadget. |
| **Cifratura della nota (`ct_note`)** | Due elementi cifrati più un tag, ottenuti con una costruzione stream + MAC su Poseidon: **96 byte**. | Il nostro modello usa **67 byte**. La costruzione della PoC non dimostra automaticamente tutte le proprietà di *key commitment*, *key privacy* e robustezza richieste dal paper. |
| **Recupero del mittente (`ct_out`)** | ChaCha20-Poly1305 con chiave/nonce derivati tramite HKDF; dimensione **64M + 16 byte**. | La misura coincide col nostro modello, ma le proprietà di sicurezza richieste vanno valutate nel contesto della costruzione completa. |
| **Arità** | Circuito a **2 input e 2 output**, con convenzioni per input fittizi. | Il nostro modello è volutamente variabile: non vogliamo ereditare automaticamente il limite 2→2. |
| **Header** | Magic `sbp`, versione 1 byte, tipo 1 byte, byte riservato 1 byte. | **Non interoperabile** col nostro header `btc` + versione uint16 LE + tipo. La differenza è intenzionale nella PoC. |
| **Setup Groth16** | Generato da un **seed fisso e pubblico**. | **Insecure by design:** chiunque conosce il materiale che permette di falsificare prove. Da non utilizzare per custodire valore. |
| **Estensioni** | Mint e peg-out gestiti tramite componenti aggiuntivi e operatore. | Sono estensioni fuori dal transfer base oggetto del nostro piano iniziale. |

#### Prestazioni riportate dall'autore della PoC

Per il circuito **2→2** attuale, su server x86-64 con build Rust `release`:

| Misura | Risultato riportato |
|---|---:|
| Vincoli R1CS (operazioni elementari verificate dal circuito) | **96.039** |
| Generazione della prova con 1 thread | **9,5–9,8 s** |
| Generazione della prova con 16 thread | **1,7–1,9 s** |
| Verifica della prova | **2,5 ms** |
| Dimensione della proving key | **56 MB** |
| Dimensione Envelope 2→2 senza payout | **669 byte** |
| Dimensione Envelope 2→2 illustrata nel paper | **610 byte** |

I **59 byte** di differenza fra gli Envelope derivano, secondo `PROFILE.md`, da due ciphertext note più lunghi (29 byte in più ciascuno) e da 1 byte aggiuntivo per un campo payout.

Il benchmark misura **la PoC nella forma descritta**, non una versione pienamente conforme al paper né una soluzione Python.

L'autore riporta anche queste **stime**, ricavate da gadget e da estrapolazioni, che non vanno scambiate con prove end-to-end misurate:

- Sostituire con **tre HKDF-SHA256 in-circuit** le derivazioni oggi eseguite con Poseidon: circa **792.262 vincoli totali** (~8,2 volte la baseline), con proving stimato ~16 secondi su 16 thread.
- Sostituire la cifratura Poseidon delle note con una costruzione byte-oriented esemplificativa: circa **736.815 vincoli totali** (~7,7 volte la baseline), **senza** garantire per questo che la costruzione soddisfi tutti i requisiti AEAD del paper.
- Applicare insieme le principali modifiche stimate dall'autore: circa **1,89 milioni di vincoli**, proving key ~**1,1 GB** e ~**37 secondi** stimati su 16 thread.

**Lezione pratica:** riprodurre la logica del paper nel circuito può essere molto più costoso di implementare le stesse primitive fuori dal circuito. La PoC è utile per individuare i punti critici, **non** per scegliere una scorciatoia crittografica senza una giustificazione formale.

### 5.4 Tutte le decisioni ancora da prendere — spiegate in modo operativo

Questa tabella elenca ciò che serve decidere, senza ripetere l'intero confronto fra curve.

| Decisione | Che cosa significa concretamente | Indicazione e stato |
|---|---|---|
| **Curva delle note + curva Groth16** | Quali gruppi usiamo per chiavi/ECDH e per le prove; la scelta determina i campi del circuito e il formato dei punti. | **Da decidere per primi.** Confrontare A, B e C; A è prima candidata. |
| **Formato di chiavi e proof** | Quanti byte occupano, come sono codificate e quali byte il parser deve rifiutare. | **Fase 1 aperta.** Oggi assumiamo 32 B per `pk_eph` e 192 B per proof. Servono decodifica canonica e controlli di sottogruppo. |
| **`ScalarFromBytes` e `BytesToField`** | Come una sequenza di byte diventa uno scalare/elemento di campo; scegliere endianness e regole per valori fuori intervallo/zero. | **Fase 2 aperta.** Native Python e circuito devono ottenere esattamente gli stessi risultati. |
| **HKDF wallet** | Come deriviamo `sk_master`, `sk_spend`, `sk_nf`, `vk_in`, `vk_out`, `sk_view` a partire dal seed/altre chiavi. | **HKDF-SHA256 fissato dal paper.** Definire salt e label esatte; non sostituirlo con Poseidon senza cambiare la specifica. |
| **`DiversifyHash`** | Come il diversifier di 11 byte viene trasformato in un punto di curva `G_d` valido. | **Aperto.** Scegliere algoritmo e regole per punti invalidi e sottogruppo. |
| **`H_body`** | Hash dei byte canonici dell'Envelope (senza proof), usato per legare la prova a quel trasferimento. | **Aperto.** SHA-256 oppure una costruzione circuit-friendly; definire esattamente byte e domain separation. |
| **`H_leaf` e Merkle hash** | Come otteniamo l'identificatore di una nota e come combiniamo i nodi dell'albero. | **Aperto.** Poseidon/Poseidon2 sono candidati; servono parametri, profondità dell'albero, nodi vuoti e codifica degli input. |
| **`H_rho`, `H_eph` e nullifier** | Come deriviamo casualità di nota, chiave effimera e identificatore pubblico di spesa senza rivelare l'autorità di spesa. | **Aperto.** Richiedono domain separation e, per il nullifier, proprietà di PRF/binding; non basta chiamare qualunque hash. |
| **Recipient encryption (`ct_note`)** | Come cifriamo `(v,d,r_seed)` usando ECDH, con verifica della stessa cifratura nel circuito. | **Critico.** Deve soddisfare anche key privacy, key commitment e note-opening robustness. Non scegliere automaticamente AES-GCM o ChaCha20-Poly1305 “semplici”. |
| **Sender recovery (`ct_out`)** | Come il mittente recupera le note inviate tramite `vk_out`, senza rivelare la sua identità. | **Aperto.** Definire KDF, nonce, dati associati e AEAD con le proprietà richieste; controllare la dimensione `64M+16`. |
| **Arità supportate dal circuito** | Quali combinazioni N/M il prover può dimostrare; ogni forma deve avere una corrispondente interfaccia di verifica. | **Aperto.** I modelli Python sono variabili, ma Groth16 non accetta automaticamente tutte le arità possibili. |
| **Setup e limiti operativi** | Come generiamo in sicurezza proving/verifying key e quali payload/costi massimi accettiamo. | **Aperto.** Mai usare seed di setup pubblico in produzione; definire anche limiti di risorse e policy carrier. |

### 5.5 Ordine consigliato di lavoro

1. **Decidere l'architettura delle curve e il backend utilizzabile dal progetto Python.** È la scelta con più dipendenze.
2. **Chiudere la canonicalità della Fase 1:** codifica e validazione dei punti, formato delle proof, elementi di campo, test negativi e vettori di test.
3. **Finalizzare la Fase 2:** sostituire i placeholder del collega, definire scalar encoding, HKDF e `DiversifyHash`, mantenendo fedeltà al paper.
4. **Progettare gli hash e le cifrature con il circuito in mente:** prima di implementare la Fase 3, verificare sicurezza richiesta e costo dei gadget.
5. **Definire le arità Groth16 e il setup:** prima di dichiarare pronto un protocollo interoperabile.

### 5.6 Fonti da conservare

- Paper *Shielded Bitcoin: Private Transfers on the Bitcoin L1*: Sezioni 5–6, 9, 12–15, 17, 22.1; Appendici A e B.
- [bitsagarob — PROFILE.md](https://github.com/bitsagarob/shielded-btc-probe/blob/master/PROFILE.md): scelte e divergenze dichiarate rispetto al paper.
- [bitsagarob — RUNS.md](https://github.com/bitsagarob/shielded-btc-probe/blob/master/RUNS.md): prove di esecuzione descritte dall'autore.
- [bitsagarob — keys.rs](https://github.com/bitsagarob/shielded-btc-probe/blob/master/src/keys.rs), [note.rs](https://github.com/bitsagarob/shielded-btc-probe/blob/master/src/note.rs), [circuit.rs](https://github.com/bitsagarob/shielded-btc-probe/blob/master/src/circuit.rs), [prover.rs](https://github.com/bitsagarob/shielded-btc-probe/blob/master/src/prover.rs), [poseidon.rs](https://github.com/bitsagarob/shielded-btc-probe/blob/master/src/poseidon.rs).
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf): Jubjub / Sapling.
- [EIP-2494](https://eips.ethereum.org/EIPS/eip-2494): Baby Jubjub.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): HKDF.
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380): hash-to-curve.
- [RFC 9771](https://www.rfc-editor.org/rfc/rfc9771): proprietà di commitment negli AEAD.

**Conclusione:** la priorità non è copiare una primitive della PoC, ma decidere una suite completa e documentabile in cui byte, chiavi, hash, cifrature e circuito implementino **la stessa relazione**. Finché non vengono scelte e verificate queste convenzioni, la Fase 1 è conclusa solo strutturalmente e la Fase 2 rimane parziale.
