# Stato del progetto Shielded Bitcoin

## 1. Cosa è già fissato e cosa manca

Il paper contiene una specifica logica piuttosto dettagliata, ma non
definisce completamente una suite crittografica concreta. È quindi
necessario distinguere tra le scelte già indicate dal paper e le
decisioni tecniche ancora da prendere.

### 1.1 Scelte già presenti nel paper

  Elemento                            Scelta del paper
  ----------------------------------- --------------------------------------------
  Gerarchia delle chiavi              HKDF-SHA256 con label domain-separated
  ZK proof system                     Groth16
  Publication carrier del profilo A   Un singolo output OP_RETURN
  Serializzazione                     Encoding canonico definito in Appendix A.5
  Anchor window raccomandata          W = 100, K_min = 1
  Wallet seed raccomandato            32 byte casuali
  Diversifier                         11 byte

### 1.2 Scelte ancora da definire concretamente

  -----------------------------------------------------------------------
  Elemento                            Decisione necessaria
  ----------------------------------- -----------------------------------
  `H_body`                            Definire la funzione hash concreta

  `H_leaf`                            Definire hash e parametri per il
                                      Merkle tree

  Proof backend                       Scegliere curva e backend Groth16

  Circuit implementation              Definire gadget e aritmetizzazione

  AEAD                                Scegliere una costruzione concreta
                                      compatibile con i requisiti

  KDF delle cifrature                 Definire una key schedule concreta

  Nullifier derivation                Istanziare concretamente la
                                      funzione richiesta

  Encoding                            Definire parametri e convenzioni
                                      complete per la suite scelta
  -----------------------------------------------------------------------

## 2. Regole di codifica

  Elemento                    Regola di codifica
  --------------------------- --------------------------------------
  Interi a larghezza fissa    Little-endian
  Conteggi dei vettori        Bitcoin-style CompactSize canonico
  Elementi del campo finito   Codifica canonica a larghezza fissa
  Punti di curva              Un'unica codifica compressa canonica
  Ciphertext                  Lunghezza fissa definita dal formato
  Vettori                     Ordine crescente degli indici

## 3. Piano di lavoro

  ------------------------------------------------------------------------
                          Fase Attività              Obiettivo
  ---------------------------- --------------------- ---------------------
                             1 Data model e          Definire note,
                               serializzazione       envelope, leaf e
                                                     stato

                             2 Key derivation        Implementare seed,
                                                     chiavi e diversifier

                             3 Note encryption       Implementare
                                                     recipient e
                                                     sender-recovery
                                                     channel

                             4 Merkle tree           Costruire append,
                                                     root e Merkle witness

                             5 Nullifier             Implementare
                                                     derivazione e
                                                     controllo
                                                     anti-double-spend

                             6 Transfer construction Costruire body e
                                                     `h_body`

                             7 Circuit               Tradurre gli otto
                                                     blocchi di Appendix B
                                                     in vincoli

                             8 Groth16               Implementare setup,
                                                     proving e
                                                     verification

                             9 Replay engine         Implementare
                                                     acceptance pipeline e
                                                     aggiornamenti atomici

                            10 Wallet recovery       Decifrare e
                                                     riconoscere le note
  ------------------------------------------------------------------------

## 4. Fase 1 --- Data model e serializzazione

### 4.1 Componenti

  Componente              Stato / attività
  ----------------------- ---------------------------
  `Note`                  Modello logico
  `TransferEnvelope`      Modello logico
  `NoteLeaf`              Modello logico
  `ReplayState`           Modello logico
  `CanonicalSerializer`   Da implementare e testare
  `CanonicalParser`       Da implementare e testare

### 4.2 Struttura del progetto

``` text
shielded_bitcoin/
│
├── models/
│   ├── note.py
│   ├── envelope.py
│   ├── leaf.py
│   └── replay_state.py
│
├── serialization/
│   ├── encoder.py
│   └── decoder.py
│
├── tests/
│   ├── test_models.py
│   └── test_serialization.py
│
└── main.py
```

### 4.3 Obiettivo della fase

Completare i modelli logici e implementare il serializzatore e il parser
canonici. La fase si considera completata quando i modelli rispettano il
formato definito e i test verificano la correttezza della
serializzazione e della deserializzazione, inclusi i casi non validi e i
vincoli di canonicalità.
