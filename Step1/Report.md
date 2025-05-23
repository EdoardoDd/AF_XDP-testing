# Report Step1

AF_XDP è un'interfaccia socket che permette di raggiungere prestazioni di rete vicine a quelle delle soluzioni di kernel bypass tradizionali, mantenendo al contempo l'integrazione con il kernel Linux. Questa tecnologia consente di elaborare pacchetti di rete con throughput elevato, latenze ridotte e un utilizzo efficiente della CPU.

Il seguente progetto si propone come un'implementazione del meccanismo ping-pong simile ad iperf ma con capacità di kernel bypass per ottenere misurazioni delle prestazioni.

Componenti principali:
- **XDP Sender**: Un'applicazione per l'invio di pacchetti di test con analisi delle prestazioni di rete    
- **XDP Receiver**: Un'applicazione per la ricezione e risposta dei pacchetti 

Nello sviluppo dell'applicazione è stata utilizzata la libreria common/, la quale implementa funzioni utili per configurare l'ambiente XDP, gestire l'interazione con l'interfaccia AF_XDP e manipolare i pacchetti.
<br/>

## Gestione della memoria in AF_XDP
AF_XDP basa la sua efficienza su un modello di gestione della memoria unico che riduce drasticamente le copie e le transizioni tra kernel e spazio utente. Il componente fondamentale è l'UMEM (User Memory), un'area di memoria contigua allocata dall'applicazione e condivisa con il kernel. Questa memoria viene suddivisa in frame di dimensione fissa che fungono da contenitori per i pacchetti di rete.

Il trasferimento dei pacchetti avviene attraverso quattro ring di descrittori che operano in modalità lock-free: i ring di ricezione (**RX**) e trasmissione (**TX**) contengono descrittori che puntano ai frame dell'UMEM, mentre i ring di riempimento (**FILL**) e completamento (**COMPLETION**) gestiscono il trasferimento di proprietà dei frame tra applicazione e kernel. Questa architettura permette l'implementazione di un modello a produttore-consumatore efficiente, dove il driver di rete può scrivere direttamente nella memoria utente (in modalità **zero-copy**) eliminando copie non necessarie.

La corretta configurazione dell'UMEM e la gestione efficiente dei frame sono cruciali per le prestazioni: dimensioni inadeguate del buffer o scarse strategie di riciclo dei frame possono limitare significativamente il throughput e aumentare la latenza. Il sistema supporta due modalità principali: **copy-mode**, compatibile con tutti i driver che supportano XDP, e **zero-copy**, che offre prestazioni massime ma richiede supporto specifico dal driver.

<br/>


## Architettura e Implementazione
Utilizzando AF_XDP, abbiamo implementato una soluzione completamente user-space che gestisce direttamente l'elaborazione dei pacchetti, bypassando il network stack del kernel per ottenere prestazioni ottimali mantenendo al contempo la flessibilità e il controllo tipici delle applicazioni utente.

#### XDP Sender
1. **Inizializzazione**:
   - Alloca un'area di memoria condivisa (UMEM) divisa in frame di dimensione fissa
   - Configura un socket AF_XDP associato all'interfaccia di rete
   - Inizializza quattro ring di descrittori: TX, COMPLETION, RX e FILL

2. **Ciclo di trasmissione**:
   - Alloca frame UMEM dalla pool di frame liberi
   - Assembla pacchetti con timestamp di invio e payload configurabile
   - Inserisce descrittori nel ring TX con riferimenti ai frame
   - Invia pacchetti in batch per massimizzare l'efficienza
   - Monitora i completamenti tramite il ring COMPLETION
   - Ricicla i frame completati riportandoli nella pool di frame liberi
<br/>


##### Sender - Gestione della memoria e interazione con i ring
1. **Ciclo di trasmissione (TX)** - Il Sender segue i seguenti passaggi:
    - Richiesta di un frame libero dall'UMEM utilizzando la funzione `xsk_alloc_umem_frame()`, che preleva un indirizzo dalla pool di frame disponibili.
    - Il contenuto del pacchetto viene scritto direttamente nella memoria UMEM utilizzando l'indirizzo allocato, includendo un timestamp e un numero di sequenza univoco.
    - Il Sender, attraverso `xsk_ring_prod__reserve()` ottiene uno slot nel ring TX, dove inserisce un descrittore contenente l'indirizzo del frame e la lunghezza del pacchetto.
    - Con `xsk_ring_prod__submit()`, il descrittore viene sottomesso e reso visibile al kernel per la trasmissione.
    - Il pacchetto inviato viene registrato nella struttura `ping_tracker` per il successivo calcolo del RTT quando arriverà la risposta.
Questo approccio elimina copie di memoria non necessarie, poiché il pacchetto viene costruito direttamente nell'area UMEM che verrà acceduta dal driver di rete.

2. **Ciclo di ricezione (RX)** - Il Sender deve anche riceve e processare le richieste "pong":
    - Prima di tentare qualsiasi ricezione, il Sender rifornisce il ring FILL tramite `xsk_refill_fill_queue()`, assicurando che ci siano sempre frame disponibili per i pacchetti in arrivo.
    - Il Sender controlla nel ring RX chiamando `xsk_ring_cons__peek()` per verificare se sono arrivati nuovi pacchetti.
    - Per ogni pacchetto il Sender accede direttamente all'UMEM usando l'indirizzo fornito dal  descrittore. Viene estratto il numero di sequenza dal pacchetto "pong" ricevuto, utilizzato per trovare la corrispondente voce nel `ping_tracker`.
    - Dopo aver calcolato il RTT, con `xsk_ring_cons__release()`, i descrittori vengono marcati come processati.

3. **Gestione della Completition Queue**
    - La funzione `complete_tx()` esamina il ring COMPLETION per identificare i frame il cui invio è stato completato. 
    - I frame completati vengono restituiti alla pool di frame liberi tramite `xsk_free_umem_frame()`, rendendoli disponibili per future trasmissioni o ricezioni.
    - Il contatore `outstanding_tx` viene decrementato per tenere traccia del numero di trasmissioni pendenti.


#### XDP Receiver
1. **Inizializzazione**:
   - Configura una struttura UMEM analoga a quella del Sender
   - Rifornisce il ring FILL con frame vuoti per la ricezione
   - Predispone strutture dati per l'analisi delle prestazioni

2. **Ciclo di ricezione e risposta**:
   - Controlla continuamente il ring RX per nuovi pacchetti
   - Estrae timestamp dai pacchetti ricevuti
   <!-- - Calcola metriche di prestazione (latenza, jitter) -->
   - In modalità echo, scambia gli indirizzi sorgente/destinazione
   - Prepara pacchetti di risposta nel ring TX

3. **Ottimizzazione della memoria**:
   - Mantiene un buffer circolare per i frame in uso
   - Implementa un meccanismo di rifornimento proattivo del ring FILL
   - Utilizza tecniche di batching per l'elaborazione dei pacchetti
   - Minimizza le transizioni tra kernel e spazio utente

##### Receiver - Gestione della memoria e interazione con i ring
1. **Ciclo di ricezione (RX)** - La ricezione dei pacchetti "ping" segue i seguenti passaggi:
   - Il Receiver assicura che il ring FILL sia costantemente rifornito tramite `xsk_refill_fill_queue()`, chiamata sia all'inizio che alla fine di ogni ciclo di elaborazione per garantire la disponibilità di buffer per i pacchetti in arrivo.
   - Attraverso `poll()` con timeout 1 secondo, il Receiver monitora l'arrivo di nuovi pacchetti in modo efficiente.
    - Tramite `xsk_ring_cons__peek()`, il Receiver verifica la presenza di pacchetti nel ring RX.
    - Per ogni pacchetto ricevuto, il Receiver utilizza `xsk_umem__get_data()` per accedere direttamente ai dati nella memoria UMEM senza copie intermedie.
    - Viene validata l'integrità del pacchetto e viene estratto il numero di sequenza.
2. **Ciclo di trasmissione (TX)** - Dopo aver ricevuto il ping, il Receiver genera e invia una risposta pong:
   - Creazione della risposta: Viene utilizzata `create_response_packet()`che crea automaticamente un pacchetto di risposta invertendo indirizzi MAC, IP e porte UDP, mantenendo tutti gli altri campi invariati.
   - Il payload "PING" viene sostituito con "PONG", preservando eventuali dati aggiuntivi come il numero di sequenza per permettere la correlazione lato sender.
   - L'invio avviene tramite la funzione `xsk_send_packet()`, la quale gestisce internamente:
      - L'allocazione di un nuovo frame UMEM tramite `xsk_alloc_umem_frame()`
      - La copia dei dati nel frame UMEM allocato
      - La riserva di uno slot nel ring TX tramite `xsk_ring_prod__reserve()`
      - La configurazione del descrittore TX con indirizzo e lunghezza del frame
      - La sottomissione tramite `xsk_ring_prod__submit()` che rende il descrittore visibile al kernel
3. **Gestione della Completion Queue**:
   - Durante il processing dei pacchetti, ogni 8 pacchetti elaborati viene chiamata `complete_tx()` che esamina il ring COMPLETION per identificare i frame il cui invio è stato completato dal kernel.
   - La funzione `complete_tx()` utilizza `xsk_ring_cons__peek()` per ottenere fino a 64 completion alla volta, ottimizzando le performance tramite elaborazione batch.
   - I frame completati vengono restituiti alla pool di frame liberi tramite `xsk_free_umem_frame()`
   - Il contatore `outstanding_tx` viene decrementato per tenere traccia del numero di trasmissioni pendenti, permettendo di evitare l'esaurimento dei buffer TX e di ottimizzare la frequenza delle chiamate a `sendto()`.

- Il receiver mantiene contatori per PING ricevuti, PONG inviati ed errori, con report periodici ogni 5 secondi che includono anche lo stato della memoria UMEM.
- Al termine o in caso di segnali di interruzione, viene eseguito il cleanup completo di socket, UMEM e buffer, garantendo la liberazione di tutte le risorse allocate.

Questa architettura permette al receiver di gestire efficacemente il traffico PING-PONG con latenze minime e throughput elevato, sfruttando appieno le capabilities di AF_XDP per il bypass del network stack del kernel.

## Test e Prestazioni
Il componente Sender si occupa anche dell'analisi delle prestazioni, monitorando throughput, packet loss e latenza. 
- Modalità AF_XDP: Zero-copy
- Dimensione pacchetto: 64 bytes
<br/>

**Tabella 1: Throughput e Packet Loss**
| Rate Target (pps) | TX Effettivo (pps) | RX Effettivo (pps) | Packet Loss (%) | Throughput TX (Mbps) | Throughput RX (Mbps) |
|-------------------|--------------------|--------------------|-----------------|---------------------|---------------------|
| 1,000             | 999.95             | 999.95             | 0.00%           | 0.51                | 0.51                |
| 3,000             | 2,998.44           | 2,997.02           | 0.05%           | 1.54                | 1.53                |
| 5,000             | 4,994.10           | 4,994.10           | 0.00%           | 2.56                | 2.56                |
| 7,000             | 6,989.75           | 5,808.24           | 16.90%          | 3.58                | 2.97                |
| 10,000            | 9,985.35           | 5,808.24           | 41.83%          | 5.11                | 2.97                |
| 13,000            | 12,978.13          | 5,808.25           | 55.25%          | 6.64                | 2.97                |
| 17,000            | 16,972.26          | 5,808.24           | 65.78%          | 8.69                | 2.97                |
| 20,000            | 19,966.33          | 5,802.53           | 70.94%          | 10.22               | 2.97                |

**Tabella 2: Analisi Latenza**
| Rate (pps) | Min (ms) | Avg (ms) | Max (ms) | Jitter (ms) | P50 (ms) | P90 (ms) | P99 (ms) |
|------------|----------|----------|----------|-------------|----------|----------|----------|
| 1,000      | 0.099    | 0.347    | 0.465    | 0.040       | 0.355    | 0.383    | 0.410    |
| 3,000      | 0.043    | 0.228    | 0.567    | 0.110       | 0.225    | 0.371    | 0.434    |
| 5,000      | 0.027    | 0.056    | 0.295    | 0.030       | 0.048    | 0.052    | 0.082    |
| 7,000      | 0.037    | 0.065    | 0.132    | 0.014       | 0.069    | 0.077    | 0.082    |
| 10,000     | 0.026    | 0.052    | 0.269    | 0.021       | 0.054    | 0.070    | 0.095    |
| 13,000     | 0.021    | 0.064    | 0.846    | 0.038       | 0.060    | 0.080    | 0.111    |
| 17,000     | 0.020    | 0.080    | 0.898    | 0.064       | 0.058    | 0.084    | 0.610    |
| 20,000     | 0.021    | 0.073    | 0.987    | 0.075       | 0.061    | 0.145    | 0.750    |

Il receiver presenta un chiaro limite tra i 5000 e i 6000 pps. Il collo di bottiglia è dovuto presumibilmente:
- a una poco efficiente gestione dei ring buffer da parte del receiver 
- overhead nell'elaborazione dei pacchetti nei loop di ricezione
