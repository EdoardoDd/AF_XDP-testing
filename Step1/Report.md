# Report XDPsock - AF_XDP Performance Tool

AF_XDP è un'interfaccia socket che permette di raggiungere prestazioni di rete ad alta velocità attraverso il kernel bypass. Il programma **xdpsock** implementa un tool di testing delle prestazioni di rete basato su AF_XDP per la valutazione di throughput, latenza e packet loss.

### Opzioni Principali
- `-i <if>`: Interfaccia di rete
- `-q <n>`: Coda (default: 0)  
- `-R <pps>`: Rate in pacchetti/secondo
- `-d <sec>`: Durata test
- `-z`: Zero-copy mode
- `-S`: XDP-SKB mode
- `-N`: XDP-native mode

## Architettura del Sistema

### Modalità

L'applicazione offre quattro modalità principali:

1. **RXPROCESS** (`-r`): Analisi dei pacchetti in ricezione con calcolo di RTT, jitter e packet loss
2. **TXONLY** (`-t`): Trasmissione continua per test di throughput
3. **ECHO** (`-l`): Server echo che risponde alle richieste (default)
4. **TXRX** (`-x`): Client ping bidirezionale con misurazione RTT

### Gestione della Memoria

- **UMEM**: 8K frame da 4KB condivisi tra applicazione e kernel
- **Ring Buffer**: RX, TX, FILL e COMPLETION queue per trasferimento lock-free
- **Batch Processing**: Elaborazione a gruppi di 64 pacchetti per efficienza

### Struttura dei Pacchetti

Formato: Ethernet (14B) + IP (20B) + UDP (8B) + Payload (16B)

Payload personalizzato:
- **Sequence** (4B): Numero di sequenza per tracking
- **Timestamp** (8B): Per calcolo RTT
- **Type/Data** (4B): REQUEST/RESPONSE + dati aggiuntivi
<!-- Potremmo analizzare diverse dimensione dei pacchetti per vedere quale ha migliori prestazioni -->

## Implementazione

### Zero-Copy Mode
La modalità zero-copy (`-z`) elimina le copie di memoria tra kernel e user space attraverso l'accesso diretto all'UMEM condivisa, in questo modo operano sulla stessa area di memoria, riducendo drasticamente l'overhead di trasferimento dati. 
Questa modalità offre prestazioni massime ma richiede supporto specifico del driver di rete. In caso di incompatibilità, il sistema utilizza automaticamente la modalità copy come fallback.

### Batch Processing
Il programma elabora pacchetti in gruppi di 64 (`BATCH_SIZE = 64`). Questo permette meno chiamate di sistema e transizioni kernel/user space. 
   - TX: `xsk_ring_prod__reserve()` riserva 64 slot simultaneamente
   - RX: `xsk_ring_cons__peek()` legge fino a 64 pacchetti per ciclo
   - Completion: Processamento batch delle completion queue
   - FILL Queue: Rifornimento a gruppi di frame liberi

## Strategie di Polling
Il programma implementa due approcci per gestire eventi sui socket AF_XDP, selezionabili tramite l'opzione `-p`:

#### Busy Polling (Modalità Default)
Senza l'opzione `-p`, il programma usa **busy polling**:
- Loop infinito che controlla continuamente i ring buffer
- Nessuna attesa o sleep nel ciclo principale  
- Controllando direttamente il ring buffer, non c'è context switch
- Alto uso di CPU sul core dedicato

#### Poll() Mode (`-p`)
Con l'opzione `-p`, il programma usa la **syscall poll()**:
- Il processo si **blocca** e delega al kernel il monitoraggio dei socket
- Il kernel **sblocca** il processo solo quando arrivano pacchetti o al timeout (1s)
- Ciò causa overhead di context switch tra user space e kernel space
- Latenza più alta ma efficienza risorse per ambienti multi-processo, consumo basso di CPU durante idle
<!-- Approfondisci con magari un confronto dell'uso della CPU-->

## Metriche Raccolte
- **Throughput**: pps e Mbps in TX/RX
- **RTT**: Min/Avg/Max round trip time
- **Jitter**: Variabilità del RTT
- **Packet Loss**: Percentuale e conteggio
- **Out-of-order**: Pacchetti fuori sequenza


## Invio Pacchetti (TX)

1. **Preparazione**: 
   - Generazione template pacchetto con `gen_eth_frame()` nell'UMEM
   - Aggiornamento sequence number e timestamp per ogni invio

2. **Trasmissione**:
   - `xsk_ring_prod__reserve()`: Riserva slot nel TX ring
   - Configurazione descrittori con indirizzo frame e lunghezza
   - `xsk_ring_prod__submit()`: Sottomette batch al kernel
   - `kick_tx()`: Trigger invio via `sendto()`

3. **Completion**:
   - `complete_tx_*()`: Controlla completion queue
   - Rilascio frame completati nella pool libera
   - Aggiornamento contatori TX

## Ricezione Pacchetti (RX)

1. **Rifornimento**:
   - `xsk_ring_prod__reserve()` su FILL queue
   - Inserimento indirizzi frame liberi per ricezione
   - `xsk_ring_prod__submit()`: Frame disponibili al kernel

2. **Ricezione**:
   - `xsk_ring_cons__peek()`: Controlla nuovi pacchetti in RX ring
   - Accesso diretto ai dati via `xsk_umem__get_data()`
   - Parsing payload per sequence/timestamp/type

3. **Processing**:
   - **ECHO**: `swap_addresses()` + `convert_to_response()`
   - **RXPROCESS**: Calcolo RTT, tracking loss/jitter
   - `xsk_ring_cons__release()`: Rilascio descrittori processati

### Gestione Memoria

- **Frame Pool**: Pool circolare di indirizzi UMEM liberi
- **Zero-Copy**: Accesso diretto senza copie intermedie
- **Batch Operations**: Elaborazione gruppi per ridurre overhead
- **Ring Synchronization**: Produttore-consumatore lock-free

## Prestazioni

*[Da completare appena torna disponibile la NIC che supporta XDP NATIVE e ZERO COPY]*