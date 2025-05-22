# Common - AF_XDP Utility Library
Questa libreria fornisce un insieme di funzioni per lavorare con AF_XDP, con l'obbiettivo di semplificare lo sviluppo di applicazioni XDP.

## Componenti

#### 1. common_defines.h
File header che contiene definizioni fondamentali utilizzate in tutta la libreria:
- `struct config`: Struttura centrale che mantiene la configurazione dell'applicazione XDP.
<br/>

#### 2. common_packet.c/h
Questo modulo implementa funzionalità complete per la manipolazione e l'analisi dei pacchetti di rete:
- **Checksum**:
    - `csum16_add`, `csum16_sub`: Calcolo e aggiornamento incrementale di checksum
    - `csum_replace2`: Sostituzione di campi nel checksum
- **Analisi dei pacchetti**:
    - `print_packet_info`: Funzione dettagliata che decodifica e stampa:
        - Header Ethernet (MAC sorgente/destinazione, tipo)
        - IPv4/IPv6 (indirizzi, protocollo)
        - TCP (porte, flag SYN/ACK/FIN/etc.)
        - UDP (porte, lunghezza)
        - ICMP/ICMPv6 (tipo, codice)
        - Dump esadecimale dei primi 32 byte
- **Creazione pacchetti**:
    - `create_udp_packet`: Costruisce un pacchetto UDP configurando header, calcolando checksum IP e inserendo payload specificato
    - `create_response_packet`: Genera un pacchetto di risposta basato su un pacchetto ricevuto
- **Estrazione informazioni**:
    - `extract_packet_info`: Estrae i vari campi da un pacchetto    
    - `packet_contains`: Verifica se un pacchetto contiene un pattern specifico
- **Funzioni per gli indirizzi MAC**:
    - `get_interface_mac`: Ottiene l'indirizzo MAC di un'interfaccia di rete
    - `discover_mac_address`: Scopre l'indirizzo MAC associato a un IP usando ARP
    - `mac_addr_to_str`: Converte un indirizzo MAC binario in formato stringa
    - `str_to_mac_addr`: Converte una stringa in un indirizzo MAC binario
<br/>

#### 3. common_params.c/h
Questo modulo gestisce l'analisi dei parametri cli per configurare l'ambiente XDP:
- Definisce una **struttura globale** `cfg` che mantiene la configurazione predefinita dell'applicazione
- `struct option long_options[]`: Array di opzioni della linea di comando supportate
- `usage()`: Funzione che stampa l'help con tutte le opzioni disponibili
- `parse_cmdline_args()`: Analizza gli argomenti passati dall'utente e configura la struttura cfg
- opzioni di configurazione:
    - Selezione dell'interfaccia di rete (`--dev`)
    - Modalità XDP (`--skb-mode`, `--native-mode`, `--auto-mode`)
    - Opzioni di forza (`--force`)
    - Modalità di copia (`--copy`, `--zero-copy`)
    - Selezione della coda (`--queue`)
    - Modalità di polling (`--poll-mode`)
    - Verbosità (`--quiet`)
    - File e nome del programma (`--filename`, `--progname`)
    - Modalità di test delle prestazioni (`--perf-mode`)
    - Parametri di test (`--duration`, `--packetsize`, `--rate`)
<br/>

#### 4. common_stats.c/h
Questo modulo implementa funzionalità per la misurazione e visualizzazione delle prestazioni:
- **Tracking delle statistiche di base**:
    - `struct stats_recor`: Struttura che mantiene contatori di pacchetti e byte
    - `stats_print()`: Visualizza statistiche RX/TX, inclusi pacchetti al secondo (pps) e Mbps
- **Monitoraggio asincrono**:
    - `stats_poll()`: Funzione thread che periodicamente raccoglie e visualizza statistiche
- **Statistiche per test delle prestazioni**:
    -`struct perf_stats`: struttura che mantiene:
        - Contatori di pacchetti e byte
        - Statistiche di latenza (min, max, media)
        - Calcolo della varianza per il jitter
        - Timestamp di inizio per calcolare la durata totale
    - `perf_stats_init()`: Inizializza la struttura delle statistiche
    - `perf_stats_add_latency()`: Aggiunge un nuovo campione di latenza
    - `perf_stats_print_summary()`: Genera un report completo
<br/>

#### 5. common_user_bpf_xdp.c/h
Componente centrale della libreria, **implementa l'interazione con AF_XDP**:
- **Strutture dati principali**:
    - `struct xsk_umem_info`: Gestisce la memoria condivisa (**UMEM**)
        - Ring di produzione e consumo (fill queue, completion queue)
        - Riferimento alla struttura UMEM
        - Puntatore al buffer
    - `struct xsk_socket_info`: Rappresenta un **socket AF_XDP**
        - Ring RX e TX
        - Riferimento all'UMEM
        - Array degli indirizzi dei frame
        - Contatori di frame liberi e trasmissioni in sospeso 
        - Statistiche
- **Gestione del programma XDP**:
    - `do_unload()`: Scarica un programma XDP da un'interfaccia
- **Gestione dell'UMEM**:
    - `configure_xsk_umem()`: Configura la memoria condivisa per AF_XDP
    - `xsk_alloc_umem_frame()`: Alloca un frame dalla memoria gestita
    - `xsk_free_umem_frame()`: Restituisce un frame all'UMEM
    - `xsk_umem_free_frames()`: Restituisce il numero di frame liberi
    - `xsk_ring_prod__free()`: Calcola lo spazio libero in un ring di produzione
- **Configurazione e gestione dei socket**:
    - xsk_configure_socket(): Configura un socket AF_XDP completo, inizializzando i ring RX/TX e popolando la fill queue
- **Operazioni di trasmissione e ricezione**:
    - `complete_tx()`: Gestisce la completion queue per i pacchetti trasmessi
    - `xsk_send_packet()`: Invia un pacchetto tramite AF_XDP
        - Alloca un frame
        - Copia i dati nel buffer
        - Configura il descrittore TX
    - `xsk_receive_packet()`: Riceve un pacchetto con timeout - gestisce le statistiche di ricezione
    - `xsk_refill_fill_queue()`: Rifornisce la fill queue con frame liberi
    - `xsk_process_packets()`: Elabora i pacchetti ricevuti con una funzione di callback
    - `xsk_request_response()`: Implementa un pattern request-response
<br/>

