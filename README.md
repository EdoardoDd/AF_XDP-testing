Questa repository contiene strumenti per misurare e ottimizzare le prestazioni di rete utilizzando la tecnologia AF_XDP.

 ---
 
### Struttura della repository:
- Step1: Applicazione ping-pong (simile a iperf) basata su AF_XDP
  - Strumento di benchmark per misurare latenza e throughput
  - Implementa un modello client-server per test di comunicazione bidirezionale

### Prerequisiti
- Kernel Linux 5.x o superiore con supporto XDP
- Scheda di rete compatibile con XDP
- Librerie di sviluppo: libbpf, libxdp

## Step1 - Installation
 ```bash
git clone https://github.com//EdoardoDd/AF_XDP-testing.git

# Install dependencies
./setup.sh

# Compile libraries and applications
make
 ```

## Step1 - Usage
Opzioni disponibili

    -r, --rxprocess
    Riceve e analizza i pacchetti in ingresso per metriche di performance (RTT, jitter, perdita)

    -t, --txonly
    Invia solo pacchetti, utile per test di throughput

    -l, --echo
    Modalità echo server: scambio MAC/IP e risposta con stesso payload

    -x, --txrx
    Test ping bidirezionale con misurazione del RTT

    -i, --interface=n
    Esegui sull’interfaccia n (predefinita: enp18s0)

    -q, --queue=n
    Usa la coda n (predefinita: 0)

    -p, --poll
    Usa la syscall poll() al posto del busy polling

    -S, --xdp-skb
    Usa la modalità XDP skb

    -N, --xdp-native
    Forza la modalità XDP nativa

    -n, --interval=n
    Intervallo di aggiornamento delle statistiche, in secondi (predefinito: 1)

    -z, --zero-copy
    Forza la modalità zero-copy

    -c, --copy
    Forza la modalità copy (predefinita)

    -R, --rate=n
    Specifica il rate di trasmissione in pacchetti al secondo (solo per modalità txrx)

    -d, --duration=n
    Esegui per n secondi (predefinito: infinito)

Modalità operative

    - rxprocess
    Riceve pacchetti e calcola statistiche su RTT, jitter e perdite

    - txonly
    Trasmette pacchetti in modo continuo per test di throughput

    - echo
    Modalità echo server: scambia indirizzi MAC/IP e risponde al mittente

    - txrx
    Modalità ping client: invia richieste e misura i tempi di risposta

