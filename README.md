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

## Installation
 ```bash
git clone https://github.com//EdoardoDd/AF_XDP-testing.git

# Install dependencies
./setup.sh

# Compile libraries and applications
make
 ```
