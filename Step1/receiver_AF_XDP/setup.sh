#!/bin/bash

# Script per installare le dipendenze necessarie per il progetto
# Da eseguire su entrambe le VM

sudo apt update

sudo apt install -y \
    clang \
    llvm \
    libelf-dev \
    gcc \
    make \
    libbpf-dev \
    libxdp-dev \
    libxdp1 \
    linux-headers-$(uname -r)

sudo ldconfig

echo "Installazione completata!"
echo "Versione clang: $(clang --version | head -n 1)"
echo "Versione GCC: $(gcc --version | head -n 1)"
echo "Versione kernel: $(uname -r)"
echo "Verifica se libxdp è raggiungibile: $(ldconfig -p | grep libxdp || echo "NON TROVATA")"
echo "Verifica se libbpf è raggiungibile: $(ldconfig -p | grep libbpf || echo "NON TROVATA")"

if sudo ip link set dev enp8s0 xdp off 2>/dev/null; then
    echo "L'interfaccia enp8s0 supporta XDP"
else
    echo "ATTENZIONE: L'interfaccia enp8s0 sembra non supportare XDP"
fi