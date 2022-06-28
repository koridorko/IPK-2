# IPK - projekt č. 2 - Sniffer paketov

Jedná sa o program, ktorý analyzuje a podľa zadaného filtra zachytáva na určenom sieťovom rozhraní pakety, a tlačí ich hlavičky spolu so základnými informáciami (timestamp, čas, zdrojová MAC adresa, ciel’ová
MAC adresa, dĺžka rámca, zdrojová IP adresa (ak je), ciel’ová IP adresa (ak je), zdrojový port (ak
je), ciel’ový port (ak je)) o pakete na `stdout`.
Taktiež sú vytlačené (aj HEXA aj ASCI hodnota) BYTE-y paketu.
Podporuje IPv4 aj IPv6.
Podporované typy paketov : UDP, TCP, ARP, ICMP

### Argumenty pri spúšťaní
`./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p --port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`
kde :
`--i | -i` udáva rozhranie na ktorom budú pakety odchytávané (pokiaľ nieje zadané, vypíše zoznam všetkých rozhraní a program sa ukončí)
`--p | -p` udáva číslo portu na ktorom sa budú pakety odchztávať (predvolená hodnota sú všetkz porty)
`-t | --tcp` pakety TCP budú odchytávané
`-u | --udp` pakety UDP budú odchytávané
`--arp` pakety ARP budú odchytávané
`--icmp` pakety ICMP budú odchytávané

### Príklad spustenia
```
make
sudo ./ipk-sniffer -i eth0 --arp -u -n 10
```
Na rozhraní `eth0` bude odchytených 10 paketov (dokopy) `UDP` a `ARP`

### Zoznam odovzdaných súborov
1. Makefile
2. main.cpp
3. manual.pdf
4. README.MD