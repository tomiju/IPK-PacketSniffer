# IPK - Projekt 2
### Varianta: [ZETA] Sniffer paketů
### Autor: Tomáš Julina (xjulin08)
### Datum: 01.05.2020

***
* Zvolený jazyk: C++

* ROZŠÍŘENÍ:
	- Sniffování na více rozhraních
			formát: "-i rozhrani1,rozhrani2" (musí být odděleny čárkou, bez mezery, jen čárka)

	- Filtrování více portů najednou
			formát: "-p port1,port2" (musí být odděleny čárkou, bez mezery, jen čárka)

	- Cache pro překlad IP adres - pokud je již adresa jednou přeložená, uložím ji do cache
	  před příštím pokusem o přeložení se první zjistí, zda už není přeložená, aby se zbytečně
	  nezacyklilo posílání DNS paketů s žádostí o překlad.

	- Podpora paketů s IPv6 adresou.

	- Nekonečný výpis paketů při zadání parametru "-n -1" (nutné manuální ukončení programu).

Poznámky k implementaci:

	1. V případě volání "sudo ./ipk-sniffer" dojde k vypsání všech aktivních zařízení
	   které je možné použít s funkcí "pcap_open_live()", nefiltruji "RUNNING" ani "UP" flagy.
	   V případě, že není zadán parametr "-i", ale je zadán některý další argument správně
	   vypíšu seznam zařízení a program úspěšně skončí, pokud ovšem chybí parametr "-i" a
	   je zadán další parametr chybný, či s chybnou hodnotou program skončí s chybovým hlášením.

	2. Chybějící hodnota parametru "-i" je vnímána jako chyba.

	3. V případě, kdy velikost paketu 60B a velikost hlavičky (IP+TCP+ETH) je menší než 60B tak
	   paket obsahuje ethernetový padding (ve Wireshark i TCPdump se vypisuje za TCP hlavičkou), tento
 	   padding se přidává automaticky, když je paket menší, než 64B (minimální velikost ethernet frame)
	   tento padding vypisuji tedy po vzoru Wireshark hned za TCP hlavičku jakou součást hlavičky paketu.
	   Viz. druhý paket v ukázce níže.

	4. Každých 8 vypsaných bajtů je odděleno mezerou pro větší přehlednost (viz. zadání a Wireshark)

	5. Program podporuje rozhraní, která vytvářejí ethernetové či linux „cooked“ hlavičky.

	6. Opakované použití parametru "-i" přepíše prvotní použití (platí pro všechny argumenty).

	7. Hodnota "-1" u parametru "n" znamená, že se bude vypisovat nekonečné množství paketů a sniffer
	   musí být ukončen manuálně.

	8. Maximální hodnota parametru "-n" je 2147483647 (záporná hodnota, kromě -1 je chyba), v případě, že
	   chcete víc, použijte "-n -1" pro nekonečný výpis.

	9. Argument "-h" nebo "--help" slouží k výpisu nápovědy k programu.

Seznam souborů:
- ipk-sniffer.cpp
- ipk-sniffer.hpp
- Makefile
- README
- manual.pdf

Příklady spuštění:
```sudo ./ipk-sniffer -i enp0s3,lo,any -n 30 -p 80
sudo ./ipk-sniffer -i enp0s3 -n -1 -u
sudo ./ipk-sniffer -i enp0s3 -t -p 80,22
```
Ukázka spuštění (na referenčním stroji):

	```student@student-vm:\~/Desktop/xjulin08$ make
	student@student-vm:~/Desktop/xjulin08$ sudo ./ipk-sniffer -i enp0s3 -n 30 -p 80
	15:29:30.496522 student-vm : 39512 > ec2-18-217-80-105.us-east-2.compute.amazonaws.com : 80

	0x0000:  52 54 00 12 35 02 08 00  27 6f 35 b5 08 00 45 00  RT..5... 'o5...E.
	0x0010:  00 3c 99 cb 40 00 40 06  31 a0 0a 00 02 0f 12 d9  .<..@.@. 1.......
	0x0020:  50 69 9a 58 00 50 5a a9  4a 12 00 00 00 00 a0 02  Pi.X.PZ. J.......
	0x0030:  fa f0 6f 7f 00 00 02 04  05 b4 04 02 08 0a 20 1f  ..o..... ...... .
	0x0040:  f2 81 00 00 00 00 01 03  03 07                    ........ ..

	15:29:30.638126 ec2-18-217-80-105.us-east-2.compute.amazonaws.com : 80 > student-vm : 39512

	0x0000:  08 00 27 6f 35 b5 52 54  00 12 35 02 08 00 45 00  ..'o5.RT ..5...E.
	0x0010:  00 2c eb de 00 00 40 06  1f 9d 12 d9 50 69 0a 00  .,....@. ....Pi..
	0x0020:  02 0f 00 50 9a 58 03 fd  7c 01 5a a9 4a 13 60 12  ...P.X.. |.Z.J.`.
	0x0030:  ff ff 69 62 00 00 02 04  05 b4 00 00              ..ib.... ....

	15:29:30.638198 student-vm : 39512 > ec2-18-217-80-105.us-east-2.compute.amazonaws.com : 80

	0x0000:  52 54 00 12 35 02 08 00  27 6f 35 b5 08 00 45 00  RT..5... 'o5...E.
	0x0010:  00 28 99 cc 40 00 40 06  31 b3 0a 00 02 0f 12 d9  .(..@.@. 1.......
	0x0020:  50 69 9a 58 00 50 5a a9  4a 13 03 fd 7c 02 50 10  Pi.X.PZ. J...|.P.
	0x0030:  fa f0 6f 6b 00 00                                 ..ok..

	15:29:30.645205 student-vm : 39512 > ec2-18-217-80-105.us-east-2.compute.amazonaws.com : 80

	0x0000:  52 54 00 12 35 02 08 00  27 6f 35 b5 08 00 45 00  RT..5... 'o5...E.
	0x0010:  00 71 99 cd 40 00 40 06  31 69 0a 00 02 0f 12 d9  .q..@.@. 1i......
	0x0020:  50 69 9a 58 00 50 5a a9  4a 13 03 fd 7c 02 50 18  Pi.X.PZ. J...|.P.
	0x0030:  fa f0 6f b4 00 00                                 ..o...

	0x0036:  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HT TP/1.1..
	0x0046:  48 6f 73 74 3a 20 62 6c  61 6e 6b 2e 6f 72 67 0d  Host: bl ank.org.
	0x0056:  0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 63 75 72  .User-Ag ent: cur
	0x0066:  6c 2f 37 2e 35 38 2e 30  0d 0a 41 63 63 65 70 74  l/7.58.0 ..Accept
	0x0076:  3a 20 2a 2f 2a 0d 0a 0d  0a                       : */*...
  ```


Popis výstupu:
	První část:
		čas IP|FQDN : port > IP|FQDN : port
	Druhá část:
		IP header + UDP/TCP header + ETHERNET header + ETHERNET padding
		počet_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII
	Třetí část:
		Data paketu (pokud nějaké jsou)
		počet_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII
