/**
  * IPK Project 2 - Sniffer paketů
  * Autor: Tomáš Julina (xjulin08)
  * Datum: 01.05.2020
  * Soubor: ipk-sniffer.cpp
 **/

#include "ipk-sniffer.hpp"

 /*
   * Princip For cyklu pro výpis po 16 znacích byl inspirován kódem funkce PrintData ze zdroje:
   *
   * Název článku: C Packet Sniffer Code with libpcap and linux sockets
   * Autor článku: Silver Moon
   * Odkaz: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void print_packet(int packetSize, int headerSize, int ethernetPadding, const u_char* buffer)
{
  int i, j;
  int byteCounter = 0; // počítadlo vypsaných bajtů

  for (i = 0; i < headerSize + ethernetPadding; i++) // velikost hlavičky = hlavička + případný padding
  {
    // po vytištění hexa bajtů tisk stejných znaků v ASCII
    if (i != 0 && i % 16 == 0)
    {
      printf("  ");
      for (j = i - 16; j < i; j++) // vrácení se zpět o 16 znaků
      {
        if (j % 8 == 0 && j % 16 != 0)
        {
          printf(" ");
        }
        if (buffer[j] >= 32 && buffer[j] <= 126)
        {
          printf("%c", (unsigned char)buffer[j]); // tisknutelné znaky tisknu
          byteCounter++;
        }
        else
        {
          printf("."); // místo netisknutelných tečka
          byteCounter++;
        }
      }
        printf("\n");
      }

      if (i % 16 == 0)
      {
        printf("0x%04x: ", byteCounter); // počet vytisknutých znaků (začátek řádku)
      }

      if (i % 8 == 0 && i % 16 != 0) // mezera po 8 hexa bajtech
      {
        printf(" ");
      }

      printf(" %02x", (unsigned int)buffer[i]); // hexa bajty

      if (i == headerSize + ethernetPadding - 1) // poslední řádek
      {
        for (j = 0; j < 15 - i % 16; j++) // když není poslední řádek celý, tak se dotisknou mezery - formátování
        {
          printf("   ");
        }
        if (j >= 8)
        {
          printf(" ");
        }
        printf("  ");

        for (j = i - i % 16; j <= i; j++) // zbytek posledního řádku (ASCII) - vrácení se o počet vytisknutých znaků z posledního řádku zpět
        {
          if (j % 8 == 0 && j % 16 != 0)
          {
            printf(" ");
          }

          if (buffer[j] >= 32 && buffer[j] <= 126)
          {
            printf("%c", (unsigned char)buffer[j]);
            byteCounter++;
          }
          else
          {
            printf(".");
            byteCounter++;
          }
        }
        printf("\n");
      }
  }

  if (packetSize - headerSize - ethernetPadding != 0) // případ, kdy jsou kromě hlavičky i data - oddělí se mezerou a vytisknou se opět stejným způsobem
  {
    printf("\n");

    int pom = i; // pomocné proměnné pro orientaci v bufferu s daty paketu
    int pom2 = 0;

    for (i = 0; i < packetSize - headerSize - ethernetPadding; i++) // celý paket - hlavička = data
    {
      // po vytištění hexa bajtů tisk stejných znaků v ASCII
      if (i != 0 && i % 16 == 0)
      {
        printf("  ");

        pom2 = i - 16; // orientace v bufferu s daty - pom2 je "j" z části výpisu hlavičky
        for (j = pom - 16; j < pom; j++)
        {
          if (pom2 % 8 == 0 && pom2 % 16 != 0)
          {
            printf(" ");
          }
          if (buffer[j] >= 32 && buffer[j] <= 126)
          {
            printf("%c", (unsigned char)buffer[j]); // tisknutelné znaky tisknu
            byteCounter++;
          }
          else
          {
            printf("."); // místo netisknutelných tečka
            byteCounter++;
          }
          pom2++;
        }
          printf("\n");
          pom2 = j;
        }

        if (i % 16 == 0)
        {
          printf("0x%04x: ", byteCounter); // počet vytisknutých znaků (začátek řádku)
        }

        if (i % 8 == 0 && i % 16 != 0) // formátování
        {
          printf(" ");
        }

        printf(" %02x", (unsigned int)buffer[pom]); // hexa bajty

        if (i == packetSize - headerSize - ethernetPadding - 1) // poslední řádek
        {
          for (j = 0; j < 15 - i % 16; j++) // když není poslední řádek celý, tak se dotisknou mezery - formátování
          {
            printf("   ");
          }
          if (j >= 8)
          {
            printf(" ");
          }
          printf("  ");

          pom2 = pom - i % 16; // pom2 je "j" z části výpisu hlavičky

          for (j = i - i % 16; j <= i; j++) // zbytek posledního řádku
          {
            if (j % 8 == 0 && j % 16 != 0)
            {
              printf(" ");
            }

            if (buffer[pom2] >= 32 && buffer[pom2] <= 126)
            {
              printf("%c", (unsigned char)buffer[pom2]);
              byteCounter++;
            }
            else
            {
              printf(".");
              byteCounter++;
            }
            pom2++;
          }
          printf("\n");
        }
        pom++;
    }
  }
  printf("\n");
}

void callback(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
    struct my_data *myData = (struct my_data*) args; // vstupní argumenty
    int handleId = myData->snifferNumber; // ID aktuálního rozhraní

    if (myData->number == -1 || myData->number == -5) // má se vypsat pouze 1 paket (-5, nebyl zadán parametr -n) nebo nekonečný výpis (-1)
    {

    }
    else if (myData->number < 1) // konec sniffování - byl vypsán požadovaný počet paketů
    {
      pcap_breakloop(myData->sniffer[handleId]);
      return;
    }

    int packetSize = header->caplen; // délka zachyceného paketu

    time_t timestamp; // čas z hlavičky
    char timeString[16]; // string verze času

    char nodeSrc[NI_MAXHOST]; // IP/DN zdroje
    char nodeDst[NI_MAXHOST]; // IP/DN cíle

    struct iphdr* iph = (struct iphdr*)(buffer + myData->linkLayerHeaderSize[myData->snifferNumber]); // IP hlavička
    unsigned short iphLen; // délka IP hlavičky v 32 bit slovech (ukazuje na začátek dat)
    int protocol; // 6 == TCP, 17 == UDP

    map<string,string>::iterator cacheIterator;

    // IPv4
    if (iph->version == 4)
    {
      iphLen = iph->ihl * 4; // délka IP hlavičky v 32 bit slovech (ukazuje na začátek dat) (4 octety)
      protocol = iph->protocol; // TCP/UDP

      struct sockaddr_in source, dest; // adresa zdroje a cíle IPV4

      source.sin_family = AF_INET; // IPV4 rodina
      dest.sin_family = AF_INET; // IPV4 rodina

      source.sin_addr.s_addr = iph->saddr; // zdrojová IP
      dest.sin_addr.s_addr = iph->daddr; // cílová IP

      char srcIP[NI_MAXHOST]; // IP zdroje (pro cache)
      char dstIP[NI_MAXHOST]; // IP cíle (pro cache)

      inet_ntop(AF_INET, &(source.sin_addr.s_addr), srcIP, INET_ADDRSTRLEN); // převod binární formy IP na textovou
      inet_ntop(AF_INET, &(dest.sin_addr.s_addr), dstIP, INET_ADDRSTRLEN); // převod binární formy IP na textovou

      string stringSrcIp(srcIP); // vyčištění paměti po předchozím výpisu
      string stringDstIp(dstIP); // vyčištění paměti po předchozím výpisu

      // pokus o vyhledání adresy v cache, pokud se najde, načtu ji z tama, jinak použiji getnameinfo
      cacheIterator = myData->DNScache.find(stringSrcIp);

      memset(nodeSrc, 0, sizeof(nodeSrc)); // vyčistění pole po předchozím výpisu
      memset(nodeDst, 0, sizeof(nodeDst)); // vyčistění pole po předchozím výpisu

      if (cacheIterator != myData->DNScache.end()) // našel se překlad v cache
      {
        for (unsigned int x = 0; x < cacheIterator->second.length(); x++)
        {
          nodeSrc[x] = cacheIterator->second[x];
        }
      }
      else // nenašel se překlad v cache
      {
        getnameinfo((struct sockaddr*) &source, sizeof(source), nodeSrc, sizeof(nodeSrc), NULL, 0, 0); // pokus o získání DN pro IPV4

        string tmpSrc(nodeSrc);
        myData->DNScache.insert(pair<string,string>(stringSrcIp,tmpSrc)); // uložení přeloženého jména do cache
      }

      cacheIterator = myData->DNScache.find(stringDstIp);

      if (cacheIterator != myData->DNScache.end()) // našel se překlad v cache
      {
        for (unsigned int x = 0; x < cacheIterator->second.length(); x++)
        {
          nodeDst[x] = cacheIterator->second[x];
        }
      }
      else // nenašel se překlad v cache
      {
        getnameinfo((struct sockaddr*) &dest, sizeof(dest), nodeDst, sizeof(nodeDst), NULL, 0, 0); // pokus o získání DN pro IPV4
        // uložení přeložené DN do cache
        string tmpDst(nodeDst);
        myData->DNScache.insert(pair<string,string>(stringDstIp,tmpDst)); // uložení přeloženého jména do cache
      }
    }
    // IPv6
    else if (iph->version == 6)
    {
      struct ip6_hdr* iph6 = (struct ip6_hdr*)(buffer + myData->linkLayerHeaderSize[myData->snifferNumber]); // IPv6 hlavička
      iphLen = 40; // ipv6 header má fixní velikost 40 octets
      protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt; // protocol - TCP/UDP

      struct sockaddr_in6 source6, dest6; // adresa zdroje a cíle IPV6

      source6.sin6_family = AF_INET6; // IPV6 rodina
      dest6.sin6_family = AF_INET6; // IPV6 rodina

      source6.sin6_addr = iph6->ip6_src; // zdrojová IP
      dest6.sin6_addr = iph6->ip6_dst; // cílová IP

      char srcIP6[NI_MAXHOST]; // IP zdroje (pro cache)
      char dstIP6[NI_MAXHOST]; // IP cíle (pro cache)

      inet_ntop(AF_INET6, &(source6.sin6_addr), srcIP6, INET6_ADDRSTRLEN); // převod binární formy IP na textovou
      inet_ntop(AF_INET6, &(dest6.sin6_addr), dstIP6, INET6_ADDRSTRLEN); // převod binární formy IP na textovou

      string stringSrcIp6(srcIP6);
      string stringDstIp6(dstIP6);

      // pokus o vyhledání adresy v cache, pokud se najde, načtu ji z tama, jinak použiji getnameinfo
      cacheIterator = myData->DNScache.find(stringSrcIp6);

      memset(nodeSrc, 0, sizeof(nodeSrc)); // vyčištění paměti po předchozím výpisu
      memset(nodeDst, 0, sizeof(nodeDst)); // vyčištění paměti po předchozím výpisu

      if (cacheIterator != myData->DNScache.end()) // našel se překlad v cache
      {
        for (unsigned int x = 0; x < cacheIterator->second.length(); x++)
        {
          nodeSrc[x] = cacheIterator->second[x];
        }
      }
      else // nenašel se překlad v cache
      {
        getnameinfo((struct sockaddr*) &source6, sizeof(source6), nodeSrc, sizeof(nodeSrc), NULL, 0, 0); // pokus o získání DN pro IPV6

        string tmpSrc6(nodeSrc);
        myData->DNScache.insert(pair<string,string>(stringSrcIp6,tmpSrc6)); // uložení přeloženého jména do cache
      }

      cacheIterator = myData->DNScache.find(stringDstIp6);

      if (cacheIterator != myData->DNScache.end()) // našel se překlad v cache
      {
        for (unsigned int x = 0; x < cacheIterator->second.length(); x++)
        {
          nodeDst[x] = cacheIterator->second[x];
        }
      }
      else // nenašel se překlad v cache
      {
        getnameinfo((struct sockaddr*) &dest6, sizeof(dest6), nodeDst, sizeof(nodeDst), NULL, 0, 0); // pokus o získání DN pro IPV6
        // uložení přeložené DN do cache
        string tmpDst6(nodeDst);
        myData->DNScache.insert(pair<string,string>(stringDstIp6,tmpDst6)); // uložení přeloženého jména do cache
      }
    }

    // TCP paket
    if ((protocol == 6 && !myData->tcp && !myData->udp) || (protocol == 6 && myData->tcp && myData->udp) || (protocol == 6 && myData->tcp))
    {
        struct tcphdr* tcph = (struct tcphdr*)(buffer + iphLen + myData->linkLayerHeaderSize[myData->snifferNumber]); // TCP hlavička

        // pokud se hledá paket na nějakém portu a port nesedí, přeskočím ho
        if (!myData->port.empty())
        {
          bool isPortFromFilter = false;
          for (unsigned int i = 0; i < myData->port.size(); ++i)
          {
            if (myData->port[i] == ntohs(tcph->dest) || myData->port[i] == ntohs(tcph->source))
            {
              isPortFromFilter = true;
              break;
            }
          }

          if (!isPortFromFilter) // když neodpovídá port, paket se přeskočí
          {
            return;
          }
        }

        // počítadlo paketů
        if (myData->number == -5) // má se vypsat pouze 1 (nebyl zadán parametr -n)
        {
          myData->number--; // počítadlo paketů
        }
        else if(myData->number == -1) // nekonečný výpis
        {

        }
        else if (myData->number < 1) // konec sniffování - byl vypsán požadovaný počet paketů
        {
          pcap_breakloop(myData->sniffer[handleId]);
          return;
        }
        else
        {
          myData->number--; // počítadlo paketů
        }

        // struktura time_t, vezmu čas přijetí v sekundách
        timestamp = header->ts.tv_sec;

        //strftime vezme strukturu, kterou vrátí funkce localtime a převede ji na string dle požadovaného formátu
        // výsledný čas, délka stringu, formát, localtime převede čas do struktury na sekundy, minuty, ...
        strftime(timeString, sizeof(timeString), "%H:%M:%S", localtime(&timestamp)); // formátování času
        printf("%s.%.6ld ", timeString, header->ts.tv_usec); // tisk času -> HH:MM:SS.US, ts.tv_usec je čas minus tv_sec v mikrosekundách

        // tisk zbytku prvního řádku výpisu
        printf("%s : ", nodeSrc); // IP/DN
        printf("%u > ", ntohs(tcph->source)); // zdrojový port
        printf("%s : ", nodeDst); // IP/DN
        printf("%u\n\n", ntohs(tcph->dest)); // cílový port

        int headerSizeTCP = myData->linkLayerHeaderSize[myData->snifferNumber] + iphLen + tcph->doff * 4; // délka hlavičky (zároveň i pointer na data)
        int ethernetPadding = 0; // ethernet padding v případě, kdy je velikost paketu menší než 64B (minimální velikost ethernet frame)

        if (packetSize == 60 && headerSizeTCP < 60)
        {
          ethernetPadding = packetSize - headerSizeTCP;
        }

        print_packet(packetSize, headerSizeTCP, ethernetPadding, buffer); // vypíše hlavičku + obsah paketu

        if (myData->number < 1) // konec sniffování - byl vypsán požadovaný počet paketů
        {
          pcap_breakloop(myData->sniffer[handleId]);
          return;
        }
    }

    // UDP paket
    else if ((protocol == 17 && !myData->tcp && !myData->udp) || (protocol == 17 && myData->tcp && myData->udp) || (protocol == 17 && myData->udp))
    {
        struct udphdr* udph = (struct udphdr*)(buffer + iphLen + myData->linkLayerHeaderSize[myData->snifferNumber]); // UDP hlavička

        // pokud se hledá paket na nějakém portu a port nesedí, přeskočím ho
        if (!myData->port.empty())
        {
          bool isPortFromFilter = false;
          for (unsigned int i = 0; i < myData->port.size(); ++i)
          {
            if (myData->port[i] == ntohs(udph->dest) || myData->port[i] == ntohs(udph->source))
            {
              isPortFromFilter = true;
              break;
            }
          }

          if (!isPortFromFilter) // když neodpovídá port, paket se přeskočí
          {
            return;
          }
        }

        // počítadlo paketů
        if (myData->number == -5) // má se vypsat pouze 1 (nebyl zadán parametr -n)
        {
          myData->number--; // počítadlo paketů
        }
        else if (myData->number == -1)
        {

        }
        else if (myData->number < 1) // konec sniffování - byl vypsán požadovaný počet paketů
        {
          pcap_breakloop(myData->sniffer[handleId]);
          return;
        }
        else
        {
          myData->number--; // počítadlo paketů
        }

        // struktura time_t, vezmu čas přijetí v sekundách
        timestamp = header->ts.tv_sec;

        //strftime vezme strukturu, kterou vrátí funkce localtime a převede ji na string dle požadovaného formátu
        // výsledný čas, délka stringu, formát, localtime převede čas do struktury na sekundy, minuty, ....
        strftime(timeString, sizeof(timeString), "%H:%M:%S", localtime(&timestamp));
        printf("%s.%.6ld ", timeString, header->ts.tv_usec); // tisk času -> HH:MM:SS.US, ts.tv_usec je čas minus tv_sec v microsekundách

        // tisk zbytku prvního řádku
        printf("%s : ", nodeSrc); // IP/DN
        printf("%u > ", ntohs(udph->source)); // zdrojový port
        printf("%s : ", nodeDst); // IP/DN
        printf("%u\n\n", ntohs(udph->dest)); // cílový port

        int headerSizeUDP = myData->linkLayerHeaderSize[myData->snifferNumber] + iphLen + sizeof(udph); // délka hlavičky (zároveň i pointer na data)
        int ethernetPadding = 0; // ethernet padding v případě, kdy je velikost paketu menší než 64B (minimální velikost ethernet frame)

        if (packetSize == 60 && headerSizeUDP < 60)
        {
          ethernetPadding = packetSize - headerSizeUDP;
        }

        print_packet(packetSize, headerSizeUDP, ethernetPadding, buffer); // vypíše hlavičku + obsah paketu

        if (myData->number < 1) // konec sniffování - byl vypsán požadovaný počet paketů
        {
            pcap_breakloop(myData->sniffer[handleId]);
            return;
        }
    }
}

/**
  * Oddělování slov v řetězci pomocí oddělovače bylo inspirováno/převzato a upraveno z:
  *
  * Název článku: Parse (split) a string in C++ using string delimiter (standard C++)
  * Autor odpovědi: hayk.mart
  * Datum odpovědi: Jan 31 '15 at 5:07
  * Odkaz: https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c#comment44856986_14266139
 **/
vector<string> processInterface(string interfaces)
{
  regex format("^[A-Za-z0-9]+(,[A-Za-z0-9]+)*$"); // regulární výraz - formát vstupu

  vector<string> processedInterfaces; // vysledne pole rozhraní

  if(regex_match(interfaces, format))
  {
    size_t wordEnd = 0; // ukazatel na konec slova
    size_t nextWord = 0; // ukazatel na začátek nového slova

    while ((nextWord = interfaces.find(",", wordEnd)) != string::npos) // najdu oddělovač
    {
      // kontrola duplicitních názvů rozhraní
      for (unsigned int i = 0; i < processedInterfaces.size(); ++i)
      {
        if (processedInterfaces[i] == interfaces.substr(wordEnd, nextWord - wordEnd))
        {
          fprintf (stderr, "ERROR: Duplicate interface in argument -i.\n");
          exit(SNIFFER_ERROR_CODE);
        }
      }
      processedInterfaces.push_back(interfaces.substr(wordEnd, nextWord - wordEnd).c_str()); // next - end = delka slova
      wordEnd = nextWord + 1; // posunutí na začátek názvu dalšího rozhraní (za ",")
    }

    // kontrola duplicitních názvů rozhraní
    for (unsigned int i = 0; i < processedInterfaces.size(); ++i)
    {
      if (processedInterfaces[i] == interfaces.substr(wordEnd, nextWord - wordEnd))
      {
        fprintf (stderr, "ERROR: Duplicate interface name in argument -i.\n");
        exit(SNIFFER_ERROR_CODE);
      }
    }

    processedInterfaces.push_back(interfaces.substr(wordEnd).c_str()); // přidání posledního názvu do pole

    return processedInterfaces;
  }
  else
  {
    fprintf (stderr, "ERROR: Wrong interface format!\n");
    exit(SNIFFER_ERROR_CODE);
  }
}

/**
  * Oddělování slov v řetězci pomocí oddělovače bylo inspirováno/převzato a upraveno z:
  *
  * Název článku: Parse (split) a string in C++ using string delimiter (standard C++)
  * Autor odpovědi: hayk.mart
  * Datum odpovědi: Jan 31 '15 at 5:07
  * Odkaz: https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c#comment44856986_14266139
 **/
vector<int> processPorts(string ports)
{
  regex format("^[0-9]{1,5}+(,[0-9]{1,5})*$"); // regulární výraz - formát vstupu

  vector<int> processedPorts; // výsledné pole portů

  if(regex_match(ports, format))
  {
    size_t wordEnd = 0; // ukazatel na konec slova
    size_t nextWord = 0; // ukazatel na začátek nového slova

    while ((nextWord = ports.find(",", wordEnd)) != string::npos) // najdu oddělovač
    {
      processedPorts.push_back(atoi(ports.substr(wordEnd, nextWord - wordEnd).c_str())); // next - end = délka slova
      wordEnd = nextWord + 1; // posunutí na začátek čísla dalšího portu (za ",")
    }

    processedPorts.push_back(atoi(ports.substr(wordEnd).c_str())); // přidání posledního portu do pole

    return processedPorts;
  }
  else
  {
    fprintf (stderr, "ERROR: Wrong port format!\n");
    exit(SNIFFER_ERROR_CODE);
  }
}

void printHelp()
{
  printf("\n ##################################\n\n");
  printf("   IPK Project 2 - Packet Sniffer\n");
  printf("   Author: Tomas Julina\n");
  printf("   Date: 01.05.2020\n");
  printf("\n ##################################\n\n");

  printf("\n Program usage:\n\n");

  printf("   ./ipk-sniffer -i interface[,interface2,…] [-p ¬¬port[,port2,…]] [--tcp|-t] [--udp|-u] [-n num]\n\n where:\n\n");
  printf("    > -i eth0 (interface for sniffing; if missing, list of active interfaces will be printed)\n    > extension: -i enp0s3,lo (sniffing on multiple interfaces at once)\n");
  printf("    > -p 23 (filtering only packets with given ports; if missing, all no port filtering at all)\n    > extension: -p 23,53 (filtering multiple ports at once)\n");
  printf("    > -t or --tcp (filters only TCP packets)\n");
  printf("    > -u or --udp (filters only UDP packets)\n");
  printf("    > if neither -tcp nor -udp is provided, sniffer will print both types\n");
  printf("    > -n 10 (number of packets to be printed; if missing, default value is 1 packet)\n    > extension: if value is \"-1\", infinite number of packets will be printed – need to be stopped manually.\n");
  printf("    > -h or --help (prints this message)\n\n\n");
}

void parse_arguments(int argc, char* argv[], vector<string>* interface, bool* isInterface, vector<int>* port, bool* tcp, bool* udp, int* number)
{
    int c;
    int i;

    struct option long_options[] =
    {
      {"tcp", no_argument, NULL, 't'},
      {"udp", no_argument, NULL, 'u'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:p:tun:h", long_options, NULL)) != -1)
    {
        switch (c)
        {
          case 'i':
            {
              *interface = processInterface(optarg);
              *isInterface = true;
              break;
            }

          case 'p':
            {
              *port = processPorts(optarg);
              break;
            }

          case 't':
            {
              *tcp = true;
              break;
            }

          case 'u':
            {
              *udp = true;
              break;
            }

          case 'h':
            {
              printHelp();
              *interface = vector<string>(); // dealokace paměti, v případě, že s -h byly zadány i další parametry
              *port = vector<int>(); // dealokace paměti, v případě, že s -h byly zadány i další parametry
              exit(0);
            }

          case 'n':
            {
              char* endptr;
              *number = strtol(optarg, &endptr, 10);

              string sizeControl(optarg); // pomocná proměnná pro kontrolu maximální délky hodnoty argumentu
              if (sizeControl.length() > 10)
              {
                fprintf(stderr, "ERROR: Wrong \"-n\" argument or value (maximum is 2147483647).\n");
                exit(SNIFFER_ERROR_CODE);
              }

              if((*endptr == '\0' && *number >= 0) || (*endptr == '\0' && *number == -1))
              {
                break;
              }
              else
              {
                fprintf(stderr, "ERROR: Wrong \"-n\" argument.\n");
                exit(SNIFFER_ERROR_CODE);
              }
              break;
            }

          case '?':
            {
              fprintf(stderr, "ERROR: Unrecognized option.\n");
              exit(SNIFFER_ERROR_CODE);
              break;
            }

          default:
            {
              fprintf(stderr, "ERROR: Wrong argument!\n");
              exit(SNIFFER_ERROR_CODE);
            }

        }
    }

    // neznámé argumenty bez "-"
    for (i = optind; i < argc; i++)
    {
      fprintf(stderr, "ERROR: Unrecognized option.\n");
      exit(SNIFFER_ERROR_CODE);
    }
}

string prepareFilter(struct my_data* data) // poskládá filtr
{
  string filter;

  if (data->tcp && data->udp)
  {
    if (data->port.empty())
    {
      filter.append("tcp or udp");
    }
    else
    {
      for (unsigned int i = 0; i < data->port.size(); ++i)
      {
        filter.append("port ");
        filter.append(to_string(data->port[i]));
        if (i + 1 < data->port.size())
        {
          filter.append(" or ");
        }
      }
    }
  }
  else if (data->tcp && !data->udp)
  {
    if (data->port.empty())
    {
      filter.append("tcp");
    }
    else
    {
      filter.append("tcp ");
      for (unsigned int i = 0; i < data->port.size(); ++i)
      {
        filter.append("port ");
        filter.append(to_string(data->port[i]));
        if (i + 1 < data->port.size())
        {
          filter.append(" or tcp ");
        }
      }
    }
  }
  else if (data->udp && !data->tcp)
  {
    if (data->port.empty())
    {
      filter.append("udp");
    }
    else
    {
      filter.append("udp ");
      for (unsigned int i = 0; i < data->port.size(); ++i)
      {
        filter.append("port ");
        filter.append(to_string(data->port[i]));
        if (i + 1 < data->port.size())
        {
          filter.append(" or udp ");
        }
      }
    }
  }
  else
  {
    if (data->port.empty())
    {
      filter.append("tcp or udp");
    }
    else
    {
      for (unsigned int i = 0; i < data->port.size(); ++i)
      {
        filter.append("port ");
        filter.append(to_string(data->port[i]));
        if (i + 1 < data->port.size())
        {
          filter.append(" or ");
        }
      }
    }
  }
  return filter;
}

/*
  Inspirací pro práci s knihovnou pcap.h byla knihovní dokumentace a návod na stránce tcpdump.org:

  Název článku: Programming with pcap
  Autor článku: Tim Carstens
  Odkaz: https://www.tcpdump.org/pcap.html
*/
int main(int argc, char** argv)
{
    vector<string> interfacesVector; // název rozhraní
    bool isInterface = false; // je/není vybráno rozhraní
    char errBuffer[100]; // buffer pro uložení errorů funkcí knihovny pcap
    string filter; // proměnná pro filtr paketů

    struct my_data myData; // instance struktury s pomocnými daty

    myData.tcp = false;
    myData.udp = false;
    myData.number = -5; // default hodnota, vypíše se jeden paket
    myData.snifferNumber = 0;

    // zpracování vstupních argumentů
    parse_arguments(argc, argv, &interfacesVector, &isInterface, &myData.port, &myData.tcp, &myData.udp, &myData.number);

    // příprava filtru
    filter = prepareFilter(&myData);

    // pouze výpis aktivních rozhraní
    if (!isInterface)
    {
        pcap_if_t* interfaces, *interface;

        // najde všechny použitelné a AKTIVNÍ rozhraní pro pcap_open_live
        if (pcap_findalldevs(&interfaces, errBuffer))
        {
            fprintf(stderr,"ERROR: Couldn't find any interfaces\nREASON:\n %s", errBuffer);
            exit(SNIFFER_ERROR_CODE);
        }

        // výpis zařízení
        for (interface = interfaces; interface != NULL; interface = interface->next)
        {
            printf("%s\n", interface->name);
        }

        pcap_freealldevs(interfaces); // uvolnění paměti

        return 0;
    }

    // Otevření všech zařízení k odchytávání paketů, dle vstupních argumentů
    for (unsigned int i = 0; i < interfacesVector.size(); ++i)
    {
      // pokusí se otevřít rozhraní pro zachytávání paketů
      // název, max délka paketu, 1 = promisc mód (zachytává všechny pakety i když nejsou mířené pro hostitelské zařízení),
      // timeout=200ms (aby se funkce nevolala pro každý paket zvlášť, ale pro více naráz - uloží se do bufferu), error buffer
      pcap_t* pom = pcap_open_live(interfacesVector[i].c_str(), 65536, 1, 200, errBuffer);

      myData.sniffer.push_back(pom);
      myData.snifferNumber = i;

      // nepodařilo se otevřít rozhraní
      if (myData.sniffer[i] == NULL)
      {
          fprintf(stderr, "ERROR: Couldn't open interface %s\nREASON:\n %s\n", interfacesVector[i].c_str(), errBuffer);
          exit(SNIFFER_ERROR_CODE);
      }

      // Zjistí typ hlavičky linkové vrsty a uloží její velikost do vektoru, podporuji Ethernet header a Linux "cooked" capture header
      if (pcap_datalink(myData.sniffer[i]) == DLT_EN10MB)
      {
        myData.linkLayerHeaderSize.push_back(ETHERNET_HEADER);
      }
      else if(pcap_datalink(myData.sniffer[i]) == DLT_LINUX_SLL)
      {
        myData.linkLayerHeaderSize.push_back(LINUX_COOKED_CAPTURE);
      }
      else
      {
        fprintf(stderr, "ERROR: Unsupported header type.\n");

        // uvolnění paměti (uzavře rozhraní)
        for (unsigned int j = 0; j < interfacesVector.size(); ++j)
        {
          pcap_close(myData.sniffer[j]);
        }

        exit(SNIFFER_ERROR_CODE);
      }

      struct bpf_program fp; // proměnná pro uložení zkompilovaného filtru
      bpf_u_int32 mask;	// nepotřebné
      bpf_u_int32 net; // IPv4 netmask našeho zařízení

      if (pcap_lookupnet(interfacesVector[i].c_str(), &net, &mask, errBuffer) == -1) // kvůli proměnné net pro filtrování
      {
        fprintf(stderr, "ERROR: Something went wrong when program attempted to get network number and netmask for a device %s.\nREASON: %s\n", interfacesVector[i].c_str(), errBuffer);

        // uvolnění paměti (uzavře rozhraní)
        for (unsigned int j = 0; j < interfacesVector.size(); ++j)
        {
          pcap_close(myData.sniffer[j]);
        }

        exit(SNIFFER_ERROR_CODE);
      }
      if (pcap_compile(myData.sniffer[i], &fp, filter.c_str(), 0, net) == -1) // kompilace filtru
      {
        fprintf(stderr, "ERROR: Something went wrong during filter compilation.\n");

        // uvolnění paměti (uzavře rozhraní)
        for (unsigned int j = 0; j < interfacesVector.size(); ++j)
        {
          pcap_close(myData.sniffer[j]);
        }

  			exit(SNIFFER_ERROR_CODE);
  		}
		  if (pcap_setfilter(myData.sniffer[i], &fp) == -1) // aplikace filtru na sniffer
      {
        fprintf(stderr, "ERROR: Something went wrong with setting filter.\n");

        // uvolnění paměti (uzavře rozhraní)
        for (unsigned int j = 0; j < interfacesVector.size(); ++j)
        {
          pcap_close(myData.sniffer[j]);
        }
        pcap_freecode (&fp); // uvolnění zkompilovaného filtru z paměti

  			exit(SNIFFER_ERROR_CODE);
		  }
      pcap_setnonblock(myData.sniffer[i], 1, errBuffer); // neblokující mód (kvůli odchytávání na více rozhraní)
      pcap_freecode (&fp); // uvolnění paměti filtru
    }

    // smyčka dokud není vytisknut požadovaný počet paketů
    do
    {
      // neustálé přepínání rozhraními, rozhraní, které bude mít odchycené pakety pro zpracování tyto pakety vytiskne
      for (unsigned int i = 0; i < interfacesVector.size(); ++i)
      {
        if(myData.number > 0 || myData.number == -1 || myData.number == -5) // -1 neomezené množství, -5 pouze jeden paket a konec
        {
          myData.snifferNumber = i; // číslo rozhraní, na kterém byl vypisovaný paket zachycen
          // zpracování zachytávaných paketů
          // handler pro sniffer, -1 = neomezené množství paketů, callback = vlastní funkce zpracovávající jednotlivé pakety, myData = uživatelovi data předávané funkce callback()
          pcap_dispatch(myData.sniffer[i], -1, callback, (u_char*)&myData);
        }
      }
    } while(myData.number >= 1 || myData.number == -1 || myData.number == -5);

    // uvolnění paměti (uzavře rozhraní)
    for (unsigned int j = 0; j < interfacesVector.size(); ++j)
    {
      pcap_close(myData.sniffer[j]);
    }

    return 0;
}
