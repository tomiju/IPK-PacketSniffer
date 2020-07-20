/**
  * IPK Project 2 - Sniffer paketů
  * Autor: Tomáš Julina (xjulin08)
  * Datum: 01.05.2020
  * Soubor: ipk-sniffer.hpp
 **/

// C knihovny
#include <stdlib.h> // exit()
#include <getopt.h> // zpracování vstupních argumentů
#include <pcap.h> // sniffing
#include <sys/socket.h> // sockaddr
#include <netdb.h> // getnameinfo()
#include <netinet/udp.h> // deklarace UDP hlavičky
#include <netinet/tcp.h> // deklarace TCP hlavičky
#include <netinet/ip.h>	// deklarace IPv4 hlavičky
#include <netinet/ip6.h> // deklarace IPv6 hlavičky
#include <stdbool.h> // bool
#include <limits.h> // INT_MAX
#include <time.h> // timestamps
#include <arpa/inet.h> // inet_ntop

// C++ knihovny
#include <iostream>
#include <regex> // regex (rozpětí portů)
#include <vector> // vectory
#include <string> // string
#include <map> // hashovací mapa pro cache DNS

using namespace std;

// Konstanty
#define LINUX_COOKED_CAPTURE 16 // velikost linux "cooked" capture hlavičky (pro rozhraní any)
#define ETHERNET_HEADER 14 // velikost ethernetové hlavičky
#define SNIFFER_ERROR_CODE 1

/**
  * Funkce, která zpracuje vstupní parametry pomocí getopt() a naplní pomocné proměnné ve struktuře my_data
  * @PARAM: int argc počítadlo argumentů programu
  * @PARAM: char* argv[] pole s argumenty programu
  * @PARAM: char** interface název vybraného rozhraní (pokud je is_interface == true)
  * @PARAM: bool* is_interface pomocná proměnná podle které se buď provádí sniffování, nebo se vypíší dostupná zařízení
  * @PARAM: int* port volitelné číslo portu
  * @PARAM: bool* tcp volitelná možnost hledat pouze TCP pakety
  * @PARAM: bool* udp volitelná možnost hledat pouze UDP pakety
  * @PARAM: int* number volitelné množství vypsaných paketů
 **/
void parse_arguments(int argc, char* argv[], vector<string>* interface, bool* isInterface, vector<int>* port, bool* tcp, bool* udp, int* number);

/**
  * Funkce, která je volána při přijetí každého paketu funkcí pcap_loop()
  * @PARAM: u_char* uživatelovi data (konkrétně instance struktury my_data obsahující vše potřebné)
  * @PARAM: const struct pcap_pkthdr* hlavička paketu
  * @PARAM: const u_char* buffer s daty paketu
 **/
void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

/**
  * Pomocná funkce, která nejprve na základě velikosti IP + ETH + UDP/TCP hlavičky
  * vytiskne "hlavičku" paketu a poté datový obsah paketu (pokud nějaký je)
  * @PARAM: int packetSize velikost zachycené paketu
  * @PARAM: int headerSize velikost hlavičky paketu (ETH + IP + UDP/TCP)
  * @PARAM: int ethernetPadding případná velikost ethernetového paddingu (default = 0)
  * @PARAM: const u_char* buffer všechna data paketu
 **/
void print_packet(int packetSize, int headerSize, int ethernetPadding, const u_char* buffer);

/**
  * Funkce zpracuje vstupní argument rozhraní, může být zadáno i více rozhraní (rozšíření) - formát "rozhrani1,rozhrani2"
  * Formát je kontrolován regulárním výrazem, jednotlivé výrazy oddělím tak, že hledám čárku a poté pomocí funkce substr
  * uložím do vectoru název rozhraní
  * @PARAM: string interfaces proměnná s daty ze vstupu
  * @RETURN: vector<string> pole s rozparsovanými názvy rozhraní
 **/
vector<string> processInterface(string interfaces);

/**
  * Funkce zpracuje vstupní argument portů, může být zadáno i více portů (rozšíření) - formát "port1,port2"
  * Formát je kontrolován regulárním výrazem, jednotlivé výrazy oddělím tak, že hledám čárku a poté pomocí funkce substr
  * uložím do vectoru název rozhraní (viz. funkce processInterface)
  * @PARAM: int ports proměnná s daty ze vstupu
  * @RETURN: vector<int> pole s rozparsovanými čísly portů
 **/
vector<int> processPorts(int ports);

/**
  * Funkce, která na základě vstupních argumentů poskládá filtr pro odchytávání paketů
  * @PARAM: struct my_data struktura obsahující rozparsované vstupní argumenty
  * @RETURN: string poskládaný filtr
 **/
string prepareFilter(struct my_data data);

/**
  * Vytiskne nápovědu a ukončí program
 **/
void printHelp();

/**
  * Pomocná struktura obsahující veškeré zpracované data ze vstupních argumentů programu (pro předání callback funkci)
 **/
struct my_data
{
    vector<int> port; // číslo portu
    bool tcp; // filtrovat TCP pakety
    bool udp; // filtrovat UDP pakety
    int number; // počet paketu k vypsání
    vector<pcap_t*> sniffer; // handler pro sniffer
    int snifferNumber; // číslo konkrétního snifferu
    vector<int> linkLayerHeaderSize; // pole s velikostmi ethernetové/linux cooked hlavičky, 14 = ETHERNET HEADER, 16 = LINUX "COOKED" CAPTURE HEADER
    map<string,string> DNScache; // cache pro překlad DN (aby se nepřekládalo již přeložené)
};
