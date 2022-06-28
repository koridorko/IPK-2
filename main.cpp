/*
@author : Stefan Gajdosik <xgajdo30>
@file   : main.cpp 
@brief  : Simple packet sniffer for IPK subject
*/


// C++ libs
#include <iostream>
#include <ctime>

// libs for working with packets, net, etc
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

//basic C libs for arg parsing and work with C-string
#include <getopt.h>
#include <string.h>

char * ERR_BUFFER;

// default filter for 4 types of packets we have to catch
std::string filter = "udp or tcp or arp or icmp";

// default number of packets to catch
int NUMBER_OF_PACKETS = 1;

// for filter string
bool ALL_PORTS = true;

// to change filter string if port is added
std::string PORT;

// boolean value to know if we have to change filter
// according to argv
bool CHANGE_IN_FILTER_REQUIRED = false;

// to know if we take only some kind of packets
// if yes, we will specify it later, else all other packets are true
bool SPECIFICATION = false;

// to check if interface is added or we have to print all
bool INTERFACE_ADDED = false;
std::string INTERFACE = "";


// boolean values for filter
bool TCP = false;
bool UDP = false;
bool ARP = false;
bool ICMP = false;


/// start of program
/// ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

/*
/ @brief function for printing all interfaces and exiting program
*/
void get_and_print_all_interfaces(){
    pcap_if_t * interface_list, *device;

    if(pcap_findalldevs(&interface_list, ERR_BUFFER) == -1){
        printf("%s", ERR_BUFFER);
        exit(EXIT_FAILURE);
    }
    else{
        std::cout << "ALL INTERFACES:" <<std::endl;
        for(device = interface_list; device; device = device->next){
            std::cout << device->name << std::endl;
        }
    }
    pcap_freealldevs(interface_list);
}

// Helper function for determining if filter is empty string
bool changed(std::string actual){
    return (actual != ""); 
}

/*
/ @brief function for creating filter string to filter kinds of packets
/
*/
void create_filter(){
    std::string new_filter = "";

    if(!ALL_PORTS && !SPECIFICATION){
        new_filter = (std::string("arp or icmp or ") + std::string("(udp port ") + PORT + ")" + std::string(" or (tcp port " + PORT + ")"));
    }

    if(SPECIFICATION){
        if (UDP && !ALL_PORTS){
            new_filter += "(udp and port " + PORT + " )";
        }
        else if(UDP && ALL_PORTS){
            new_filter += "udp";
        }
        if (ARP){
            if (changed(new_filter)) new_filter += " or ";
            new_filter += " arp";
        }
        if(ICMP){
            if(changed(new_filter))new_filter += " or ";
            new_filter += " icmp ";
        }
        if (TCP && !ALL_PORTS){
            if (changed(new_filter)) new_filter += " or ";
            new_filter += "(tcp and port " + PORT + " )";
        }
        else if(TCP && ALL_PORTS){
            if (changed(new_filter)) new_filter += " or ";
            new_filter += "tcp";
        }
        
    }

    filter = new_filter;
    
}

// Function to print timestamp in correct format
//inspiration from https://www.programiz.com/cpp-programming/library-function/ctime/gmtime
void get_time(const time_t * seconds, const time_t * miliseconds){
    tm *tm_gmt = localtime(seconds);
    std::cout << "timestamp: ";
    std::cout << tm_gmt->tm_year + 1900;
    std::cout << "-";
    std::cout << tm_gmt->tm_mon;
    std::cout << "-";
    std::cout << tm_gmt->tm_mday;
    std::cout << "T";
    std::cout << tm_gmt->tm_hour;
    std::cout << ":";
    std::cout << tm_gmt->tm_min;
    std::cout << ":";
    std::cout << tm_gmt->tm_sec;
    std::cout << ".";
    std::cout << (long)miliseconds << " " << tm_gmt->tm_zone <<std::endl;
}


/// printing ARP IP adress (src/dest)
void print_arp_IP(u_int8_t *ipsource, u_int8_t *ipdestination){
    printf("src IP: ");
    for(int i = 0; i <4; i++){
        //last part of MAC (no ":")
        if(i == 3) printf("%u\n", ipsource[i]); 
        else printf("%u:", ipsource[i]);
    }
    printf("dst IP: ");
    for(int i = 0; i <4; i++){
        //last part of MAC (no ":")
        if(i == 3) printf("%u\n", ipdestination[i]); 
        else printf("%u:", ipdestination[i]);
    }

}


/// i understood how inet_ntoa works thanks to https://stackoverflow.com/questions/6530578/what-are-addresses-of-type-in-addr-t-inet-ntoa-etc
void print_ipv4_IP(uint32_t source, uint32_t destination){
    printf("src IP: ");
    struct in_addr src = {source};
    printf("%s\n", inet_ntoa(src));

    printf("dst IP: ");
    struct in_addr dst = {destination};
    printf("%s\n", inet_ntoa(dst));
}


// found function for printing https://man7.org/linux/man-pages/man3/inet_ntop.3.html?fbclid=IwAR092i5b10QlQbid1_wbS1WM97TCUfNNO2MLPB1vrVyZqu4TPGRUU_-7t6w
void print_ipv6_IP(in6_addr source, in6_addr destination){
    printf("src IP: ");
    char src[50];
    inet_ntop(AF_INET6, &source, src, 50);
    printf("%s\n", src);

    printf("dst IP: ");
    char dest[50];
    inet_ntop(AF_INET6, &destination, dest, 50);
    printf("%s\n", dest);
}


/// printing MAC adress (src/dest)
void print_MAC(u_int8_t * macsource, u_int8_t *macdestination){
    printf("src MAC: ");
    for(int i = 0; i <6; i++){
        //last part of MAC (no ":")
        if(i == 5) printf("%02x\n", macsource[i]); 
        else printf("%02x:", macsource[i]);
    }
    printf("dst MAC: ");
    for(int i = 0; i <6; i++){
        //last part of MAC (no ":")
        if(i == 5) printf("%02x\n", macdestination[i]); 
        else printf("%02x:", macdestination[i]);
    }
}

/// inspiration from https://www.devdungeon.com/content/using-libpcap-c
void packet_parsing(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
    
    unsigned char ETHERNET_OFFSET = 14;
    /// ofset from https://cs.wikipedia.org/wiki/IPv4
    unsigned char ipv4_OFFSET = 20;
    unsigned char ipv6_OFFSET = 40;
    struct ether_header *eth_header;
    struct ether_arp * arp;
    struct iphdr * ipv4;
    struct tcphdr * tcp;
    struct udphdr * udp;
    struct icmphdr *icmp;
    struct ip6_hdr *ipv6;
    struct icmp6_hdr *icmp_6;

    eth_header = (struct ether_header *) packet;
    
    // timestamp of packet
    get_time(&header->ts.tv_sec, &header->ts.tv_usec);


    switch (ntohs(eth_header->ether_type))
    {
    case ETHERTYPE_ARP:
        arp = (struct ether_arp*) (packet + ETHERNET_OFFSET);
        print_MAC(arp->arp_sha, arp->arp_tha);
        printf("frame length: %d bytes\n", header->len);
        print_arp_IP(arp->arp_spa, arp->arp_tpa);
        break;

    case ETHERTYPE_IP:
        ipv4 = (struct iphdr *) (packet + ETHERNET_OFFSET);
        print_MAC(eth_header->ether_shost, eth_header->ether_dhost);
        printf("frame length: %d bytes\n", header->len);
        print_ipv4_IP(ipv4->saddr, ipv4->daddr);
        
        /// numbers from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        switch (ipv4->protocol)
        {
        /// ICMP
        case 1:
            icmp = (struct icmphdr *) (packet + ETHERNET_OFFSET + ipv4_OFFSET);
            break;
        /// TCP
        case 6:
            tcp = (struct tcphdr *) (packet + ETHERNET_OFFSET + ipv4_OFFSET);
            printf("src port: %hu\n", ntohs(tcp->th_sport));
            printf("dst port: %hu\n", ntohs(tcp->th_dport));
            break;
        /// UDP
        case 17:
            udp = (struct udphdr *) (packet + ETHERNET_OFFSET + ipv4_OFFSET);
            printf("src port: %hu\n", ntohs(udp->uh_sport));
            printf("dst port: %hu\n", ntohs(udp->uh_dport));
            break;
        
        default:
            break;
        }
        break;
    case ETHERTYPE_IPV6:
        ipv6 = (struct ip6_hdr *) (packet + ETHERNET_OFFSET);
        print_MAC(eth_header->ether_shost, eth_header->ether_dhost);
        printf("frame length: %d bytes\n", header->len);
        print_ipv6_IP(ipv6->ip6_src, ipv6->ip6_dst);

        // Next header - protocol number
        switch (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
        {
        /// TCP
        case 6:
            tcp = (struct tcphdr *) (packet + ETHERNET_OFFSET + ipv6_OFFSET);
            printf("src port: %hu\n", ntohs(tcp->th_sport));
            printf("dst port: %hu\n", ntohs(tcp->th_dport));
            break;
        /// UDP
        case 17:
            udp = (struct udphdr *) (packet + ETHERNET_OFFSET + ipv6_OFFSET);
            printf("src port: %hu\n", ntohs(udp->uh_sport));
            printf("dst port: %hu\n", ntohs(udp->uh_dport));
            break;

        /// ICMP_V6
        case 58:
            icmp_6 = (struct icmp6_hdr *) (packet + ETHERNET_OFFSET + ipv6_OFFSET);

            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    printf("\n");
    

    int new_line = 15;
    // first number of bytes, just for more simplycity of printing
    printf("0x0000: ");
    for (int i = 0; i < header->len; i++){

        if(i % 8 == 0 && i +1 % 15 != 0){
            printf(" ");
        }
        // printing hexa value of byte
        printf("%02x ", packet[i]);


        if(new_line == i){
            for(int j = i-15; j <= i; j++ ){
                if(j % 8 == 0){
                    printf("  ");
                }
                if(!isprint((unsigned char)packet[j])){
                    printf(".");
                }
                else{
                    printf("%c", (unsigned char)packet[j]);
                }
            }
            new_line += 16;
            printf("\n");
            }
        
        if(i + 1 == header->len){
            /// part of padding from spaces between every eigthth num
            printf("  ");
            for(int k = i; k < new_line;k++){
                //pading for alignment
                printf("   ");
            }
            for(int j = i-(i%16); j <= i; j++ ){
                if(j% 8 == 0){
                    printf(" ");
                }
                if(!isprint((unsigned char)packet[j])){
                    printf(".");
                }
                else{
                    printf("%c", (unsigned char)packet[j]);
                }
            }
            printf("\n");
        }
        if(i == new_line -16){
            printf("0x%04x: ", i + 1);
        }
        
    }
    printf("\n");printf("\n");
}




int main(int argc, char ** argv){



    /// instpiration from https://stackoverflow.com/questions/22464891/specify-long-command-line-arguments-without-the-short-format-getopt
    /// not stolen code, but understanding of concept
    const struct option longopts[] =
  {
    {.name = "tcp", no_argument, 0,'t'},
	{.name = "udp", no_argument, 0, 'u'},
    {.name = "icmp", no_argument, 0, 'w'},
    {.name = "arp", no_argument, 0,'z'},
    {.name = "interface", required_argument, 0, 'i'},
    {0,0,0,0}
  };
    int index;
    int arg = 0;


    /// parsing of argv
    while(arg != -1)
  {
    arg = getopt_long(argc, argv, "i:p:tun:", longopts, &index);
    switch (arg)
    {
      case 'i':
        INTERFACE_ADDED = true;
        INTERFACE = optarg;
        break;

      case 'p':
        ALL_PORTS = false;
        PORT = optarg;
        CHANGE_IN_FILTER_REQUIRED = true;
        break;

      case 't':
        SPECIFICATION = true;
        TCP = true;
        CHANGE_IN_FILTER_REQUIRED = true;
        break;

        case 'u':
        SPECIFICATION = true;
        UDP = true;
        CHANGE_IN_FILTER_REQUIRED = true;
        break;

        case 'w':
        SPECIFICATION = true;
        ICMP = true;
        CHANGE_IN_FILTER_REQUIRED = true;
        break;

        case 'z':
        SPECIFICATION = true;
        ARP = true;
        CHANGE_IN_FILTER_REQUIRED = true;
        break;

        case 'n':
        NUMBER_OF_PACKETS = std::stoi(optarg);
        break;
    }
  }

    // if no specification
    // sniffing all types of packets
    if (SPECIFICATION != true){
        TCP = true;
        UDP = true;
        ARP = true;
        ICMP = true;
    }
    
    /// Writing all avalible interfaces and exiting program
    if(!INTERFACE_ADDED){
        get_and_print_all_interfaces();
        return 0;
    }


    /// code inspiration and understantment of pcap_open_live & pcap_compile & pcap_setfilter
    /// from https://www.tcpdump.org/pcap.html
    pcap_t *handle;
    const char * Interface = INTERFACE.c_str();
    // char[] for packet
    const u_char *packet;
    // ethernet header	
    struct pcap_pkthdr header;	

    struct bpf_program fp;
    bpf_u_int32 net;

    // creating of filter
    if(CHANGE_IN_FILTER_REQUIRED){
        create_filter();
    }
    const char * filter_buffer = filter.c_str();

    // opening interface
    handle = pcap_open_live(Interface, BUFSIZ, 1, 1000, ERR_BUFFER);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", Interface, ERR_BUFFER);
    	return(EXIT_FAILURE);
    }
    /// compilation of filter
    if (pcap_compile(handle, &fp, filter_buffer, 0, net) == -1) {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_buffer, pcap_geterr(handle));
    	return(EXIT_FAILURE);
    }
    /// seting filter to interface
    if (pcap_setfilter(handle, &fp) == -1) {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_buffer, pcap_geterr(handle));
    	return(EXIT_FAILURE);
    }

    // end of inspired code
    /////////////////////////////////////////////////
    
    /////////////////////////////////////////////////
    //                Alternative ?                //
    //for(unsigned i = 0; i <NUMBER_OF_PACKETS; i++){
	//packet = pcap_next(handle, &header);
	/////////////////////////////////////////////////
    
    pcap_loop(handle, NUMBER_OF_PACKETS, packet_parsing, NULL);

    pcap_close(handle);


    return 0;
}



