#include <stdio.h>
#include <string.h>
#include <time.h>
#include "GeoIP.h"
#include "pcap.h"

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    union{
        ip_address  saddr;      // Source address
        u_int32_t saddrint;
    };
    union{
        ip_address  daddr;      // Destination address
        u_int32_t daddrint;
    };
    u_int   op_pad;         // Option + Padding
}ip_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
char *iptos(u_long in);

/* geoip */
static GeoIP * gi;
static char arg_outside = 0;
static int country_id_target = 0;

/* pcap handle */
static pcap_t *adhandle;

/* Anti-repeatsend list */
#define SENDLISTSIZE 1024
static u_int32_t sendlist[SENDLISTSIZE+1];
static u_short sendlist_head = 0;

/* if we're built against a version of geoip-api-c that doesn't define this,
 * the flag should be harmless (as long as it doesn't clash with another
 * flag using the same bit position). */
#ifndef GEOIP_SILENCE
#define GEOIP_SILENCE		16
#endif

int main(int argc, char *argv[])
{
    int arg_count;
    int arg_inum=0;
    char arg_country[8] = "CN";
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    pcap_addr_t *a;
    char packet_filter[0xffff] = {0};
    struct bpf_program fcode;
    int result = 0;

    if (argc > 1)
    {
//        if(argc != 5)
//        {
//            printf("\nThe command had no other arguments.\n");
//            return -1;
//        }
        for (arg_count = 1; arg_count < argc; arg_count++)
        {
            if(strcmp(argv[arg_count], "-i") == 0)
                arg_inum = atoi(argv[arg_count+1]);

            if(strcmp(argv[arg_count], "-c") == 0)
                strcpy(arg_country, argv[arg_count+1]);

            if(strcmp(argv[arg_count], "-o") == 0)
                arg_outside = 1;
        }
        printf("the interface number(-i): %d\n", arg_inum);
    }

    /* Init GeoIP */
    _GeoIP_setup_dbfilename();
    if(!GeoIP_db_avail(GEOIP_COUNTRY_EDITION))
    {
        printf("\nGeoIP_db_avail Error.\n");
        return -1;
    }
    gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD | GEOIP_SILENCE);
    if (NULL == gi) {
        printf("\nGeoIP_open_type Error.\n");
        return -1;
    }
    gi->charset = GEOIP_CHARSET_UTF8;
    if(!(country_id_target = GeoIP_id_by_code(arg_country))){
        printf("\nGeoIP_id_by_code Error.\n");
        return -1;
    }
    printf("country_id_target: %d\n", country_id_target);

    /* Retrieve the device list */
#ifdef _WIN32
    result = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
#elif __unix
    result = pcap_findalldevs(&alldevs, errbuf);
#endif
    if (result == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        else
            printf(" (No description available)");
        if (d->addresses)
        {
            printf("\nIP: [");
            struct pcap_addr *taddr;
            struct sockaddr_in *sin;
            char  revIP[100];
            for (taddr = d->addresses; taddr; taddr = taddr->next)
            {
                sin = (struct sockaddr_in *)taddr->addr;
                if (sin->sin_family == AF_INET){
                    strcpy(revIP, inet_ntoa(sin->sin_addr));
                    printf("%s", revIP);
                    if (taddr->next)
                        putchar(',');
                }
            }
            putchar(']');
        }
        putchar('\n');
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    if (arg_inum == 0)
    {
        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &arg_inum);
    }

    if(arg_inum < 1 || arg_inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< arg_inum-1 ;d=d->next, i++);

    /* Open the adapter */
#ifdef _WIN32
    adhandle= pcap_open(d->name,  // name of the device
                                  65536,     // portion of the packet to capture.
                                  // 65536 grants that the whole packet will be captured on all the MACs.
                                  PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                                  1000,      // read timeout
                                  NULL,      // remote authentication
                                  errbuf     // error buffer
                                  );
#elif __unix
    adhandle= pcap_open_live(d->name,  // name of the device
                                  65536,     // portion of the packet to capture.
                                  // 65536 grants that the whole packet will be captured on all the MACs.
                                  1,         // promiscuous mode
                                  1000,      // read timeout
                                  errbuf     // error buffer
                                  );
#endif
    if ( adhandle == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
#ifdef _WIN32
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
#elif __unix
        netmask=0xffffff;
#endif
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;

    //build the filter
    strcat(packet_filter, "ip");
    for(a=d->addresses;a;a=a->next) {
        if(a->addr->sa_family == AF_INET && a->addr)
        {
            strcat(packet_filter, " src ");
            strcat(packet_filter, iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        }
    }
    strcat(packet_filter, " and not (tcp[tcpflags] & tcp-syn != 0)");
    printf("packet_filter: %s\n", packet_filter);

    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[16];
    ip_header *ih;
    u_int ip_len;
    time_t local_tv_sec;
    u_int ide_crc;

    int country_id;
    const char *country_code;

    int i;

    /*
     * Unused variable
     */
    (void)(param);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

    ide_crc = ih->crc + (ih->identification << 16);
    for(i=0; i < SENDLISTSIZE; ++i)
        if(sendlist[i] == ide_crc)
            return;

    /* geoip */
    country_id = GeoIP_id_by_ipnum(gi, ntohl(ih->daddrint));
    country_code = GeoIP_country_code[country_id];
    //dst is n/a
    if(country_id == 0)
        return;
    //dst is not china
    if(arg_outside && (country_id != country_id_target))
        return;
    //dst is china
    else if((!arg_outside) && (country_id == country_id_target))
        return;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = *localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    /* print timestamp and length of the packet */
    printf("%s.%.6d LEN:%03x ", timestr, header->ts.tv_usec, header->len);
    printf("IDX:%03x IDECRC:%08x ", sendlist_head, ide_crc);

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;

    /* print ip addresses and udp ports */

    printf("DST:[%s] %d.%d.%d.%d\n",
           country_code,
           ih->daddr.byte1,
           ih->daddr.byte2,
           ih->daddr.byte3,
           ih->daddr.byte4
           );

    /* Send down the packet */
    sendlist[sendlist_head++] = ide_crc;
    if(sendlist_head > SENDLISTSIZE)
        sendlist_head = 0;

    if (pcap_sendpacket(adhandle, pkt_data, header->caplen /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
        return;
    }
}

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
