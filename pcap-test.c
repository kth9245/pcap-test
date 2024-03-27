#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
	u_int16_t ether_type;  
} libnet_ethernet_hdr;

typedef struct {
    u_int8_t ip_hl:4,       /* version */
           ip_v:4;        /* header length */
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4]; /* source and dest address */
} libnet_ipv4_hdr;

typedef struct {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t off;
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
} libnet_tcp_hdr;

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
} 

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		
		libnet_ethernet_hdr* eth_hdr = packet;
		libnet_ipv4_hdr* ip_hdr = packet + 14;
		libnet_tcp_hdr* tcp_hdr = packet + 14 + 4*ip_hdr->ip_hl;
		
		if(ip_hdr->ip_p != 0x06){
			continue;
		}
		printf("Mac\n\tSrc ");
		for (int i=0; i<5; i++){
			printf("%x:", eth_hdr->ether_shost[i]);
		}
		printf("%x -> ", eth_hdr->ether_shost[5]);
		printf("Dst ");
		for (int i=0; i<5; i++){
			printf("%x:", eth_hdr->ether_dhost[i]);
		}
		printf("%x\n", eth_hdr->ether_dhost[5]);
		if(ntohs(eth_hdr->ether_type) == 0x0800){
			printf("IP\n");
			printf("\tSrc ");
			for (int i=0; i<3; i++){
				printf("%u:", ip_hdr->ip_src[i]);
			}
			printf("%u -> ", ip_hdr->ip_src[3]);
			printf("Dst ");
			for (int i=0; i<3; i++){
				printf("%u:", ip_hdr->ip_dst[i]);
			}
			printf("%u\n", ip_hdr->ip_dst[3]);
			if(ip_hdr->ip_p == 0x06){
				printf("TCP\n");
				printf("\tSrc Port : %u -> Dst Port : %u\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
				int data_len = header->caplen - 14 - 4*ip_hdr->ip_hl - 4*(tcp_hdr->off>>4);
				if(data_len > 0){
					printf("DATA\n\t");
					char *data = packet + (header->caplen - data_len);
					if (data_len > 20) data_len = 20;
					for(int i = 0; i < data_len; i++ ){
						printf("%02x ", data[i]);
					}
					printf("\n");
				}
			}
		}
		printf("\n");
	}

	pcap_close(pcap);
}
