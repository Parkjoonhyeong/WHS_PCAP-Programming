#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>  // ← ASCII 출력에 필요

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* Destination MAC */
    u_char  ether_shost[6]; /* Source MAC */
    u_short ether_type;     /* Protocol type */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Check if it is an IP packet
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("\n==================================================\n");
        printf("[+] Ethernet Header\n");
        printf("    ▸ Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("    ▸ Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("\n[+] IP Header\n");
        printf("    ▸ Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("    ▸ Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

        // Check for TCP packets
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            printf("\n[+] TCP Header\n");
            printf("    ▸ Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("    ▸ Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // Calculate TCP Payload length and display the first 20 bytes
            int ip_header_len = ip->iph_ihl * 4;
            int tcp_header_len = (tcp->tcp_offx2 >> 4) * 4;
            int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_length = header->caplen - payload_offset;

            printf("\n[+] Payload (First 20 bytes)\n");
            if (payload_length > 0) {
                printf("    ▸ HEX    : ");
                for (int i = 0; i < 20 && i < payload_length; i++) {
                    printf("%02x ", packet[payload_offset + i]);
                }
                printf("\n");

                printf("    ▸ ASCII  : ");
                for (int i = 0; i < 20 && i < payload_length; i++) {
                    char c = packet[payload_offset + i];
                    printf("%c", isprint(c) ? c : '.');
                }
                printf("\n");
            } else {
                printf("    ▸ No Payload\n");
            }
        } else {
            printf("\n[+] Not a TCP Packet (Filtered Out)\n");
        }

        printf("==================================================\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 필터링
    bpf_u_int32 net;

    // 네트워크 인터페이스 열기
    char *dev = "enp0s3";  // 사용 환경에 따라 수정
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // TCP 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "Error compiling filter:");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "Error setting filter:");
        return 1;
    }

    printf("Sniffing on device: %s\n", dev);
    
    // 패킷 캡처 시작
    pcap_loop(handle, 10, got_packet, NULL);

    // 핸들러 종료
    pcap_close(handle);
    return 0;
}
