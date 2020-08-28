#include <pcap.h>
#include <stdio.h>
#include </home/kali/Desktop/libnet-headers.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while(true){
      struct pcap_pkthdr *hd;
      const u_char *pk;
      int res = pcap_next_ex(handle,&hd, &pk);
      if(res == 0) continue;
      if(res == -1 || res == -2) break;
      printf("\n------------------\n");
      // packet
      printf("\nPacket Length: %u\n",hd->caplen); //  Packet Length


      // ethernet
      const struct eth_hdr* pk_eth = (const struct eth_hdr*)pk;
      printf("\n===     MAC     ===\n ");
      printf("SRC MAC: ");
      for (int i = 0; i < ETH_ALEN; ++i) {
          printf("%s%02X", (i ? ":" : ""), pk_eth->src[i]);
      }

      printf("\nDST IP: ");
      for (int i = 0; i < ETH_ALEN; ++i) {
          printf("%s%02X", (i ? ":" : ""), pk_eth->dst[i]);
      }



      // ipv4
      const struct ipv4_hdr *pk_ipv4 = (const struct ipv4_hdr *)pk_eth->data;
      printf("\n\n===     IP      ===\n");
      printf("SRC IP: ");
      for (int i = 0; i < IPV4_ALEN; ++i) {
          printf("%s%d", (i ? "." : ""), pk_ipv4->src[i]);
      }
      printf("\nDST IP: ");
      // - dst
      for (int i = 0; i < IPV4_ALEN; ++i) {
          printf("%s%d", (i ? "." : ""), pk_ipv4->dst[i]);
      }
      uint8_t ihl = IPV4_HL(pk_ipv4);
        if(ihl < IPV4_HL_MIN){
            puts("\n\nInvalid ipv4 packet\n");
            return 2;
        }

      const struct tcp_hdr* pk_tcp = (const struct tcp_hdr*)&pk_ipv4->data[ihl - IPV4_HL_MIN];
      uint16_t length = ntohs(pk_ipv4->length) - ihl;
      printf("\nSRC Port: %d", ntohs(pk_tcp->src));
      printf("\nDST Port: %d\n", ntohs(pk_tcp->dst));


      const char* payload;


      pk_eth = (struct eth_hdr*)(pk);
      pk_ipv4 = (struct ipv4_hdr*)(pk + 14);  // size ethernet 14
      pk_tcp = (struct tcp_hdr*)(pk + 14 + 20); // size ipv4 20

      payload = (char *)(pk + 14 + 20 + 20);




      // Payload
      int payload_len = hd->caplen - (sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) );


      int byte_check = 0; // check byte's number


      if (payload_len == 0){
                  printf("no Payload!");
              }
              else if (payload_len > 0) {
                  printf("\nsize : %d\n", payload_len);
                  if(byte_check >= 16) break;
                  const char *temp_p = payload;
                  int byte_count = 0;
                  printf("Payload -> \n");
                  while (byte_count++ < payload_len) {
                      printf("%02x ", *temp_p); // hex value
                      temp_p++;
                      if (byte_count == 16) break;
                  }
                  byte_check++;
                  printf("\n");
              }



  }
  pcap_close(handle);
  return 0;
}
