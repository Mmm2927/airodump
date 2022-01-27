#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <map>
#include <string>

#include <iostream>

#include "airodump.h"

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump mon0\n");
}

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_map(std::map<std::string, int>& m) {
    for (std::map<std::string, int>::iterator itr = m.begin(); itr != m.end(); ++itr) {
        std::cout << itr->first << " " << itr->second << std::endl;
    }
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
	
	std::map<std::string, unsigned int> ssid_list;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		struct ieee80211_radiotap_header radio;
		memcpy(&radio, packet, sizeof(ieee80211_radiotap_header));
		//u_int8_t type = htons(*(packet+radio.it_len));
		u_int8_t type = *(packet+radio.it_len);
		if(*(packet+radio.it_len) != 0x80)	{
			continue;
		}
		struct ieee80211_beacon_hdr beacon;
		memcpy(&beacon, packet+radio.it_len, sizeof(ieee80211_beacon_hdr));
		//u_int32_t tags_size = header->caplen - radio.it_len - sizeof(ieee80211_beacon_hdr)+sizeof(std::list<tagged_param>);
		u_int32_t tags_size = header->caplen - radio.it_len - 36;

		//std::map<char*, int> ssid_list;
		char *ssid;	
		std::string ssid_name;
		while(tags_size >0){
			int8_t tag_size = (int8_t)*(packet+header->caplen-tags_size+1);
			if((u_int8_t)*(packet+header->caplen-tags_size) == SSID_PARAMETER_SET){
				ssid = (char*)malloc(tag_size+1);
				memcpy(ssid, packet+header->caplen-tags_size+2, tag_size);
				
				ssid[tag_size] = '\0';

				ssid_name.assign(ssid, tag_size);
				
				if (ssid_list.count(ssid_name)) {
        				ssid_list[ssid_name] += 1;
    				}
				else {
					ssid_list[ssid_name] = 1;
				}
				
			}
			//DumpHex(packet+header->caplen-tags_size+1, tags_size-1);
			tags_size -= tag_size + 2;
		}
		printf("SSID : %s\n", ssid);
		printf("BSS ID : %02X::%02X::%02X::%02X::%02X::%02X\n",
				beacon.addr3[0],
				beacon.addr3[1],
				beacon.addr3[2],
				beacon.addr3[3],
				beacon.addr3[4],
				beacon.addr3[5]);
		printf("beacons %d\n\n", ssid_list[ssid_name]);
		free(ssid);
	}
		
	
	pcap_close(pcap);
}
