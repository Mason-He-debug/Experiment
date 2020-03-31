/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifdef _MSC_VER
 /*
  * we do not want the warnings about the old deprecated and unsecure CRT functions
  * since these examples can be compiled under *nix as well
  */
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "pcap.h"
#include <conio.h>
#include <time.h>
 /* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/*定义MAC地址*/
typedef struct ip_mac
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}ip_mac;

/*定义发送方和接收方的MAC地址*/
struct ether_arp {
	u_int8_t arp_tha[6];//目标硬件地址
	u_int8_t arp_sha[6];//发送者硬件地址
};

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
time_t start, now;  //计时
#define FROM_NIC
int main()
{
	
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
#ifdef FROM_NIC

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
		1000,		// read timeout
		NULL,		// remote authentication
		errbuf		// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else

	/* Open the capture file */
	if ((adhandle = pcap_open_offline("E:\\360MoveData\\Users\\asus\\Desktop\\dns.pcap",			// name of the device
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file\n");
		return -1;
	}

	// read and dispatch packets until EOF is reached
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);

#endif
	return 0;
}

int macJudge(int mac1[7], int mac2[7])
{
	int temp = 1;
	for (int i = 0; i < 6; i++)
	{
		if (mac1[i] != mac2[i]) { temp = 0; break; }
	}
	return temp;
}
int ipJudge(int ip1[5], int ip2[5])
{
	int temp = 1;
	for (int i = 0; i < 4; i++)
	{
		if (ip1[i] != ip2[i]) { temp = 0; break; }
	}
	return temp;
}
int macR[1000][7];  //用于纪录mac接受信息
int macS[1000][7];  //用于纪录mac发送信息
int macSSum = 0;
int macRSum = 0;
int ipR[1000][5];  //用于纪录ip接受信息
int ipS[1000][5];  //用于纪录ip发送信息
int ipSSum = 0;
int ipRSum = 0;


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	FILE *fp;
	fp = fopen("log.csv", "a");
	struct tm ltime;
	char timestr[40];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	 * Unused variable
	 */
	(VOID)(param);
	struct ether_arp* arp_protocol;
	arp_protocol = (struct ether_arp*)(pkt_data);
	u_int8_t* arp_tha = arp_protocol->arp_tha;
	u_int8_t* arp_sha = arp_protocol->arp_sha;
	int mactempR[7];
	int mactempS[7];
	for (int i = 0; i < 6; i++)
	{
		mactempR[i] = arp_tha[i];
		mactempS[i] = arp_sha[i];
	}
	mactempR[6] = header->len;
	mactempS[6] = header->len;
	int mr = 0; int ms = 0;
	for (int i = 0; i < macSSum; i++)
	{
		if (macJudge(mactempS, macS[i])) { macS[i][6] = macS[i][6] + mactempS[6]; ms = 1; break; }
	}
	for (int i = 0; i < macRSum; i++)
	{
		if (macJudge(mactempR, macR[i])) { macR[i][6] = macR[i][6] + mactempR[6]; mr = 1; break; }
	}
	if (!ms) {
		for (int i = 0; i < 7; i++)
			macS[macSSum][i] = mactempS[i];
		macSSum++;
	}
	if (!mr) {
		for (int i = 0; i < 7; i++)
			macR[macRSum][i] = mactempR[i];
		macRSum++;
	}
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	fprintf(fp,"%s,", timestr);
	printf("%s,", timestr);

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		14); //length of ethernet header

	int iptempR[5];
	int iptempS[5];
	iptempS[0] = ih->saddr.byte1;
	iptempS[1] = ih->saddr.byte2;
	iptempS[2] = ih->saddr.byte3;
	iptempS[3] = ih->saddr.byte4;

	iptempR[0] = ih->daddr.byte1;
	iptempR[1] = ih->daddr.byte2;
	iptempR[2] = ih->daddr.byte3;
	iptempR[3] = ih->daddr.byte4;

	iptempR[4] = header->len;
	iptempS[4] = header->len;
	int ir = 0; int is = 0;
	for (int i = 0; i < ipSSum; i++)
	{
		if (ipJudge(iptempS, ipS[i])) { ipS[i][4] = ipS[i][4] + iptempS[4]; is = 1; break; }
	}
	for (int i = 0; i < ipRSum; i++)
	{
		if (ipJudge(iptempR, ipR[i])) { ipR[i][4] = ipR[i][4] + iptempR[4]; ir = 1; break; }
	}
	if (!is) {
		for (int i = 0; i < 5; i++)
			ipS[ipSSum][i] = iptempS[i];
		ipSSum++;
	}
	if (!ir) {
		for (int i = 0; i < 5; i++)
			ipR[ipRSum][i] = iptempR[i];
		ipRSum++;
	}

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	fprintf(fp,"%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d,%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d",
		*arp_sha, *(arp_sha + 1), *(arp_sha + 2), *(arp_sha + 3), *(arp_sha + 4), *(arp_sha + 5),
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		*arp_tha, *(arp_tha + 1), *(arp_tha + 2), *(arp_tha + 3), *(arp_tha + 4), *(arp_tha + 5),
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	printf("%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d,%02x-%02x-%02x-%02x-%02x-%02x,%d.%d.%d.%d",
		*arp_sha, *(arp_sha + 1), *(arp_sha + 2), *(arp_sha + 3), *(arp_sha + 4), *(arp_sha + 5),
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		*arp_tha, *(arp_tha + 1), *(arp_tha + 2), *(arp_tha + 3), *(arp_tha + 4), *(arp_tha + 5),
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	ih = (ip_header*)(pkt_data + 14);
	fprintf(fp,",%d \n", header->len);
	printf(",%d \n", header->len);
	if (header->len > 1024)printf("%s\n", "Warning: Transmission over 1024.");
	now = time(NULL);
	fclose(fp);
}