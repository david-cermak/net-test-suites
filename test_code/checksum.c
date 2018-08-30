/*
 * Copyright © 2018, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */


//
// Note: this is a test code for tweaking checksum calculation, etc...
//

#include <sys/socket.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>


#define ETH_ALEN	6				/* Octets in one ethernet addr	 */
#define ETH_HLEN	14				/* Total octets in header.	 */
#define ETH_ZLEN	60				/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4				/* Octets in the FCS		 */

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x8600


struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	uint16_t		h_proto;			/* packet type ID field	*/
};



int32_t _cs(void *data, size_t data_len)
{
	int32_t s = 0;

	for ( ; data_len > 1; data_len -= 2, data += 2)
		s += *((uint16_t *) data);

	if (data_len)
		s += *((uint8_t *) data);

	return s;
}

uint16_t cs(int32_t s)
{
	return ~((s & 0xFFFF) + (s >> 16));
}

/* TODO: Refactor this */
uint16_t inet6_chksum(uint8_t *data, size_t data_len)
{
	struct ethhdr *eth = (struct ethhdr *) data;
	struct ip *ip = (struct ip *) (eth + 1);
	struct ip6_hdr *ip6 = (struct ip6_hdr *) (eth + 1);
	struct icmp6_hdr *icmp6;
	struct icmp *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint16_t *sum = NULL;
	uint16_t h_proto = eth->h_proto;
	uint8_t *ipproto = NULL;
	size_t vlan_len = 0;

	if (ntohs(eth->h_proto) == ETHERTYPE_VLAN) {
		ip = (struct ip *) ((void *) ip + 4);
		ip6 = (struct ip6_hdr *) ((void *) ip6 + 4);
		h_proto = *(uint16_t *)
			((void *) eth + sizeof(struct ethhdr) + 2);
		vlan_len = 4;
	}

	h_proto = ntohs(h_proto);

	switch (h_proto) {
	case ETHERTYPE_IP:
		ipproto = &ip->ip_p;
		break;
	case ETHERTYPE_IPV6:
		ipproto = &ip6->ip6_nxt;
		break;
	case ETHERTYPE_ARP:
		goto end;
	default:
		printf("Unsupported ETHERTYPE: 0x%04hx (%hu)", h_proto, h_proto);
	}

	switch (*ipproto) {
	case IPPROTO_TCP:
		if (h_proto == ETHERTYPE_IP) {
			tcp = (struct tcphdr *) (ip + 1);
		} else {
			tcp = (struct tcphdr *) (ip6 + 1);
		}
		sum = &tcp->th_sum;
		break;
	case IPPROTO_UDP:
		if (h_proto == ETHERTYPE_IP) {
			udp = (struct udphdr *) (ip + 1);
		} else {
			udp = (struct udphdr *) (ip6 + 1);
		}
		sum = &udp->uh_sum;
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmp *) (ip + 1);
		sum = &icmp->icmp_cksum;
		if (!(*sum)) {
			if (h_proto == ETHERTYPE_IP) {
				ip->ip_sum = cs(_cs(ip, sizeof(struct ip)));
			}			
			int32_t s = 0;
			s += _cs(data + 14, data_len - 14);
			s = cs(s);
			*sum = s;
		}
		break;
	case IPPROTO_ICMPV6:
		icmp6 = (struct icmp6_hdr *) (ip6 + 1);
		sum = &icmp6->icmp6_cksum;
		break;
	default:
		printf("Unsupported IPPROTO: 0x%04hx (%hu)", ip6->ip6_nxt,
		   ip6->ip6_nxt);
	}

	if (*sum) {
		goto end;
	}

	int32_t s;

	if (h_proto == ETHERTYPE_IP) {
		s = _cs(&ip->ip_src, sizeof(struct in_addr)) * 2;
		// s = _cs(&ip->ip_src, 4 * 2);
	} else {
		s = _cs(&ip6->ip6_src, sizeof(struct in6_addr) * 2);
	}

	if (h_proto == ETHERTYPE_IP) {
		s += htons(ip->ip_p);
		s += htons(data_len - vlan_len - 20 - 14);
	} else {
		s += htons(*ipproto);
		s += ip6->ip6_plen;
	}

	*sum = 0;

	if (h_proto == ETHERTYPE_IP) {
		s += _cs(data + 14 + vlan_len + 20, data_len - vlan_len - 20 - 14);
	} else {
		s += _cs(ip6 + 1, ntohs(ip6->ip6_plen));
	}

	s = cs(s);

	*sum = s;

	if (h_proto == ETHERTYPE_IP) {
		ip->ip_sum = cs(_cs(ip, sizeof(struct ip)));
	}
 end:
	return s;
}

void my_send(char* msg, int data_len)
{
	unsigned char buf[100];
	memcpy(buf, msg, data_len);

	inet6_chksum(buf, data_len);

	
	int i;
	for (i=0; i<data_len; i++) {
		printf("0x%02x ", buf[i]);
	}
	printf("\n");

}

char data[100] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00, 0x00, 
    // 0x1c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0xa7, 0xde, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x08, 0x00, 0x0, 0x00, 0x00, 0x01, 0x00, 0x01
       0x1c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x08, 0x00, 0x0, 0x00, 0x00, 0x01, 0x00, 0x01
// 0x30, 0xae, 0xa4, 0x80, 0x47, 0x75, 0xdc, 0xa9, 0x04, 0x99, 0xf3, 0x82, 0x08, 0x00, 0x45, 0x00, 0x00, 
// 0x1c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x32, 0x8d, 0xc0, 0xa8, 0x04, 0x02, 0xc0, 0xa8, 0x04, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01    
};

int main()
{
	uint16_t *ptr  = (uint16_t *)(data+14);
	uint32_t s = 0;
	for (int i= 0; i<(42-14)/2; i++) {
		s += *ptr++;
	}
	s = cs(s);
	printf("%0x\n",s);

	my_send(data, 42);
	return 0;
}