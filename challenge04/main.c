/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017 Hiroki SHIROKURA All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_byteorder.h>

enum eth_type {
  eth_ipv4 = 0x0800,
  eth_arp  = 0x0806,
  eth_ipv6 = 0x86dd,
};

struct eth_hdr {
  uint8_t  dst[6];
  uint8_t  src[6];
  uint16_t type;
} __attribute__((__packed__));

enum ip_proto {
  ipproto_icmp = 1,
  ipproto_tcp  = 6,
  ipproto_udp  = 17,
};

struct ip4_hdr {
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t totlen;
  uint16_t id;
  uint16_t flag_off;
  uint8_t  ttl;
  uint8_t  proto;
  uint16_t checksum;
  uint8_t  src[4];
  uint8_t  dst[4];
} __attribute__((__packed__));

struct udp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t cksum;
} __attribute__((__packed__));

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((__packed__));

struct resrec {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t len;
} __attribute__((__packed__));

static struct rte_mbuf* get_pkt(void)
{
  static const unsigned char dns_pkt[] = {
    0x74, 0x03, 0xbd, 0x3d, 0x78, 0x96, 0x00, 0xa0,
    0xde, 0xc6, 0x52, 0x07, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x48, 0x09, 0x47, 0x00, 0x00, 0xff, 0x11,
    0x59, 0x16, 0xac, 0x14, 0x00, 0x01, 0xac, 0x14,
    0x01, 0x1e, 0x00, 0x35, 0xd2, 0xf4, 0x00, 0x34,
    0x73, 0x43, 0xb0, 0x00, 0x81, 0x80, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x64,
    0x70, 0x64, 0x6b, 0x05, 0x6e, 0x69, 0x6e, 0x6a,
    0x61, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0x39,
    0x00, 0x04, 0xa3, 0x2c, 0xa5, 0x31
  };

  const size_t NUM_MBUFS = 8191;
  const size_t MBUF_CACHE_SIZE = 250;
  struct rte_mempool *mempool;
  mempool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
    MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mempool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  struct rte_mbuf* m = rte_pktmbuf_alloc(mempool);
  uint8_t* p = rte_pktmbuf_mtod(m, uint8_t*);
  size_t   l = sizeof(dns_pkt);
  m->pkt_len  = l;
  m->data_len = l;
  memcpy(p, dns_pkt, l);
  return m;
}

static bool
is_printable_char(char c){
  return ((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9'));
}

static int
domain_reader(uint8_t *dns_pointer){
  uint8_t * c;
  uint8_t len;
  char domain[100];

  c = dns_pointer;
  while(*c != 0){
    c++;
  }
  len = c - dns_pointer + 1; // for memory
  memcpy(domain, dns_pointer+1, len-1);  //length of domain name (dpdk.ninja)
  for(int i = 0; i < len - 2; i++){  // pre&post counts '4'dpdk5ninja'0'
    if(!is_printable_char(domain[i]))
      domain[i] = '.';
  }
  printf("Domain %s\n", domain);

  return len;
}

static size_t analyze_rr(uint8_t * ptr){
  const uint8_t * const ptr_head = ptr;
  if(*ptr == 0xc0){
    ptr++;
    printf("Offset 0x%x\n", *ptr);
    ptr++;
  } else{
    ptr += domain_reader(ptr);
  }
  struct resrec *rr = (struct resrec *)(ptr);
  printf("Type %x\n", rte_be_to_cpu_16(rr->type));
  printf("Class %x\n", rte_be_to_cpu_16(rr->class));
  printf("Time to Live %d\n", rte_be_to_cpu_32(rr->ttl));
  printf("Length %x\n", rte_be_to_cpu_16(rr->len));
  ptr += sizeof(struct resrec);
  return ptr - ptr_head;
}

static void analyze_packet(struct rte_mbuf* m)
{
  struct eth_hdr *eth;
  struct ip4_hdr *ip;
  struct udp_hdr *udp;
  struct dns_hdr *dns;
  size_t length = m->pkt_len;

  eth = rte_pktmbuf_mtod(m, struct eth_hdr *);
  if (length < sizeof(struct eth_hdr)) return ; // error
  printf("\n=====DATA LINK=====\n");
  printf("dst %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
  printf("src %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
  //printf("type\n%x", rte_be_to_cpu_16(eth->type));
  switch(rte_be_to_cpu_16(eth->type)){
    case eth_ipv4:
      printf("Type IPv4\n");
      break;
    case eth_arp:
      printf("Type ARP\n");
      break;
    case eth_ipv6:
      printf("Type IPv6\n");
      break;
    default:
      printf("Type error\n");
      break;
  }

  ip = (struct ip4_hdr *)(eth+1);
  printf("\n=====NETWORK=====\n");
  printf("Version %02x\n", (ip->version_ihl & 0xf0) >> 4);
  printf("Header Length %d\n", (ip->version_ihl & 0x0f) * 4);
  printf("Type of Service %d\n", ip->tos);
  printf("Total Length%d\n", rte_be_to_cpu_16(ip->totlen));
  printf("Identification %d\n", rte_be_to_cpu_16(ip->id));
  printf("Type of Service %d\n", rte_be_to_cpu_16(ip->flag_off));
  printf("Time to Live %d\n", ip->ttl);
  //printf("Protocol %d\n", ip->proto);
  switch(ip->proto){
    case ipproto_icmp:
      printf("Protocol ICMP\n");
      break;
    case ipproto_tcp:
      printf("Protocol TCP\n");
      break;
    case ipproto_udp:
      printf("Protocol UDP\n");
      break;
    default:
      printf("Protocol error\n");
      break;
  }
  printf("Checksum %d\n", rte_be_to_cpu_16(ip->checksum));
  printf("Source %3d.%3d.%3d.%3d\n", ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3]);
  printf("Destination %3d.%3d.%3d.%3d\n", ip->src[0], ip->src[1], ip->src[2], ip->src[3]);

  udp = (struct udp_hdr *)(ip+1);
  printf("\n=====TRANSPORT=====\n");
  printf("Source Port %d\n", rte_be_to_cpu_16(udp->src_port));
  printf("Destination Port %d\n", rte_be_to_cpu_16(udp->dst_port));
  printf("Length %d\n", rte_be_to_cpu_16(udp->len));
  printf("Checksum %d\n", rte_be_to_cpu_16(udp->cksum));

  dns = (struct dns_hdr *)(udp+1);
  uint16_t qdc = rte_be_to_cpu_16(dns->qdcount);
  uint16_t anc = rte_be_to_cpu_16(dns->ancount);
  uint16_t nsc = rte_be_to_cpu_16(dns->nscount);
  uint16_t arc = rte_be_to_cpu_16(dns->arcount);
  printf("\n=====APPLICATION=====\n");
  printf("ID %d\n", rte_be_to_cpu_16(dns->id));
  printf("Flags %d\n", rte_be_to_cpu_16(dns->flags));
  printf("QD Count %d\n", qdc);
  printf("AN Count %d\n", anc);
  printf("NS Count %d\n", nsc);
  printf("AR Count %d\n", arc);

  uint8_t * ptr;
  struct query {
    uint16_t type;
    uint16_t class;
  } __attribute__((__packed__));

  printf("\n---question---\n");
  ptr = (uint8_t *)(dns+1);
  for(int i = 0; i < qdc; i++){
    ptr += domain_reader(ptr);
    struct query *qry = (struct query *)(ptr);
    printf("Type %x\n", rte_be_to_cpu_16(qry->type));
    printf("Class %x\n", rte_be_to_cpu_16(qry->class));
    ptr += sizeof(struct query);
  }

  printf("\n---answer---\n");
  for(int i = 0; i < anc; i++){
    ptr += analyze_rr(ptr);
    printf("Address %3d.%3d.%3d.%3d\n", *(ptr), *(ptr+1), *(ptr+2), *(ptr+3));
    ptr+=4;
  }

  printf("\n---authority---\n");
  for(int i = 0; i < nsc; i++){
    analyze_rr(ptr);
  }

  printf("\n---additional rec---\n");
  for(int i = 0; i < arc; i++){
    analyze_rr(ptr);
  }

  /*
  rte_hexdump(stdout, "Packet-Hexdump",
      rte_pktmbuf_mtod(m, uint8_t*), m->pkt_len);
  */
}

int main(int argc, char **argv)
{
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  struct rte_mbuf* m = get_pkt();
  analyze_packet(m);
  return 0;
}
