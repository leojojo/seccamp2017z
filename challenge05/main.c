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
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include "protocol.h"

#define FIN (0x01 << 0)
#define SYN (0x01 << 1)
#define RST (0x01 << 2)
#define PSH (0x01 << 3)
#define ACK (0x01 << 4)
#define URG (0x01 << 5)

static struct rte_mbuf* get_pkt(void)
{
  static const unsigned char http_pkt[] = {
    0x00, 0xa0, 0xde, 0xc6, 0x52, 0x07, 0x74, 0x03,
    0xbd, 0x3d, 0x78, 0x96, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x7e, 0xb2, 0x2a, 0x40, 0x00, 0x40, 0x06,
    0x92, 0xbf, 0xac, 0x14, 0x01, 0x1e, 0xa3, 0x2c,
    0xa5, 0x31, 0xe2, 0xde, 0x00, 0x50, 0x99, 0x9d,
    0xf0, 0xb0, 0x35, 0xa2, 0xaa, 0x46, 0x80, 0x18,
    0x10, 0x16, 0x42, 0xc4, 0x00, 0x00, 0x01, 0x01,
    0x08, 0x0a, 0x57, 0x75, 0xd1, 0x14, 0x6d, 0x73,
    0x6d, 0x7c, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20,
    0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
    0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
    0x64, 0x70, 0x64, 0x6b, 0x2e, 0x6e, 0x69, 0x6e,
    0x6a, 0x61, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72,
    0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20,
    0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x35,
    0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x41, 0x63, 0x63,
    0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a,
    0x0d, 0x0a, 0x0d, 0x0a,
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
  size_t   l = sizeof(http_pkt);
  m->pkt_len  = l;
  m->data_len = l;
  memcpy(p, http_pkt, l);
  return m;
}

static bool is_domain(uint8_t * ptr){
  printf("\n=====HTTP=====\n");
  const char httpget[] = "GET / HTTP/1.1\r\nHost: dpdk.ninja\r\n";
  return memcmp(ptr, httpget, sizeof(httpget)-1) == 0;
}

static void send_rst_ack(struct rte_mbuf* m,
    uint8_t srcip[4], uint8_t dstip[4],
    uint16_t srcport, uint16_t dstport,
    uint32_t seq, uint32_t ack){

  struct ether_hdr *eth;
  struct ip4_hdr *ip;
  struct tcp_hdr *tcp;
  size_t pkt_size;

  // ==========CRAFTING PACKET==========
  // -----ethernet-----
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);  // points to start of the data in the mbuf, return type
  rte_eth_macaddr_get(0, &eth->s_addr); // port, macAddr of Eth device
  memset(&eth->d_addr, 0xFF, ETHER_ADDR_LEN); // FF:FF:FF:FF:FF
  eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4); // CPU's endian -> big endian

  // -----ip-----
  ip = (struct ip4_hdr *)(eth+1);
  ip->version_ihl = 0x45;
  ip->tos = 0x00;
  ip->totlen = rte_cpu_to_be_16(sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr));
  ip->id = rte_cpu_to_be_16(0xbeef);
  ip->flag_off = rte_cpu_to_be_16((0x02 << 13) & 0x00); // 0x02 and 0x00 -> 010 0000000000000(13 bits)
  ip->ttl = 0x40;
  ip->proto = 0x06;
  ip->checksum = 0;
  for(int i = 0; i < 4; i++){
    ip->src[i] = srcip[i];
    ip->dst[i] = dstip[i];
  }

  // -----tcp-----
  tcp = (struct tcp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0f)* 4);
  tcp->src_port = rte_cpu_to_be_16(srcport);
  tcp->dst_port = rte_cpu_to_be_16(dstport);
  tcp->sent_seq = rte_cpu_to_be_32(seq);
  tcp->recv_ack = rte_cpu_to_be_32(ack);
  tcp->data_off = sizeof(struct tcp_hdr);
  tcp->tcp_flags = RST | ACK;
  tcp->rx_win = rte_cpu_to_be_16(4000);
  tcp->cksum = 0;
  tcp->tcp_urp = rte_cpu_to_be_16(0);

  pkt_size = sizeof(struct ether_hdr) + sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr);
  m->data_len = pkt_size;
  m->pkt_len = pkt_size;
  // ==========CRAFTING PACKET==========

  rte_hexdump(stdout, "hoge", rte_pktmbuf_mtod(m, struct ether_hdr *), m->pkt_len);
  //rte_eth_tx_burst(0, 0, &m, 1);  // port, queue, pointer to retrieved packets are stored in rte_mbuf, MAX packets to retrieve
}

static void analyze_packet(struct rte_mbuf* m)
{
  uint8_t* pkt = rte_pktmbuf_mtod(m, uint8_t*);
  pkt += analyze_eth(pkt);
  pkt += analyze_ip(pkt);
  pkt += analyze_tcp(pkt);
  if(is_domain(pkt)){
    printf("DPDKNINJA!!!!!\n");
    uint8_t dummyip[4] = {0xaa,0xbb,0xcc,0xdd};
    uint8_t dummyport = 0xee;
    send_rst_ack(m, dummyip, dummyip, dummyport, dummyport, 0xabcdabcd, 0xabcdabcd);
  }
  else {
    printf("notdpdkninja\n");
  }
  //rte_hexdump(stdout, "Packet-Hexdump", pkt, len);
}

int main(int argc, char **argv)
{
  /* rte_log_set_global_level(RTE_LOG_EMERG); */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  struct rte_mbuf* m = get_pkt();
  analyze_packet(m);
  return 0;
}
