/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "TEMU_lib.h"
#include "main.h"

#define TAINT_ORIGIN_START_UDP_NIC_IN 10000
#define TAINT_ORIGIN_START_TCP_NIC_IN 20000

typedef struct tcpconn_record{
  uint32_t id;
  uint32_t origin;
  uint32_t curr_seq;
  LIST_ENTRY(tcpconn_record) link;
} tcpconn_record_t;

typedef struct udpconn_record{
  uint32_t id;
  uint32_t origin;
  LIST_ENTRY(udpconn_record) link;
} udpconn_record_t;

static LIST_HEAD(tcpconn_record_list_head, tcpconn_record) 
		tcpconn_record_head = LIST_HEAD_INITIALIZER(&tcpconn_record_head);
static LIST_HEAD(udpconn_record_list_head, udpconn_record) 
		udpconn_record_head = LIST_HEAD_INITIALIZER(&udpconn_record_head);

/* Taint receive traffic flag */
static int taint_nic_state = 0;

int min(int x, int y) {
  return (x < y) ? x : y;
}

void do_taint_nic(int state)
{
  taint_nic_state = state;
}


/* Compute a unique flow/connection identifier given packet information */
static int compute_conn_id(struct ip *iph, struct tcphdr *tcph,
  struct udphdr *udph)
{
  uint32_t conn_id = 0;

  if (tcph) {
    conn_id = iph->ip_p ^ tcph->th_dport ^ tcph->th_sport ^
      iph->ip_dst.s_addr ^ iph->ip_src.s_addr;
  }
  else if (udph) {
    conn_id = iph->ip_p ^ udph->uh_sport ^ udph->uh_dport ^
      iph->ip_src.s_addr ^ iph->ip_dst.s_addr;
  }

  return conn_id;
}

/* 
 * Returns the origin for connection, if ID those not exist it adds an UDP 
 *   connection to the list
*/
static int get_udporigin(uint32_t conn_id)
{
  static int udp_conn_ctr = TAINT_ORIGIN_START_UDP_NIC_IN;

  /* If the connection already exists, return origin */
  udpconn_record_t *udp;
  LIST_FOREACH(udp, &udpconn_record_head, link) {
    if (udp->id == conn_id) 
      return udp->origin;
  }

  /* Else, add new connection to list */
  udpconn_record_t *udpconn = malloc(sizeof(udpconn_record_t));
  if (udpconn) {
    udpconn->id = conn_id;
    udpconn->origin = udp_conn_ctr++;

    LIST_INSERT_HEAD(&udpconn_record_head, udpconn, link);
    return udpconn->origin;
  }
  
  return -1;
}

/* Adds a new TCP connection if it does not exist */
static int add_tcpconn(uint32_t conn_id, uint32_t seq)
{
  static int tcp_conn_ctr = TAINT_ORIGIN_START_TCP_NIC_IN;

  /* If the connection already exists, update seq and return */
  tcpconn_record_t *tcp;
  LIST_FOREACH(tcp, &tcpconn_record_head, link) {
    if (tcp->id == conn_id) {
      tcp->curr_seq = seq;
      return 0;
    }
  }

  /* Else, add new connection to list */
  tcpconn_record_t *tcpconn = malloc(sizeof(tcpconn_record_t));
  if (tcpconn) {
    tcpconn->id = conn_id;
    tcpconn->origin = tcp_conn_ctr++;
    tcpconn->curr_seq = seq;

    LIST_INSERT_HEAD(&tcpconn_record_head, tcpconn, link);
    return 0;
  }
  
  return -1;
}

/* Find the seq number for the given connection. Zero if it does not exist */
static uint32_t get_tcpseq(uint32_t conn_id)
{
  /* Find connection in list */
  tcpconn_record_t *tcp;
  LIST_FOREACH(tcp, &tcpconn_record_head, link) {
    if (tcp->id == conn_id)
      return tcp->curr_seq;
  }
  return 0;
}

/* Find the origin for the given connection. Zero if it does not exist */
static uint32_t get_tcporigin(uint32_t conn_id)
{
  /* Find connection in list */
  tcpconn_record_t *tcp;
  LIST_FOREACH(tcp, &tcpconn_record_head, link) {
    if (tcp->id == conn_id)
      return tcp->origin;
  }
  return 0;
}

/* Deletes a tcp connection if it exists */
static int del_tcpconn(uint32_t conn_id)
{
  /* Find connection in list and delete it */
  tcpconn_record_t *tcp;
  LIST_FOREACH(tcp, &tcpconn_record_head, link) {
    if (tcp->id == conn_id) {
      LIST_REMOVE(tcp, link);
      free(tcp);
      break;
    }
  }
  return 0;
}

void my_nic_recv(uint8_t * buf, int size, int index, int start, int stop)
{
  /* If no data, return */
  if ((buf == NULL) || (size == 0))
    return;

  struct ip *iph = (struct ip *) (buf + 14);
  struct tcphdr *tcph = (struct tcphdr *) (buf + 34);
  struct udphdr *udph = (struct udphdr *) (buf + 34);
  uint32_t seq = 0;
  int hlen = 0, tolen, len2 = 0, offset = 0, avail, len, i;
  taint_record_t record;
  uint32_t conn_id = 0;

  memset(&record, 0, sizeof(taint_record_t));

  /* Check if we need to taint data */
  if (!taint_nic_state || // Ignore if not tainting NIC
      buf[12] != 0x08 || buf[13] != 0 ||  // Ignore non-IP packets
      (iph->ip_p != 6 && iph->ip_p != 17)
     )
    goto L1;

  /* TCP */
  if (6 == iph->ip_p) {
    conn_id = compute_conn_id(iph, tcph, NULL);

    /* If it is a SYN-ACK packet, create a new outbound connection */
    if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
      add_tcpconn(conn_id, ntohl(tcph->th_seq) + 1);

        uint32_t origin = get_tcporigin(conn_id);
        printf("New outbound TCP flow. ID: %u Origin: %u %s:%d-->%s:%d\n",
                conn_id, origin, inet_ntoa(iph->ip_dst), 
				ntohs(tcph->th_dport),
                inet_ntoa(iph->ip_src), ntohs(tcph->th_sport));
    }
    /* If the corresponding connection exists, grab sequence number and 
         set length */
    if ((seq = get_tcpseq(conn_id))) {
      /* If it's a FIN packet, then no more data coming, delete connection */
      /*   but handle packet normally since FIN packet can carry data */
      if (tcph->th_flags & TH_FIN) {
        del_tcpconn(conn_id);
      }
      tolen = ntohs(iph->ip_len) + 14;
      hlen = 34 + tcph->th_off * 4;
      len2 = tolen - hlen;
    }
    if (len2) {
      record.origin = get_tcporigin(conn_id);
      printf("Received new TCP data: %010u %s:%d-->%s:%d (%d)\n",
                record.origin, inet_ntoa(iph->ip_src),
                ntohs(tcph->th_sport), inet_ntoa(iph->ip_dst),
                ntohs(tcph->th_dport), len2);
    }
  }
  /* UDP */
  else if (17 == iph->ip_p) {
    conn_id = compute_conn_id(iph, NULL, udph);
    len2 = ntohs(iph->ip_len) - 20 - 8;
    hlen = 34 + 8;
    if (len2) {
      record.origin = get_udporigin(conn_id);

      /* Log received data */
      printf("Received new UDP data: %010u %s:%d-->%s:%d (%d)\n",
                record.origin, inet_ntoa(iph->ip_src),
                ntohs(udph->uh_sport), inet_ntoa(iph->ip_dst),
                ntohs(udph->uh_dport), len2);
    }
  }

L1:
  while (size > 0) {
    avail = stop - index;
    len = size;
    if (len > avail)
      len = avail;

    for (i = 0; i < len; i += 64)
      taintcheck_nic_writebuf(index + i, min(len - i, 64), 0, NULL);

    if (len2) {
      if (!offset) {
        if (len > hlen)
          for (; offset < len - hlen; offset++) {
            if (6 == iph->ip_p)
              record.offset = ntohl(tcph->th_seq) - seq + offset;
            else
              record.offset = offset;
            taintcheck_nic_writebuf(index + hlen + offset, 1, 1,
                                    (uint8_t *) & record);
          }
      }
      else {
        for (; offset < min(len2, offset + len); offset++) {
          if (6 == iph->ip_p)
            record.offset = ntohl(tcph->th_seq) - seq + offset;
          else
            record.offset = offset;

          taintcheck_nic_writebuf(index + offset, 1, 1,
                                  (uint8_t *) & record);
        }
      }
    }

    index += len;
    if (index == stop)
      index = start;
    size -= len;
  }

}

void my_nic_send(uint32_t addr, int size, uint8_t * buf)
{
  uint32_t conn_id = 0;

  /* If no data, return */
  if ((buf == NULL) || (size == 0))
    return;

  struct ip *iph = (struct ip *) (buf + 14);
  struct tcphdr *tcph = (struct tcphdr *) (buf + 34);
  //struct udphdr *udph = (struct udphdr*)(buf+34);

  /* Check if we need to taint data and this is an IP packet */
  if (!taint_nic_state || // Ignore if not tainting NIC
      buf[12] != 0x08 || buf[13] != 0x0) // Ignore non-IP packets
    return;

  /* TCP */
  if (iph->ip_p == 6) {
    /* If it is a SYN-ACK packet, create a new inbound connection */
    /* This is slightly preferred over creating the connection when 
        the SYN is received */
    if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
      conn_id = compute_conn_id(iph, tcph, NULL);
      add_tcpconn(conn_id, ntohl(tcph->th_ack));

      uint32_t origin = get_tcporigin(conn_id);
      printf("New inbound TCP flow. ID: %u Origin: %u %s:%d-->%s:%d\n",
                conn_id, origin, inet_ntoa(iph->ip_dst), ntohs(tcph->th_dport),
                inet_ntoa(iph->ip_src), ntohs(tcph->th_sport));
    }
  }

  return;
}



