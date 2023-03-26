/* Client of the compression detection client/server application  */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "compdetect_config_parser.h"

#define DATAGRAM_SIZE 4096

/* Pseudo header needed for TCP header checksum calculation.  */
struct pseudo_header
{
  u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_size;
};

/* Calculate the checksum in the IP header and TCP header.
   This function is from https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c  */
unsigned short
checksum (const char *buf, unsigned size)
{
  unsigned sum = 0, i;

  /*Accumulate checksum.  */
  for (i = 0; i < size - 1; i += 2)
    {
      unsigned short word16 = *(unsigned short *) &buf[i];
      sum += word16;
    }
  
  /* Handle odd-sized case.  */
  if (size & 1)
    {
      unsigned short word16 = (unsigned char) buf[i];
      sum += word16;
    }

  /* Fold to get the ones-complement result.  */
  while (sum >> 16)
    {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

  /* Invert to get the negative in ones-complement arithmetic.  */
  return ~sum;
}

/* Create a SYN packet.
   This function is inspired by https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c  */
char *
create_syn_packet (struct sockaddr_in *src, struct sockaddr_in *dst, int *packet_size)
{
  char *datagram = calloc (DATAGRAM_SIZE, sizeof (char));
  if (!datagram)
    {
      perror ("cannot allocate memory for datagram");
      return NULL;
    }

  struct iphdr *iph = (struct iphdr *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
  struct pseudo_header psh;

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
  iph->id = htonl (rand () % 65535);
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl (rand () % 4294967295);
  tcph->ack_seq = htonl (0);
  tcph->doff = 10;
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;
  tcph->window = htons (5840);
  tcph->urg_ptr = 0;

  memset (&psh, 0, sizeof (psh));
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_size = htons (sizeof (struct tcphdr));

  int psize = sizeof (struct pseudo_header) + sizeof (struct tcphdr);
  char *pseudogram = malloc (psize);
  if (!pseudogram)
    {
      perror ("cannot allocate memory for pseudo datagram");
      return NULL;
    }

  memcpy (pseudogram, (char *) &psh, sizeof (struct pseudo_header));
  memcpy (pseudogram + sizeof (struct pseudo_header), tcph, sizeof (struct tcphdr));

  tcph->check = checksum (pseudogram, psize);
  iph->check = checksum (datagram, iph->tot_len);

  *packet_size = iph->tot_len;
  free (pseudogram);
  return datagram;
}

/* Create a raw TCP socket and set option to manually build IP header.  */
int
setup_raw_socket (void)
{
  int sock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
  int optval = 1;

  if (sock < 0)
    {
      perror ("cannot create raw socket");
      return -1;
    }

  if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (optval)) < 0)
    {
      perror ("cannot manually build IP header");
      close (sock);
      return -1;
    }

  return sock;
}

int
receive_rst_packet (int sock, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr)
{
  char buffer[DATAGRAM_SIZE];
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_size = sizeof (recv_addr);

  while (1)
    {
      memset (buffer, 0, sizeof (buffer));
      int bytes_received = recvfrom (sock, buffer, sizeof (buffer), 0, (struct sockaddr *) &recv_addr, &recv_addr_size);

      if (bytes_received < 0)
        {
          perror ("recvfrom () failed");
          return -1;
        }

      struct iphdr *iph = (struct iphdr *) buffer;
      struct tcphdr *tcph = (struct tcphdr *) (buffer + iph->ihl * 4);

      if (iph->saddr == dst_addr->sin_addr.s_addr && iph->daddr == src_addr->sin_addr.s_addr
          && tcph->source == dst->sin_port && tcph->dest == src->sin_port && tcph->rst == 1)
        {
          printf ("RST packet received\n");
          return 0;
        }
    }

  return -1;
}

/* Create a UDP socket and bind a port to it.  */
int
setup_udp_socket (int port, int ttl)
{
  int sock;
  int optval = 1;
  struct sockaddr_in sin;

  if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      perror ("cannot create UDP socket");
      return -1;
    }

  if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
      perror ("cannot reuse address");
      close (sock);
      return -1;
    }

  if (setsockopt (sock, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl)) < 0)
    {
      perror ("cannot set TTL");
      close (sock);
      return -1;
    }

  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);

  /* Bind a port to the UDP socket to set the src port.  */
  if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      perror ("cannot bind UDP socket to address");
      close (sock);
      return -1;
    }

  return sock;
}

/* Send a UDP packet.  */
int
send_udp_packet (int sock, const char *buffer, int buffer_size, struct sockaddr_in *dst_addr)
{
  int bytes_sent;

  if ((bytes_sent = sendto (sock, buffer, buffer_size, 0, (struct sockaddr *) dst_addr, sizeof (*dst_addr))) < 0)
    {
      perror ("sendto () failed");
      return -1;
    }

  return bytes_sent;
}

int
main(int argc, char const *argv[])
{
  if (argc < 2)
    {
      printf ("Usage: %s <config_file>\n", argv[0]);
      exit (EXIT_FAILURE);
    }

  srand (time (NULL));

  /* Parse the configuration.  */
  struct compdetect_config *config = parse_json_file (argv[1]);
  if (!config)
    {
      perror ("error parsing config file");
      exit (EXIT_FAILURE);
    }

  int raw_sock = setup_raw_socket ();
  if (raw_sock < 0)
    {
      free (config);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in head_dst_addr;
  head_dst_addr.sin_family = AF_INET;
  head_dst_addr.sin_port = config->tcp_head_syn_dest_port;
  if (inet_pton (AF_INET, config->server_ip_addr, &head_dst_addr.sin_addr) != 1)
    {
      perror ("cannot configure head destination IP address");
      free (config);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in tail_dst_addr;
  tail_dst_addr.sin_family = AF_INET;
  tail_dst_addr.sin_port = config->tcp_tail_syn_dest_port;
  if (inet_pton (AF_INET, config->server_ip_addr, &tail_dst_addr.sin_addr) != 1)
    {
      perror ("cannot configure tail destination IP address");
      free (config);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in src_addr;
  src_addr.sin_family = AF_INET;
  src_addr.sin_port = htons (rand () % 65535);
  if (inet_pton (AF_INET, config->standalone_ip_addr, &src_addr.sin_addr) != 1)
    {
      perror ("cannot configure source IP address");
      free (config);
      exit (EXIT_FAILURE);
    }

  int head_syn_size;
  char *head_syn_packet = create_syn_packet (&src_addr, &head_dst_addr, &head_syn_size);

  int sent = sendto (raw_sock, head_syn_packet, head_syn_size, 0, (struct sockaddr *) &head_dst_addr, sizeof (struct sockaddr));
  if (sent < 0)
    {
      perror ("cannot send head SYN packet");
      free (config);
      free (head_syn_packet);
      exit (EXIT_FAILURE);
    }

  if (receive_rst_packet (raw_sock, &src_addr, &head_dst_addr) < 0)
    {
      perror ("cannot receive RST packet");
      free (config);
      free (head_syn_packet);
      exit (EXIT_FAILURE);
    }

  close (raw_sock);

  return 0;
}