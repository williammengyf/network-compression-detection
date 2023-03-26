/* Client of the compression detection client/server application  */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "compdetect_config_parser.h"

#define DATAGRAM_SIZE 4096
#define OPT_SIZE 20
#define RECV_TIMEOUT 10
#define THRESHOLD 100

/* Pseudo header needed for TCP header checksum calculation.  */
struct pseudo_header
{
  u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_size;
};

struct thread_args
{
  int sock_fd;
  struct sockaddr_in *src_addr;
  struct sockaddr_in *head_dst_addr;
  struct sockaddr_in *tail_dst_addr;
  struct timeval *first_rst_time;
  struct timeval *second_rst_time;
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
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + OPT_SIZE;
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
  psh.tcp_size = htons (sizeof (struct tcphdr) + OPT_SIZE);

  int psize = sizeof (struct pseudo_header) + sizeof (struct tcphdr) + OPT_SIZE;
  char *pseudogram = malloc (psize);
  if (!pseudogram)
    {
      perror ("cannot allocate memory for pseudo datagram");
      return NULL;
    }

  memcpy (pseudogram, (char *) &psh, sizeof (struct pseudo_header));
  memcpy (pseudogram + sizeof (struct pseudo_header), tcph, sizeof (struct tcphdr) + OPT_SIZE);

  tcph->check = checksum (pseudogram, psize);
  iph->check = checksum (datagram, iph->tot_len);

  *packet_size = iph->tot_len;
  free (pseudogram);
  return datagram;
}

/* Read a file to a string.  */
char *
read_file (const char *file_path, int *buf_size)
{
  FILE *file = fopen (file_path, "r");
  if (!file)
    {
      perror ("cannot open file");
      return NULL;
    }

  struct stat file_stat;
  if (stat (file_path, &file_stat) == -1)
    {
      perror ("cannot get file size");
      fclose (file);
      return NULL;
    }

  char *buffer = malloc (file_stat.st_size + 1);
  if (!buffer)
    {
      perror ("cannot allocate memory for file data");
      fclose (file);
      return NULL;
    }

  if (fread (buffer, 1, file_stat.st_size, file) != file_stat.st_size)
    {
      perror ("cannot read file");
      fclose (file);
      free (buffer);
      return NULL;
    }

  buffer[file_stat.st_size] = '\0';
  *buf_size = file_stat.st_size + 1;
  fclose (file);

  return buffer;
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

  struct timeval timeout;
  timeout.tv_sec = RECV_TIMEOUT;
  timeout.tv_usec = 0;

  if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof (timeout)) < 0)
    {
      perror ("cannot set receive timeout");
      close (sock);
      return -1;
    }

  return sock;
}

void*
receive_rst_packet (void *args)
{
  struct thread_args *thread_args = (struct thread_args *) args;
  int sock = thread_args->sock_fd;
  struct sockaddr_in *src_addr = thread_args->src_addr;
  struct sockaddr_in *head_dst_addr = thread_args->head_dst_addr;
  struct sockaddr_in *tail_dst_addr = thread_args->tail_dst_addr;
  struct timeval *first_rst_time = thread_args->first_rst_time;
  struct timeval *second_rst_time = thread_args->second_rst_time;

  char buffer[DATAGRAM_SIZE];
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_size = sizeof (recv_addr);

  while (!first_rst_time->tv_sec || !second_rst_time->tv_sec)
    {
      memset (buffer, 0, sizeof (buffer));
      int bytes_received = recvfrom (sock, buffer, sizeof (buffer), 0, (struct sockaddr *) &recv_addr, &recv_addr_size);

      if (bytes_received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              return NULL;
            }
          else
            {
              perror ("recvfrom () failed");
              return NULL;
            }
        }

      struct iphdr *iph = (struct iphdr *) buffer;
      struct tcphdr *tcph = (struct tcphdr *) (buffer + iph->ihl * 4);

      if (iph->saddr == head_dst_addr->sin_addr.s_addr && iph->daddr == src_addr->sin_addr.s_addr
          && tcph->source == head_dst_addr->sin_port && tcph->dest == src_addr->sin_port && tcph->rst == 1)
        {
          gettimeofday (first_rst_time, NULL);
          continue;
        }

      if (iph->saddr == tail_dst_addr->sin_addr.s_addr && iph->daddr == src_addr->sin_addr.s_addr
          && tcph->source == tail_dst_addr->sin_port && tcph->dest == src_addr->sin_port && tcph->rst == 1)
        {
          gettimeofday (second_rst_time, NULL);
          continue;
        }
    }

  return NULL;
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

  /* Set Don't Fragment flag.  */
  int enable = IP_PMTUDISC_DO;
  if (setsockopt (sock, IPPROTO_IP, IP_MTU_DISCOVER, &enable, sizeof (enable)) < 0)
    {
      perror ("setsockopt () failed");
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
  head_dst_addr.sin_port = htons (config->tcp_head_syn_dest_port);
  if (inet_pton (AF_INET, config->server_ip_addr, &head_dst_addr.sin_addr) != 1)
    {
      perror ("cannot configure head destination IP address");
      free (config);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in tail_dst_addr;
  tail_dst_addr.sin_family = AF_INET;
  tail_dst_addr.sin_port = htons (config->tcp_tail_syn_dest_port);
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

  int tail_syn_size;
  char *tail_syn_packet = create_syn_packet (&src_addr, &tail_dst_addr, &tail_syn_size);

  int udp_sock = setup_udp_socket (config->udp_src_port, config->udp_packet_ttl);
  if (udp_sock < 0)
    {
      close (raw_sock);
      free (config);
      free (head_syn_packet);
      free (tail_syn_packet);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in udp_dst_addr;
  memset (&udp_dst_addr, 0, sizeof (udp_dst_addr));
  udp_dst_addr.sin_family = AF_INET;
  udp_dst_addr.sin_port = htons (config->udp_dest_port);
  if (inet_pton (AF_INET, config->server_ip_addr, &udp_dst_addr.sin_addr) != 1)
    {
      perror ("cannot configure server IP address");
      close (raw_sock);
      close (udp_sock);
      free (config);
      free (head_syn_packet);
      free (tail_syn_packet);
      exit (EXIT_FAILURE);
    }

  /* Read random bytes from file.  */
  int random_buf_size;
  char *random_buf = read_file ("random_file", &random_buf_size);
  if (!random_buf)
    {
      close (raw_sock);
      close (udp_sock);
      free (config);
      free (head_syn_packet);
      free (tail_syn_packet);
      exit (EXIT_FAILURE);
    }

  /* Allocate memory for UDP packet and fill with all 0's.  */
  char *udp_buf = calloc (config->udp_payload_size, sizeof (char));
  if (!udp_buf)
    {
      perror ("cannot allocate memory for UDP packet");
      close (raw_sock);
      close (udp_sock);
      free (config);
      free (head_syn_packet);
      free (tail_syn_packet);
      free (random_buf);
      exit (EXIT_FAILURE);
    }

  struct thread_args thread_args;
  thread_args.sock_fd = raw_sock;
  thread_args.src_addr = &src_addr;
  thread_args.head_dst_addr = &head_dst_addr;
  thread_args.tail_dst_addr = &tail_dst_addr;
  thread_args.first_rst_time = malloc (sizeof (struct timeval));
  thread_args.second_rst_time = malloc (sizeof (struct timeval));

  double rst_time_interval[2];

  for (int train = 0; train < 2; train++)
    {
      memset (thread_args.first_rst_time, 0, sizeof (struct timeval));
      memset (thread_args.second_rst_time, 0, sizeof (struct timeval));
      pthread_t receive_rst_thread;
      if (pthread_create (&receive_rst_thread, NULL, receive_rst_packet, (void *) &thread_args) != 0)
        {
          perror ("cannot create thread for receiving RST packets");
          close (raw_sock);
          close (udp_sock);
          free (config);
          free (head_syn_packet);
          free (tail_syn_packet);
          free (random_buf);
          free (thread_args.first_rst_time);
          free (thread_args.second_rst_time);
          exit (EXIT_FAILURE);
        }

      int bytes_sent = sendto (raw_sock, head_syn_packet, head_syn_size, 0, (struct sockaddr *) &head_dst_addr, sizeof (struct sockaddr));
      if (bytes_sent < 0)
        {
          perror ("cannot send head SYN packet");
          close (raw_sock);
          close (udp_sock);
          free (config);
          free (head_syn_packet);
          free (tail_syn_packet);
          free (random_buf);
          free (thread_args.first_rst_time);
          free (thread_args.second_rst_time);
          exit (EXIT_FAILURE);
        }

      if (train == 1)
        {
          memcpy (udp_buf + sizeof (uint16_t), random_buf, config->udp_payload_size - sizeof (uint16_t));
        }

      for (int packet_id = 0; packet_id < config->udp_packet_count; packet_id++)
        {
          /* Set the first 16 bits to packet ID.  */
          uint16_t packet_id_net = htons (packet_id);
          memcpy (udp_buf, &packet_id_net, sizeof (packet_id_net));

          if (send_udp_packet (udp_sock, udp_buf, config->udp_payload_size, &udp_dst_addr) < 0)
            {
              perror ("cannot send UDP packet");
              close (raw_sock);
              close (udp_sock);
              free (config);
              free (head_syn_packet);
              free (tail_syn_packet);
              free (random_buf);
              free (thread_args.first_rst_time);
              free (thread_args.second_rst_time);
              exit (EXIT_FAILURE);
            }
        }

      bytes_sent = sendto (raw_sock, tail_syn_packet, tail_syn_size, 0, (struct sockaddr *) &tail_dst_addr, sizeof (struct sockaddr));
      if (bytes_sent < 0)
        {
          perror ("cannot send tail SYN packet");
          close (raw_sock);
          close (udp_sock);
          free (config);
          free (head_syn_packet);
          free (tail_syn_packet);
          free (random_buf);
          free (thread_args.first_rst_time);
          free (thread_args.second_rst_time);
          exit (EXIT_FAILURE);
        }

      if (train == 0)
        {
          sleep (config->inter_measurement_time);
        }

      pthread_join (receive_rst_thread, NULL);
      
      if (!thread_args.first_rst_time->tv_sec || !thread_args.second_rst_time->tv_sec)
        {
          printf ("Failed to detect due to insufficient information.\n");
          close (raw_sock);
          close (udp_sock);
          free (config);
          free (head_syn_packet);
          free (tail_syn_packet);
          free (random_buf);
          free (thread_args.first_rst_time);
          free (thread_args.second_rst_time);
          exit (EXIT_FAILURE);
        }
      
      rst_time_interval[train] = ((thread_args.second_rst_time->tv_sec - thread_args.first_rst_time->tv_sec) * 1000.0
                                  + (thread_args.second_rst_time->tv_usec - thread_args.first_rst_time->tv_usec) / 1000.0);
    }

  if (rst_time_interval[1] - rst_time_interval[0] > THRESHOLD)
    {
      printf ("Compression detected!\n");
    }
  else
    {
      printf ("No compression was detected.\n");
    }

  close (raw_sock);
  close (udp_sock);
  free (config);
  free (head_syn_packet);
  free (tail_syn_packet);
  free (random_buf);
  free (thread_args.first_rst_time);
  free (thread_args.second_rst_time);

  return 0;
}