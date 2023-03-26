/* Server of the compression detection client/server application  */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "compdetect_config_parser.h"

#define RECV_TIMEOUT 5
#define THRESHOLD 100

/* Create a TCP socket, bind a port to it and make it wait for connections.  */
int
setup_tcp_socket (int port)
{
  int sock;
  int optval = 1;
  struct sockaddr_in sin;

  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("cannot create TCP socket");
      return -1;
    }

  if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
      perror ("cannot reuse address");
      close (sock);
      return -1;
    }

  memset (&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);

  if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      perror ("cannot bind TCP socket to address");
      close (sock);
      return -1;
    }

  if (listen (sock, 5) < 0)
    {
      perror ("error listening");
      close (sock);
      return -1;
    }

  return sock;
}

/* Accept a TCP connection and get the client socket.  */
int
accept_tcp_connection (int sock)
{
  struct sockaddr_in addr;
  unsigned int addr_size = sizeof (addr);
  int client_sock = accept (sock, (struct sockaddr *) &addr, &addr_size);
  if (client_sock < 0)
    {
      perror ("error accepting connection");
      return -1;
    }
  return client_sock;
}

/* Send a TCP packet.  */
int
send_tcp_packet (int sock, const char *buffer, int buffer_size)
{
  int bytes_sent = send (sock, buffer, buffer_size, 0);

  if (bytes_sent < 0)
    {
      perror ("send () failed");
      return -1;
    }
      
  return bytes_sent;
}

/* Receive a TCP packet.  */
int
receive_tcp_packet (int sock, char *buffer, int buffer_size)
{
  int bytes_received = recv(sock, buffer, buffer_size, 0);

  if (bytes_received < 0)
    {
      perror ("recv () failed");
      return -1;
    }
  else if (bytes_received == 0)
    {
      return EOF;
    }
      
  return bytes_received;
}

/* Create a UDP socket and bind a port to it.  */
int
setup_udp_socket (int port)
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

  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);

  if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      perror ("cannot bind UDP socket to address");
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

/* Receive a UDP packet.  */
int
receive_udp_packet (int sock, char *buffer, int buffer_size, struct sockaddr_in *src_addr)
{
  socklen_t addr_size = sizeof (*src_addr);
  int bytes_received = recvfrom (sock, buffer, buffer_size, 0, (struct sockaddr *) src_addr, &addr_size);

  if (bytes_received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      perror ("recvfrom () failed");
    }
  else if (bytes_received == 0)
    {
      return EOF;
    }

  return bytes_received;
}

int
main (int argc, char const *argv[])
{
  if (argc < 2)
    {
      printf ("Usage: %s <server_tcp_port_number>\n", argv[0]);
      exit (EXIT_FAILURE);
    }

  int tcp_port = atoi (argv[1]);
  if (tcp_port == 0)
    {
      perror ("invalid TCP port number");
      exit (EXIT_FAILURE);
    }

  int tcp_sock = setup_tcp_socket (tcp_port);
  if (tcp_sock < 0)
    {
      exit (EXIT_FAILURE);
    }

  int pre_probing_client_sock = accept_tcp_connection (tcp_sock);
  if (pre_probing_client_sock < 0)
    {
      exit (EXIT_FAILURE);
    }

  int buffer_size = 1024;
  char *config_buf = malloc (buffer_size);
  if (!config_buf)
    {
      perror ("cannot allocate memory for config data");
      close (tcp_sock);
      close (pre_probing_client_sock);
      exit (EXIT_FAILURE);
    }

  if (receive_tcp_packet (pre_probing_client_sock, config_buf, buffer_size) < 0)
    {
      perror ("cannot receive config data from client");
      close (tcp_sock);
      close (pre_probing_client_sock);
      free (config_buf);
      exit (EXIT_FAILURE);
    }

  /* Parse the configuration.  */
  struct compdetect_config *config = parse_json_string (config_buf);
  if (!config)
    {
      perror ("error parsing configuration");
      close (tcp_sock);
      close (pre_probing_client_sock);
      free (config_buf);
      exit (EXIT_FAILURE);
    }

  close (pre_probing_client_sock);
  free (config_buf);

  int udp_sock = setup_udp_socket (config->udp_dest_port);
  if (udp_sock < 0)
    {
      close (tcp_sock);
      free (config);
      exit (EXIT_FAILURE);
    }
  
  char *udp_buf = malloc (config->udp_payload_size);
  if (!udp_buf)
    {
      perror ("cannot allocate memory for low entropy data");
      close (tcp_sock);
      free (config);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in src_addr;
  int train_index = 0;    
  struct timeval first_packet_time[2], last_packet_time[2];
  struct timeval now;

  memset(first_packet_time, 0, sizeof(first_packet_time));
  memset(last_packet_time, 0, sizeof(last_packet_time));
  memset(&now, 0, sizeof(now));

  while (train_index < 2)
    {
      int bytes_received = receive_udp_packet (udp_sock, udp_buf, config->udp_payload_size, &src_addr);

      if (bytes_received > 0)
        {
          gettimeofday (&now, NULL);

          uint16_t src_port = ntohs (src_addr.sin_port);
          uint16_t packet_id = ntohs (*(uint16_t *) udp_buf);

          /* If it is a probing packet, record the time of arrival.  */
          if (src_port == config->udp_src_port && packet_id < config->udp_packet_count)
            {
              if (!first_packet_time[train_index].tv_sec)
                {
                  first_packet_time[train_index] = now;
                }
              last_packet_time[train_index] = now;
            }
        }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          if (first_packet_time[train_index].tv_sec)
            {
              train_index++;
            }
        }
      else
        {
          perror ("cannot receive UDP packet");
          break;
        }
    }

  close (udp_sock);
  free (udp_buf);

  double first_train_duration = ((last_packet_time[0].tv_sec - first_packet_time[0].tv_sec) * 1000.0
                                  + (last_packet_time[0].tv_usec - first_packet_time[0].tv_usec) / 1000.0);
  double second_train_duration = ((last_packet_time[1].tv_sec - first_packet_time[1].tv_sec) * 1000.0
                                  + (last_packet_time[1].tv_usec - first_packet_time[1].tv_usec) / 1000.0);

  // printf ("arrival time between the first and last packets of the first train: %.3lf ms\n", first_train_duration);
  // printf ("arrival time between the first and last packets of the second train: %.3lf ms\n", second_train_duration);

  /* Accept another TCP connection.  */
  int post_probing_client_sock = accept_tcp_connection (tcp_sock);
  if (post_probing_client_sock < 0)
    {
      close (tcp_sock);
      free (config);
      exit (EXIT_FAILURE);
    }

  char *report;
  if ((second_train_duration - first_train_duration) > THRESHOLD)
    {
      report = "Compression detected!";
    }
  else
    {
      report = "No compression was detected.";
    }

  /* Send the report to the client.  */
  if (send_tcp_packet (post_probing_client_sock, report, strlen (report) + 1) < 0)
    {
      perror ("cannot send config data to server");
      close (tcp_sock);
      close (post_probing_client_sock);
      free (config);
      exit (EXIT_FAILURE);
    }

  close (tcp_sock);
  close (post_probing_client_sock);
  free (config);
  
  return 0;
}
