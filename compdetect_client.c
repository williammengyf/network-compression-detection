/* Client of the compression detection client/server application  */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "compdetect_config_parser.h"

#define RANDOM_FILE "random_file"

/* Read a file to a string.  */
char *
read_file (const char *filename, int *file_size)
{
    int fd = open (filename, O_RDONLY);
    if (fd < 0)
    {
        perror ("cannot open file");
        return NULL;
    }

    struct stat st;
    fstat (fd, &st);
    *file_size = st.st_size;

    char *buffer = malloc (*file_size);
    if (!buffer)
    {
        perror ("cannot allocate memory for file data");
        close (fd);
        return NULL;
    }

    if (read (fd, buffer, *file_size) != *file_size)
    {
        perror ("cannot read file");
        close (fd);
        free (buffer);
        return NULL;
    }

    close (fd);
    return buffer;
}

/* Create a TCP socket and establish connection to the server.  */
int
setup_tcp_connection (const char *server_addr, int server_port)
{
    int sock;
    struct sockaddr_in sin;

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror ("cannot create TCP socket");
        return -1;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr (server_addr);
    sin.sin_port = htons (server_port);

    if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("cannot connect to server");
        close (sock);
        return -1;
    }
    return sock;
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

    /* Bind a port to the UDP socket to set the src port.  */
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
main (int argc, char const *argv[])
{
    if (argc < 2)
    {
        printf ("Usage: %s <json_config_file>\n", argv[0]);
        exit (EXIT_FAILURE);
    }

    int config_buf_size;
    char *config_buf = read_file (argv[1], &config_buf_size);
    if (!config_buf)
    {
        exit (EXIT_FAILURE);
    }

    /* Parse the configuration.  */
    struct compdetect_config *config = parse_json_string (config_buf);
    if (!config)
    {
        perror ("error parsing configuration");
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    int pre_probing_tcp_sock = setup_tcp_connection (config->server_ip_addr, config->tcp_dest_port);
    if (pre_probing_tcp_sock < 0)
    {
        free (config);
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    if (send_tcp_packet (pre_probing_tcp_sock, config_buf, config_buf_size) < 0)
    {
        perror ("cannot send config data to server");
        close (pre_probing_tcp_sock);
        free (config);
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    free (config_buf);
    close (pre_probing_tcp_sock);

    /* Wait the server to start a UDP socket.  */
    sleep (1);

    int udp_sock = setup_udp_socket (config->udp_src_port);
    if (udp_sock < 0)
    {
        free (config);
        exit (EXIT_FAILURE);
    }

    /* Set Don't Fragment flag.  */
    int enable = IP_PMTUDISC_DO;
    if (setsockopt (udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &enable, sizeof (enable)) < 0)
    {
        perror ("setsockopt () failed");
        close (udp_sock);
        free (config);
        exit (EXIT_FAILURE);
    }

    struct sockaddr_in dst_addr;
    memset (&dst_addr, 0, sizeof (dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr (config->server_ip_addr);
    dst_addr.sin_port = htons (config->udp_dest_port);

    /* Read random bytes from file.  */
    int random_buf_size;
    char *random_buf = read_file (RANDOM_FILE, &random_buf_size);
    if (!random_buf)
    {
        close (udp_sock);
        free (config);
        exit (EXIT_FAILURE);
    }

    char *udp_buf = malloc (config->udp_payload_size);
    if (!udp_buf)
    {
        perror ("cannot allocate memory for UDP packet");
        close (udp_sock);
        free (config);
        free (random_buf);
        exit (EXIT_FAILURE);
    }

    memset (udp_buf, 0, config->udp_payload_size);

    for (int train = 0; train < 2; train++)
    {
        if (train == 1)
        {
            memcpy (udp_buf + sizeof (uint16_t), random_buf, config->udp_payload_size - sizeof (uint16_t));
        }

        for (int packet_id = 0; packet_id < config->udp_packet_count; packet_id++)
        {
            /* Set the first 16 bits to packet ID.  */
            uint16_t packet_id_net = htons (packet_id);
            memcpy (udp_buf, &packet_id_net, sizeof (packet_id_net));

            if (send_udp_packet (udp_sock, udp_buf, config->udp_payload_size, &dst_addr) < 0)
            {
                perror ("cannot send UDP packet");
                close (udp_sock);
                free (config);
                free (random_buf);
                free (udp_buf);
                exit (EXIT_FAILURE);
            }
        }

        if (train == 0)
        {
            sleep (config->inter_measurement_time);
        }
    }

    close (udp_sock);
    free (random_buf);
    free (udp_buf);

    /* Establish another TCP connection.  */
    int post_probing_tcp_sock = setup_tcp_connection (config->server_ip_addr, config->tcp_dest_port);
    if (post_probing_tcp_sock < 0)
    {
        perror ("cannot create TCP socket");
        free (config);
        exit (EXIT_FAILURE);
    }

    int buffer_size = 64;
    char *report_buf = malloc (buffer_size);
    if (!report_buf)
    {
        perror ("cannot allocate memory for report data");
        close (post_probing_tcp_sock);
        free (config);
        exit (EXIT_FAILURE);
    }

    if (receive_tcp_packet (post_probing_tcp_sock, report_buf, buffer_size) < 0)
    {
        perror ("cannot receive report data from server");
        close (post_probing_tcp_sock);
        free (config);
        free (report_buf);
        exit (EXIT_FAILURE);
    }

    printf ("%s\n", report_buf);

    close (post_probing_tcp_sock);
    free (config);
    free (report_buf);

    return 0;
}
