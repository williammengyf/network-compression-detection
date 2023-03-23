#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "compdetect_config_parser.h"

char *read_file (const char *filename, int *file_size)
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

int setup_tcp_connection (int sock, const char *server_addr, int server_port)
{
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr (server_addr);
    sin.sin_port = htons (server_port);

    if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("cannot connect to server");
        return -1;
    }
    return 0;
}

int send_tcp_packet (int sock, const char *buffer, int buffer_size)
{
    int bytes_sent = send (sock, buffer, buffer_size, 0);

    if (bytes_sent < 0)
    {
        perror ("send () failed");
    }
        
    return 0;
}

int receive_tcp_packet (int sock, char *buffer, int buffer_size)
{
    int bytes_received = recv(sock, buffer, buffer_size, 0);

    if (bytes_received < 0)
    {
        perror ("recv () failed");
    }
    else if (bytes_received == 0)
    {
        return EOF;
    }

    return bytes_received;
}

int setup_udp_socket (int port)
{
    int sock;
    struct sockaddr_in sin;

    if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror ("cannot create UDP socket");
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

int send_udp_packet (int sock, const char *buffer, int buffer_size, struct sockaddr_in *dst_addr)
{
    int bytes_sent;

    if ((bytes_sent = sendto (sock, buffer, buffer_size, 0, (struct sockaddr *) dst_addr, sizeof (*dst_addr))) < 0)
    {
        perror ("sendto () failed");
        return -1;
    }

    return bytes_sent;
}

int main (int argc, char const *argv[])
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

    struct compdetect_config *config = parse_json_string (config_buf);

    int tcp_sock = socket (AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0)
    {
        perror ("cannot create TCP socket");
        free (config);
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    if (setup_tcp_connection (tcp_sock, config->server_ip_addr, config->tcp_dest_port) < 0)
    {
        close (tcp_sock);
        free (config);
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    if (send_tcp_packet (tcp_sock, config_buf, config_buf_size) < 0)
    {
        perror ("cannot send config data to server");
        close (tcp_sock);
        free (config);
        free (config_buf);
        exit (EXIT_FAILURE);
    }

    free (config_buf);
    close (tcp_sock);
    sleep (1);

    int udp_sock = setup_udp_socket (config->udp_src_port);
    if (udp_sock < 0)
    {
        free (config);
        exit (EXIT_FAILURE);
    }

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

    int random_buf_size;
    char *random_buf = read_file ("random_file", &random_buf_size);
    if (!random_buf)
    {
        close (udp_sock);
        free (config);
        exit (EXIT_FAILURE);
    }

    for (int train = 0; train < 2; train++)
    {
        for (int packet_id = 0; packet_id < config->udp_packet_count; packet_id++)
        {
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

            uint16_t packet_id_net = htons ((uint16_t) packet_id);
            memcpy (udp_buf, &packet_id_net, sizeof (packet_id_net));

            if (train == 1)
            {
                memcpy (udp_buf + sizeof (packet_id_net), random_buf, config->udp_payload_size - sizeof (packet_id_net));
            }

            if (send_udp_packet (udp_sock, udp_buf, config->udp_payload_size, &dst_addr) < 0)
            {
                perror ("cannot send UDP packet");
                close (udp_sock);
                free (config);
                free (random_buf);
                free (udp_buf);
                exit (EXIT_FAILURE);
            }

            free (udp_buf);
        }

        if (train == 0)
        {
            sleep (config->inter_measurement_time);
        }
    }

    close (udp_sock);
    free (config);
    free (random_buf);

    return 0;
}
