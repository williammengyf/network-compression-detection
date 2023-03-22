#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "compdetect_config_parser.h"

int send_packets (int sock, char *buffer, int buffer_len)
{
    int sent_bytes = send (sock, buffer, buffer_len, 0);

    if (sent_bytes < 0)
        perror ("send() failed");
        
    return 0;
}

int receive_packets (int sock, char *buffer, int buffer_len)
{
    int num_received = recv(sock, buffer, buffer_len, 0);

    if (num_received < 0)
        perror ("recv() failed");

    else if (num_received == 0)
        return EOF;

    else
        return num_received;
}

int establish_connection (int sock, const char *server_addr, int server_port)
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
        perror ("cannot allocate memory");
        close (fd);
        return NULL;
    }

    if (read (fd, buffer, file_size) != file_size)
    {
        perror ("cannot read file");
        close (fd);
        free (buffer);
        return NULL;
    }

    close (fd);
    return buffer;
}

int main (int argc, char const *argv[])
{
    if (argc < 2)
    {
        printf ("Usage: %s <json_config_file>\n", argv[0]);
        exit (EXIT_FAILURE);
    }
    
    int fd = open (argv[1], O_RDONLY);
    if (fd < 0)
    {
        perror ("cannot open file");
        exit (EXIT_FAILURE);
    }

    struct stat st;
    if (fstat (fd, &st) < 0)
    {
        perror ("cannot get file information");
        close (fd);
        exit (EXIT_FAILURE);
    }

    int file_size;
    char *buffer = read_file (argv[1], &file_size);
    if (!buffer)
    {
        exit (EXIT_FAILURE);
    }

    struct compdetect_config *config = parse_json_string (buffer);

    int sock = socket (AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror ("cannot create TCP socket");
        free (buffer);
        free (config);
        exit (EXIT_FAILURE);
    }

    if (establish_connection (sock, config->server_ip_addr, config->tcp_dest_port) < 0)
    {
        close (sock);
        free (buffer);
        free (config);
        exit (EXIT_FAILURE);
    }

    if (send_packets (sock, buffer, file_size) < 0)
    {
        perror ("cannot send data to server");
        close (sock);
        free (buffer);
        free (config);
        exit (EXIT_FAILURE);
    }

    close (sock);
    free (buffer);
    free (config);

    return 0;
}
