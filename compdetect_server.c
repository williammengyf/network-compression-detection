#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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

int setup_socket ()
{
    int sock = socket (AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror ("cannot create TCP socket");
        return -1;
    }
    return sock;
}

int bind_and_listen (int sock, int server_port)
{
    int optval = 1;
    struct sockaddr_in sin;

    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror ("cannot reuse address");
        return -1;
    }

    memset (&sin, 0, sizeof(sin));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons (server_port);

    if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("cannot bind socket to address");
        return -1;
    }

    if (listen (sock, 5) < 0)
    {
        perror ("error listening");
        return -1;
    }

    return 0;
}

int accept_connection (int sock)
{
    struct sockaddr_in addr;
    int addr_len = sizeof (addr);
    int client_sock = accept (sock, (struct sockaddr *) &addr, &addr_len);
    if (client_sock < 0)
    {
        perror ("error accepting connection");
        return -1;
    }
    return client_sock;
}

int main (int argc, char const *argv[])
{
    if (argc < 2)
    {
        printf ("Usage: %s <server_tcp_port_number>\n", argv[0]);
        exit (EXIT_FAILURE);
    }

    int server_port = atoi (argv[1]);
    if (server_port == 0)
    {
        perror ("invalid TCP port number");
        exit (EXIT_FAILURE);
    }

    int sock = setup_socket ();
    if (sock < 0)
    {
        exit (EXIT_FAILURE);
    }

    if (bind_and_listen (sock, server_port) < 0)
    {
        close (sock);
        exit (EXIT_FAILURE);
    }

    int client_sock = accept_connection (sock);
    if (client_sock < 0)
    {
        close (sock);
        exit (EXIT_FAILURE);
    }

    int buffer_size = 4096;
    char *buffer = malloc (buffer_size);
    if (!buffer)
    {
        perror ("cannot allocate memory");
        close (sock);
        close (client_sock);
        exit (EXIT_FAILURE);
    }

    if (receive_packets (client_sock, buffer, buffer_size) < 0)
    {
        perror ("error receiving data");
        close (sock);
        close (client_sock);
        free (buffer);
        exit (EXIT_FAILURE);
    }

    printf ("Received config data:\n%s\n", buffer);

    close (sock);
    close (client_sock);
    free (buffer);
    
    return 0;
}
