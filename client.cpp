#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>

int main(int argc, char *argv[]) 
{
    int sock;
    struct timeval time;                // Use this to set the timeout for Select()
    time.tv_sec = 1;
    time.tv_usec = 0;
    fd_set fdSet;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Failed to open the socket\n");
        exit(0);
    }

    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(atoi(argv[2]));

    // Setting socket address
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) <= 0)
    {
        perror("Failed to set the socket address\n");
        exit(0);
    }

    // Connect to remote address
    if (connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) 
    {
        perror("Connection failed\n");
        exit(0);
    }



    // Message max size
    int n = 1025;
    // Initialize the message
    char message[n];
    while(true)
    {
        // Clear the message
        memset(message, 0, n);
        while(strlen(message) == 0)
        {
            // Take message as input
            std::cin.getline(message, n);
        }
        // Send the message
        send(sock, message, strlen(message), 0);
        // Clear the message
        memset(message, 0, n);
        // Client recieves the output of the command that was sent to the server
        FD_ZERO(&fdSet);
        FD_SET(sock, &fdSet);
        time.tv_sec = 0;
        time.tv_usec = 20000;
        if (select(sock + 1, &fdSet, NULL, NULL, &time) > 0)
        {
            if(!recv(sock, message, sizeof(message), 0)) 
            {
                std::cout << "Message not received!" << std::endl;
            }
            // Output gets printed out
            std::cout << message;
        }
    }

    if(close(sock) != 0)
    {
        perror("Error in closing socket");
        exit(0);
    }
    
    return 0;
}
