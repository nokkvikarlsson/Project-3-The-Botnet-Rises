//
// Simple chat client for TSAM-409
//
// Command line: ./chat_client 4000 
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <thread>
#include <ctime>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>
#include <ctime>
#include <chrono>

// Threaded function for handling responss from server

void listenServer(int serverSocket)
{
    int nread;                                  // Bytes read from socket
    char buffer[1025];                          // Buffer for reading input

    while(true)
    {
       memset(buffer, 0, sizeof(buffer));
       nread = read(serverSocket, buffer, sizeof(buffer));

       if(nread == 0)                      // Server has dropped us
       {
          printf("Over and Out\n");
          exit(0);
       }
       else if(nread > 0)
       {
            //printf("%s\n", buffer);
            std::cout << std::endl;

            std::time_t t = std::time(0);   // get current time
                std::tm* curr = std::localtime(&t);

            std::cout << '[';
            if(curr->tm_mday < 10) { std::cout << '0'; }
            std::cout << curr->tm_mday << '/';
            if(curr->tm_mon < 10) { std::cout << '0'; }
            std::cout << curr->tm_mon << ' ';
            if(curr->tm_hour < 10) { std::cout << '0'; }
            std::cout << curr->tm_hour << ':';
            if(curr->tm_min < 10) { std::cout << '0'; }
                std::cout << curr->tm_min << ':';
            if(curr->tm_sec < 10) { std::cout << '0'; }
                std::cout << curr->tm_sec << ']'
                << " - " << buffer << "\n \n";
       }
    }
}

int main(int argc, char* argv[])
{
   struct addrinfo hints, *svr;              // Network host entry for server
   struct sockaddr_in serv_addr;           // Socket address for server
   int serverSocket;                         // Socket used for server 
   int nwrite;                               // No. bytes written to server
   char buffer[1025];                        // buffer for writing to server
   bool finished;                   
   int set = 1;                              // Toggle for setsockopt

   if(argc != 3)
   {
        printf("Usage: chat_client <ip  port>\n");
        printf("Ctrl-C to terminate\n");
        exit(0);
   }

   hints.ai_family   = AF_INET;            // IPv4 only addresses
   hints.ai_socktype = SOCK_STREAM;

   memset(&hints,   0, sizeof(hints));

   if(getaddrinfo(argv[1], argv[2], &hints, &svr) != 0)
   {
       perror("getaddrinfo failed: ");
       exit(0);
   }

    std::cout << std::endl << "Available commands for the client" << std::endl << std::endl;
    std::cout << "CONNECT <IP> <PORT> : Tell the server to connect to another server on the given IP address and port." << std::endl;
    std::cout << "LISTSERVERS : Prints all the directly(1-hop) connected servers to the server the client is connected to." << std::endl;
    std::cout << "SENDMSG, <GROUP_ID>, <message contents> : Sends the given message contents to the given GROUP_ID." << std::endl;
    std::cout << "GETMSG, <GROUP_ID> : Gets a single message from the server for the given GROUP_ID" << std::endl;
    std::cout << "STATUSREQ, <GROUP_ID> : Tells the server to send a STATUSREQ command to given GROUP_ID" << std::endl;
    std::cout << "LEAVE, <GROUP_ID> : Tell the servers to send a LEAVE,<IP_OF_OUR_SERVER>,<PORT_OF_OUR_SERVER> to the given GROUP_ID" << std::endl << std::endl;

   struct hostent *server;
   server = gethostbyname(argv[1]);

   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr,
      (char *)&serv_addr.sin_addr.s_addr,
      server->h_length);
   serv_addr.sin_port = htons(atoi(argv[2]));

   serverSocket = socket(AF_INET, SOCK_STREAM, 0);

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.
   if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
       printf("Failed to set SO_REUSEADDR for port %s\n", argv[2]);
       perror("setsockopt failed: ");
   }

   if(connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr) )< 0)
   {
       printf("Failed to open socket to server: %s\n", argv[1]);
       perror("Connect failed: ");
       exit(0);
   }

    // Listen and print replies from server
   std::thread serverThread(listenServer, serverSocket);

   finished = false;
   while(!finished)
   {
       bzero(buffer, sizeof(buffer));

       fgets(buffer, sizeof(buffer), stdin);

       nwrite = send(serverSocket, buffer, strlen(buffer),0);

       if(nwrite  == -1)
       {
           perror("send() to server failed: ");
           finished = true;
       }

   }
}
