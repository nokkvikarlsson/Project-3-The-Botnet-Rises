//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server 4000 
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

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG  5          // Allowed length of queue of waiting connections

// Simple class for handling connections from clients.
//
// Client(int socket) - socket to send/receive traffic from client.
class Client
{
  public:
    int sock;              // socket of client connection
    std::string name;           // Limit length of name of client's user

    Client(int socket) : sock(socket){} 

    ~Client(){}            // Virtual destructor defined for base class
};

// Simple class for handling connections from servers.
//
// Server(int socket) - socket to send/receive traffic from server.
class Server
{
  public:
    int sock;              // socket of server connection
    std::string name;      // Group ID of server user
    std::string ip;        // IP address of server
    int port;              // Port Number of server

    Server(int socket)
    {
        sock = socket;
        name = "";
        ip = "";
        port = -1;
    } 

    ~Server(){}            // Virtual destructor defined for base class
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client*> clients; // Lookup table for per Client information
std::map<int, Server*> servers; // Lookup table for per Server information

bool finished;
int listenClientSock;                 // Socket for connections from client
int listenServerSock;           // Socket for connection from other servers
int clientSock;                 // Socket for connecting client
int serverSock;                 // Socket for connecting server
fd_set openSockets;             // Current open sockets 
fd_set readSockets;             // Socket list for select()        
fd_set exceptSockets;           // Exception socket list
struct sockaddr_in client;
struct sockaddr_in server;
socklen_t clientLen;
socklen_t serverLen;
char buffer[1025];              // buffer for reading from clients
int maxfds;                     // Passed to select() as max fd in set
int n = 0;
int serverPort;                 // Port that is used to listen for server connections.
std::string name = "V_GROUP_29";               // Stores group ID

// Open socket for specified port.
//
// Returns -1 if unable to create the socket for any reason.

int open_socket(int portno)
{
   struct sockaddr_in sk_addr;   // address settings for bind()
   int sock;                     // socket opened for this port
   int set = 1;                  // for setsockopt

   // Create socket for connection. Set to be non-blocking, so recv will
   // return immediately if there isn't anything waiting to be read.
#ifdef __APPLE__     
   if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      perror("Failed to open socket");
      return(-1);
   }
#else
   if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
   {
     perror("Failed to open socket");
    return(-1);
   }
#endif

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.

   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
      perror("Failed to set SO_REUSEADDR:");
   }
   set = 1;
#ifdef __APPLE__     
   if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
   {
     perror("Failed to set SOCK_NOBBLOCK");
   }
#endif
   memset(&sk_addr, 0, sizeof(sk_addr));

   sk_addr.sin_family      = AF_INET;
   sk_addr.sin_addr.s_addr = INADDR_ANY;
   sk_addr.sin_port        = htons(portno);

   // Bind to socket to listen for connections from clients
   if(bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
   {
      perror("Failed to bind to socket:");
      return(-1);
   }
   else
   {
      return(sock);
   }
}

/* source: https://tinyurl.com/ya5prw53
 * get the local ip displayed to a host 
 */
void get_local_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char *kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

std::string addStartAndEnd(std::string msg)
{
    std::string start = "";
    std::string end = "";
    std::string retMsg = "";

    start = char(0x01);
    end = char(0x04);
    retMsg = start + msg + end;

    return retMsg;
}

void connectServer(const char * ipAddr, const char * portNo)
{
    struct addrinfo hints, *svr;              // Network host entry for server
    struct sockaddr_in serv_addr;             // Socket address for server
    int serverSocket;                         // Socket used for server 
    int nwrite;                               // No. bytes written to server
    char buffer[1025];                        // buffer for writing to server
    bool finished;                   
    int set = 1;                              // Toggle for setsockopt
    hints.ai_family   = AF_INET;            // IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;

    memset(&hints,   0, sizeof(hints));

    if(getaddrinfo(ipAddr, portNo, &hints, &svr) != 0)
    {
        perror("getaddrinfo failed: ");
        exit(0);
    }

    struct hostent *server;
    server = gethostbyname(ipAddr);

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
        (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
    serv_addr.sin_port = htons(atoi(portNo));

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
    // program exit.
    if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        printf("Failed to set SO_REUSEADDR for port %s\n", portNo);
        perror("setsockopt failed: ");
    }

    if(connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr) )< 0)
    {
        printf("Failed to open socket to server: %s\n", ipAddr);
        perror("Connect failed: ");
        exit(0);
    }
    else
    {
        printf("Server Connected");
    }

    FD_SET(serverSocket, &openSockets);

    // And update the maximum file descriptor
    maxfds = std::max(maxfds, serverSocket);

    // create a new server to store information.
    servers[serverSocket] = new Server(serverSocket);

    // Decrement the number of sockets waiting to be dealt with
    n--;

    std::string msg = "LISTSERVERS," + name;
    msg = addStartAndEnd(msg);

    send(serverSocket, msg.c_str(), msg.length(),0);
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
     // Remove client from the clients list
     clients.erase(clientSocket);

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.

     if(*maxfds == clientSocket)
     {
        for(auto const& p : clients)
        {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
     }

     // And remove from the list of open sockets.

     FD_CLR(clientSocket, openSockets);
}


// Process commands from servers on server.
void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds, 
                  char *buffer)
{
    std::vector<std::string> tokens;
    std::string strBuffer;
    std::string token;
    std::string s = buffer;
    std::string delimiter = ",";

    // Split command from server into tokens for parsing
    size_t pos = 0;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        tokens.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    tokens.push_back(s);

    std::cout << std::endl << "I AM IN SERVER COMMANDS" << std::endl;

    if((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        // Add the ID of the server to the map.
        servers[serverSocket]->name = tokens[1];

        // Get the ip and the port number where we listeen for server connections to our server.
        char ip[32];
        get_local_ip(ip);
        std::string strIP = ip;
        std::string strPort = std::to_string(serverPort);
        
        // Make the message that conatains every 1-hop connected server.
        std::string msg = "";
        msg = "SERVERS," + name + "," + strIP + "," + strPort + ";";

        // Add server from the servers map to msg and send it to the server that sent the LISTSERVERS command.
        for(auto const& pair : servers)
        {
            Server *server = pair.second;

            // Don't add servers that the servers doesnt have enough information about.
            if(server->name != "" && server->ip != "" && server->port != -1)
            {
                msg += server->name + "," + server->ip + "," + std::to_string(server->port) + ";";
            }
        }

        std::cout << "THIS IS MSG: " << msg << std::endl;

        // Add start and end characters and send msg back to the server.
        msg = addStartAndEnd(msg);
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    else if((tokens[0].compare("SERVERS") == 0) && (tokens.size() >= 4))
    {
        servers[serverSocket]->name = tokens[1];
        servers[serverSocket]->ip = tokens[2];
        servers[serverSocket]->port = atoi(tokens[3].c_str());

        std::cout << "NAME: " << servers[serverSocket]->name << std::endl;
        std::cout << "IP: " << servers[serverSocket]->ip << std::endl;
        std::cout << "PORT: " << servers[serverSocket]->port << std::endl;
    }
}

// Process command from client on the server
void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, 
                  char *buffer) 
{
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);

    while(stream >> token)
        tokens.push_back(token);

    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
    {
        clients[clientSocket]->name = tokens[1];
    }
    // Connect server to another server
    else if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3))
    {
        // Get the socket connected to the newly connected server and return it. 
        connectServer(tokens[1].c_str(), tokens[2].c_str());
    }
    else if(tokens[0].compare("LEAVE") == 0)
    {
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
 
        closeClient(clientSocket, openSockets, maxfds);
    }
    else if(tokens[0].compare("WHO") == 0)
    {
        std::cout << "Who is logged on" << std::endl;
        std::string msg;

        for(auto const& names : clients)
        {
            msg += names.second->name + ",";
        }
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(clientSocket, msg.c_str(), msg.length()-1, 0);
    }
    // This is slightly fragile, since it's relying on the order
    // of evaluation of the if statement.
    else if((tokens[0].compare("MSG") == 0) && (tokens[1].compare("ALL") == 0))
    {
        std::string msg;
        for(auto i = tokens.begin()+2;i != tokens.end();i++) 
        {
            msg += *i + " ";
        }

        for(auto const& pair : clients)
        {
            send(pair.second->sock, msg.c_str(), msg.length(),0);
        }
    }
    else if(tokens[0].compare("MSG") == 0)
    {
        for(auto const& pair : clients)
        {
            if(pair.second->name.compare(tokens[1]) == 0)
            {
                std::string msg;
                for(auto i = tokens.begin()+2;i != tokens.end();i++) 
                {
                    msg += *i + " ";
                }
                send(pair.second->sock, msg.c_str(), msg.length(),0);
            }
        }
    }
    else
    {
        std::cout << "Unknown command from client:" << buffer << std::endl;
    }
}

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup a socket for server to listen for other servers
    serverPort = atoi(argv[1]);
    listenServerSock = open_socket(serverPort);
    printf("Listening for servers on port: %d\n", serverPort);
    if(listen(listenServerSock, BACKLOG) < 0)
    {
        printf("Listen failed on port %d\n", serverPort);
        exit(0);
    }
    else 
    // Add listen socket to socket set we are monitoring
    {
        FD_ZERO(&openSockets);
        FD_SET(listenServerSock, &openSockets);
        maxfds = listenServerSock;
    }

    // Setup socket for server to listen for client connection
    int listenPort;
    std::cout << "Please specify a port to open for client connections: ";
    std::cin >> listenPort;

    listenClientSock = open_socket(listenPort);
    printf("Listening for client on port: %d\n", listenPort);
    if(listen(listenClientSock, BACKLOG) < 0)
    {
        printf("Listen failed on port %d\n", listenPort);
        exit(0);
    }
    else
    // Add listen socket to socket set we are monitoring
    {
        FD_SET(listenClientSock, &openSockets);
        maxfds = std::max(listenClientSock, listenServerSock);
    }

    finished = false;

    while(!finished)
    {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have somePort to be read()
        n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if(n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // First, accept  any new connections to the server on the listening socket
            if(FD_ISSET(listenClientSock, &readSockets))
            {
               clientSock = accept(listenClientSock, (struct sockaddr *)&client,
                                   &clientLen);
               printf("accept***\n");
               // Add new client to the list of open sockets
               FD_SET(clientSock, &openSockets);

               // And update the maximum file descriptor
               maxfds = std::max(maxfds, clientSock);

               // create a new client to store information.
               clients[clientSock] = new Client(clientSock);

               // Decrement the number of sockets waiting to be dealt with
               n--;

               printf("Client connected on client port: %d\n", clientSock);
            }
            // Second, accept any new connections to the server from other serveras from the listen Server socket
            if(FD_ISSET(listenServerSock, &readSockets))
            {
                serverSock = accept(listenServerSock, (struct sockaddr *)&server,
                                    &serverLen);
                printf("accept***\n");
                // Add new server to the list of open sockets
                FD_SET(serverSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, serverSock);

                // create a new client to store information.
                servers[serverSock] = new Server(serverSock);

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("Server connected on the port: %d\n", serverPort);
            }
            // Now check for commands from clients
            while(n-- > 0)
            {
               for(auto const& pair : clients)
               {
                  Client *client = pair.second;

                  if(FD_ISSET(client->sock, &readSockets))
                  {
                        // recv() == 0 means client has closed connection
                        if(recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            printf("Client closed connection: %d", client->sock);
                            close(client->sock);      

                            closeClient(client->sock, &openSockets, &maxfds);

                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is somePort on the socket for us.
                        else
                        {
                            std::cout << buffer << std::endl;
                            clientCommand(client->sock, &openSockets, &maxfds, 
                                        buffer);
                        }
                    }
               }
               for(auto const& pair : servers)
               {
                    Server *server = pair.second;

                    if(FD_ISSET(server->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        if(recv(server->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            printf("Server closed connection: %d", server->sock);
                            close(server->sock);      

                            closeClient(server->sock, &openSockets, &maxfds);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is somePort on the socket for us.
                        else
                        {
                            std::string strBuffer = buffer;
                            
                            if(strBuffer.find(0x01) == std::string::npos)
                            {
                                perror("NO start character found");
                            }
                            if(strBuffer.find(0x04) == std::string::npos)
                            {
                                perror("NO end character found");
                            }
                            // If end and start character was found then send the message
                            if(strBuffer.find(0x01) != std::string::npos && strBuffer.find(0x04) != std::string::npos)
                            {
                                // Extract the message between the start and the end characters.
                                unsigned start = strBuffer.find(char(0x01)) + 1;
                                unsigned end = strBuffer.find(char(0x04));
                                const char * msg = strBuffer.substr(start,end-start).c_str();

                                serverCommand(server->sock, &openSockets, &maxfds, 
                                            (char*)msg);
                            }
                        }
                    }
                }
            }
        }
    }
}
