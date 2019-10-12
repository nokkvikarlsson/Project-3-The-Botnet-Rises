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
#include <time.h>

#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <ctime>
#include <fstream>

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

// Stores messages for servers and information about the sender of the message.
class Message
{
    public:
    //std::string receiver;      // Group ID of the server the message is for.
    std::string sender;          // The Group ID of the sender of the message
    std::string msg;             // The message to the sender.

    Message(std::string sender, std::string msg)
    {
        this->sender = sender;
        this->msg = msg;
    }

    ~Message(){}            // Virtual destructor defined for base class
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client*> clients; // Lookup table for per Client information
std::map<int, Server*> servers; // Lookup table for per Server information
std::map<std::string, std::vector<Message>> messageVault; // Stores messages for groups, the key is the group_ID the messages are for.

bool finished;
int listenClientSock;                 // Socket for connections from client
int listenServerSock;                 // Socket for connection from other servers
int clientSock;                       // Socket for connecting client
int serverSock;                       // Socket for connecting server
fd_set openSockets;                   // Current open sockets 
fd_set readSockets;                   // Socket list for select()        
fd_set exceptSockets;                 // Exception socket list
struct sockaddr_in client;
struct sockaddr_in server;
socklen_t clientLen;
socklen_t serverLen;
char buffer[1025];                    // buffer for reading from clients
int maxfds;                           // Passed to select() as max fd in set
int n = 0;
int serverPort;                       // Port that is used to listen for server connections.
std::string name = "P3_GROUP_29";     // Stores group ID of our server.
char myIP[32];
int maxServerConnections = 5;         // The max number of direct server connections

//Fuction for logging messages to 2 files, send_mgs and get_msg
void logMessage(const char logType[], std::string message)
{
        std::time_t t = std::time(0);   // get current time
        std::tm* curr = std::localtime(&t);
 
        if(logType == "SENT")
        {
                std::ofstream myfile;
                myfile.open ("sentMessageLog.txt", std::ios_base::app);
                myfile << '[';
                if(curr->tm_mday < 10) { myfile << '0'; }
                myfile << curr->tm_mday << '/';
                if(curr->tm_mon < 10) { myfile << '0'; }
                myfile << curr->tm_mon << ' ';
                if(curr->tm_hour < 10) { myfile << '0'; }
                myfile << curr->tm_hour << ':';
                if(curr->tm_min < 10) { myfile << '0'; }
                myfile << curr->tm_min << ':';
                if(curr->tm_sec < 10) { myfile << '0'; }
                myfile << curr->tm_sec << ']'
                << " - " << message << "\n";
                myfile.close();
        }
        else if(logType == "RECEIVED")
        {
                std::ofstream myfile;
                myfile.open ("receivedMessageLog.txt", std::ios_base::app);
                myfile << '[';
                if(curr->tm_mday < 10) { myfile << '0'; }
                myfile << curr->tm_mday << '/';
                if(curr->tm_mon < 10) { myfile << '0'; }
                myfile << curr->tm_mon << ' ';
                if(curr->tm_hour < 10) { myfile << '0'; }
                myfile << curr->tm_hour << ':';
                if(curr->tm_min < 10) { myfile << '0'; }
                myfile << curr->tm_min << ':';
                if(curr->tm_sec < 10) { myfile << '0'; }
                myfile << curr->tm_sec << ']'
                << " - " << message << "\n";
                myfile.close();
        }
}

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

int connectServer(const char * ipAddr, const char * portNo)
{
    struct addrinfo hints, *svr;              // Network host entry for server
    struct sockaddr_in serv_addr;             // Socket address for server
    int serverSocket;                         // Socket used for server 
    int nwrite;                               // No. bytes written to server
    char buffer[5121];                        // buffer for writing to server
    bool finished;                   
    int set = 1;                              // Toggle for setsockopt
    hints.ai_family   = AF_INET;            // IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;

    memset(&hints,   0, sizeof(hints));

    if(getaddrinfo(ipAddr, portNo, &hints, &svr) != 0)
    {
        perror("getaddrinfo failed: ");
        return -1;
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
        return -1;
    }
    else
    {
        std::cout << "Server Connected" << std::endl;
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
    //unsigned int microseconds = 1000000;
    //usleep(microsecond

    return serverSocket;
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

// Close a server's connection, remove it from the client list, and
// tidy up select sockets afterwards.
void closeServer(int serverSocket)
{
     // Remove client from the clients list
     servers.erase(serverSocket);

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.

     if(maxfds == serverSocket)
     {
        for(auto const& p : clients)
        {
            maxfds = std::max(maxfds, p.second->sock);
        }
     }

     // And remove from the list of open sockets.
     FD_CLR(serverSocket, &openSockets);
}

// Parsers buffer into tokens slpit by delimiter.
std::vector<std::string> parseString(std::string delimiter, char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;
    std::string s = buffer;

    // Split command from server into tokens for parsing
    size_t pos = 0;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        tokens.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    tokens.push_back(s);

    return tokens;
}

// Process commands from servers on server.
void serverCommand(int serverSocket, char *buffer)
{
    std::string strBuffer = buffer; // Store the buffer as a string.
    // Parse the string into tokens using "," as a delimiter.
    std::vector<std::string> tokens = parseString(",", buffer);
    std::cout << "TOKENS[0]: " << tokens[0] << std::endl;

    // Sends 1-hop connected servers back to the serverSocket.
    if((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 2))
    {
        // Add the ID of the server to the map.
        
        //servers[serverSocket]->name = tokens[1];

        // Get the ip and the port number where we listeen for server connections to our server.
        std::string strIP = myIP;
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

        // Add start and end characters and send msg back to the server.
        msg = addStartAndEnd(msg);
        send(serverSocket, msg.c_str(), msg.length(), 0);
    }
    // Processes a list of servers and tries to connect to them.
    else if((tokens[0].compare("SERVERS") == 0) && (tokens.size() >= 4))
    {
        // Save the first server in the message because that's the server that we connected to.
        bool exist = false;
        for(auto const& pair : servers)
        {   
            std::cout << "this is pair.second->name: " << pair.second->name << " this is tokens[1]: " << tokens[1] << std::endl; 
            if(pair.second->name == tokens[1])
            {
                exist = true;
            }
        }
        if(!exist)
        {
            servers[serverSocket]->name = tokens[1];
            servers[serverSocket]->ip = tokens[2];
            servers[serverSocket]->port = atoi(tokens[3].c_str());
        }
        std::cout << "*****Printing out connected servers*****" << std::endl;
        for(auto const& pair : servers)
        {   
            Server *server = pair.second;

            std::cout << "-----------------------" << std::endl;
            std::cout << "Name: " << server->name << std::endl;
            std::cout << "IP: " << server->ip << std::endl;
            std::cout << "Port: " << server->port << std::endl;
            std::cout << "Sock: " << server->sock << std::endl;
            std::cout << "-----------------------" << std::endl;
        }

        std::vector<std::string> smallerTokens;
        std::vector<Server> serversToConnect; // Stores information of servers that we will try to connect to.
        
        // Parse the string into tokens with ";" as a delimeter.
        tokens = parseString(";", (char *)strBuffer.c_str());

        // Loop over the tokens and parse them into smaller tokens to seperate ip and port information of the listed servers.
        for(int i = 1; i < tokens.size(); i++)
        {
            char * miniBuffer = (char *)tokens[i].c_str(); // A parsed token on char * form.
            smallerTokens = parseString(",", miniBuffer); // Parse into smaller tokens by the delimitor ",".
            std::string storeName = "";
            // Make sure that the token is not empty.
            if(tokens[i] != "")
            {
                Server serv(-0); // Used to store server information during parsing.
                // Loop over the smaller tokens and parse out the relevant information of them.
                for(int j = 0; j < smallerTokens.size(); j++)
                {
                    // if j == 0 then it's the name of the server.
                    if(j == 0)
                    {
                        serv.name = smallerTokens[j]; 
                        storeName = smallerTokens[j]; 
                    }
                    // if j == 1 then it's an ip address.
                    if(j == 1) 
                    {
                        serv.ip = smallerTokens[j];
                    }
                    // if j == then it's a port number.
                    else if (j == 2) 
                    {
                        serv.port = atoi(smallerTokens[j].c_str());
                    }
                }
                // Make sure that ip or port is not empty, and it's not our server.
                if(serv.ip != "" && serv.port != -1)
                {
                    // Check if we already have a connection to this server.
                    bool add = true;
                    for(auto const& pair : servers)
                    {
                        Server *server = pair.second;
                        // If name is found in the map don't try to connect to it's associated server.
                        if(server->name == serv.name)
                        {
                            std::cout << "I am already connected to him: " << server->name << std::endl;
                            add = false;
                        }
                    }
                    if(add)
                    {
                        // Add the serv information to the vector.
                        if(serv.port != serverPort) // Check if it is you.
                            serversToConnect.push_back(serv);
                    }
                }
            }
        }
        int servSock;
        if(servers.size() < maxServerConnections)
        {
            // loop over serversToConnect and try to connect to the servers.
            for(int i = 0; i < serversToConnect.size(); i++)
            {
                servSock = connectServer(serversToConnect[i].ip.c_str(), std::to_string(serversToConnect[i].port).c_str());
                // Add information about the server.
                if(servSock != -1)
                {
                    servers[servSock]->name = serversToConnect[i].name;
                    servers[servSock]->ip = serversToConnect[i].ip;
                    servers[servSock]->port = serversToConnect[i].port;
                }
            }
        }
        else
        {
            std::cout << "I am connected to too many servers :/" << std::endl;
            std::cout << "The size of the map is: " << servers.size() << std::endl;
        }
        
        // Remove all empty servers from the map.
        std::vector<int> serversToRemove;
        for(auto const& pair : servers)
        {
            // If we find a server with a empty name mark it for removal.
            if(pair.second->name == "")
            {
                serversToRemove.push_back(pair.first);
            }
        }
        // Remove allt the servers from the map.
        for(int i = 0; i < serversToRemove.size(); i++)
        {
            servers.erase(serversToRemove[i]);

            if(maxfds == serversToRemove[i])
            {
                for(auto const& p : servers)
                {
                    maxfds = std::max(maxfds, p.second->sock);
                }
            }
            // Remove from the list of open sockets.
            FD_CLR(serversToRemove[i], &openSockets);
        }
        serversToRemove.clear();
    }

    // If STATUSREQ,<FROM_GROUP_ID was received then reply to the GROUP_ID wit$
    else if((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
    {
        std::cout << "STATUSREQ received" << std::endl;
        std::string msg = "";

        msg += "STATUSRESP," + name;
        msg += "," + tokens[1];
	for(auto const& pair : servers)
        {
            if(name != tokens[1] && messageVault[pair.second->name].size() != 0)
            {
                msg += "," + pair.second->name + "," + std::to_string(messageVault[pair.second->name].size());
            }
        }
        send(serverSock, msg.c_str(), msg.length(), 0);
    }

    // If SEND_MSG,<FROM_GROUP_ID>,<TO_GROUP_ID>,<message content> was received hold on to the message until someone gets the message.
    else if((tokens[0].compare("SEND_MSG") == 0) && (tokens.size() > 3))
    {
        logMessage("RECEIVED", buffer);
        std::cout << "SEND_MSG received" << std::endl;
        std::string msg = ""; // Will store message parsed from the client command.
        std::string sender = tokens[1];
        std::string receiver = tokens[2];
        int forwardSock;

        // Rebuild the message from tokens.
        for(int i = 3; i < tokens.size(); i++)
        {
            if(i == 3)
            {
                msg += tokens[i];
            }
            else
            {
                msg += " " + tokens[i];
            }
        }

        std::cout << "+++++++++++To summarize++++++++++" << std::endl;
        std::cout << "This is the message: " << msg << std::endl;
        std::cout << "This is the group_ID of the SENDER: " << sender << std::endl;
        std::cout << "This is the group_ID of the RECEIVER: " << receiver << std::endl;
        std::cout << "This is the message: " << msg << std::endl;
        
        // If the message had the server's as the destination ID then send the message back to the client.
        std::cout << "This is tokens[1] " << tokens[1] <<std::endl;
        std::cout << "This is name " << name << std::endl;

        std::cout << "Message received that's for: " << receiver << ", from: " << sender << std::endl; 

        // Check if the servers is directly connected, if not then store the message.
        bool connected;
        std::cout << "Checking if we are directly connected to:" << receiver << std::endl;
        for(auto const& pair : servers)
        {
            std::cout << "comaparing this: |" << pair.second->name << "| tothis: |" << receiver << "|" << std::endl;
            if(pair.second->name == receiver)
            {   
                connected = true;
                forwardSock = pair.second->sock;
            }
        }
        // If the receiver servers is 1-hop away then send directly to him
        if(connected)
        {
            std::cout << "Forwarding message to this sock" << forwardSock << " with this name: " << std::endl;
            std::string forwardMsg = "";
            // SEND MSG,<FROM GROUP ID>,<TO GROUP ID>,<Message content>
            forwardMsg += "SEND_MSG," + sender + "," + receiver + "," + msg;
            logMessage("SENT", forwardMsg);
            forwardMsg = addStartAndEnd(forwardMsg);
            send(forwardSock, forwardMsg.c_str(), forwardMsg.length(),0);
        }
        // Else we store the message until someone retreives it.
        else
        {
            // Check if the map contains any a key for this receiver ID, if not add it.
            if(messageVault.find(receiver) == messageVault.end())
            {
                std::cout << receiver << " was not found, we create him in the vault" << std::endl;
                std::cout << "We are growing the map :D " << std::endl;
                std::vector<Message> messages;
                Message message = Message(sender, msg);
                messages.push_back(message);
                messageVault[receiver] = messages;
            }
            // If the receiver ID is already in the map then add it to the vector of messages associated with him.
            else
            {
                std::cout << receiver << " was found we add the message to his vault" << std::endl;
                Message message = Message(sender, msg);
                messageVault[receiver].push_back(message);
            }
        }
        
        std::cout << "The size of the map: " << messageVault.size() << std::endl;
        std::cout << receiver << " has this many messages: " << messageVault[receiver].size() << std::endl;
    }
    // If GET_MSG,<FROM_GROUP_ID> is received then check in out messageVault map if we have any messages for that ID
    else if((tokens[0].compare("GET_MSG") == 0) && (tokens.size() > 1))
    {
        std::string receiver = tokens[1];
        std::string msg = "";

        // Remove ',' remove from the group name
        if(receiver[receiver.size()-1] == ',')
        {
            receiver = receiver.erase(receiver.size()-1,1);
        }

        std::cout << "+++++++++++To summarize++++++++++" << std::endl;
        std::cout << "This is the group_ID: " << name << std::endl;

        // If the message had the server's as the destination ID then send the message back to the client.
    
        // Send back all messages for that GROUP_ID and erase from our message vault afterwards.
        std::cout << receiver << " has this many messages: " << messageVault[receiver].size() << std::endl;
        if(messageVault[receiver].size() > 0)
        {
            for(int i = 0; i < messageVault[receiver].size(); i++)
            {
                msg = "SEND_MSG," + messageVault[receiver][i].sender + "," + receiver + "," +  messageVault[receiver][i].msg;
                std::cout << "This is the message I am sending: " << msg << std::endl;
                logMessage("SENT", msg);
                msg = addStartAndEnd(msg);
                send(serverSock, msg.c_str(), msg.length(),0);
            }
            messageVault.erase(receiver);
            std::cout << receiver << " has this many messages after sending them: " << messageVault[receiver].size() << std::endl;
        }
    }
    else
    {
        std::cout << "Unknown command from server:" << buffer << std::endl;
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

    std::cout << "Token[0] is this: " << tokens[0] <<std::endl;

    if(tokens[0] == ("GETMSG,"))
    {
        std::cout << "THIS IS THE SAME " << std::endl;
    }

    // Connect server to another server
    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3))
    {
        // Get the socket connected to the newly connected server and return it.
        //Check if we are already connected to five servers.
        if(servers.size() < maxServerConnections)
        {
            connectServer(tokens[1].c_str(), tokens[2].c_str());
        }
        else
        {
            std::cout << "The server has reached it's maximum connections of " << maxServerConnections << " servers. :(" << std::endl;
        }
    }
    else if((tokens[0].compare("LISTSERVERS") == 0) && (tokens.size() == 1))
    {
        // Get the ip and the port number where we listeen for server connections to our server.
        std::string strIP = myIP;
        std::string strPort = std::to_string(serverPort);
        
        // Make the message that conatains every 1-hop connected server.
        std::string msg = "";

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
        if(msg == "")
        {
            msg = "No servers are connected to the server :(";
        }

        // Send the message back to the client
        send(clientSocket, msg.c_str(), msg.length(), 0);
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
    // If SEND_MSG, <GROUP_ID>, <message> was received hold on to the message until someone gets the message.
    else if((tokens[0].compare("SENDMSG,") == 0) && (tokens.size() > 2))
    {
        std::string msg = "";               // Will store message parsed from the client command.
        std::string receiver = tokens[1];   // GROUP ID of the group the messages is meant for.
        int forwardSock;                    // Will store the socket of the server we will forward the message to.

        // Remove ',' remove from the group name
        if(receiver[receiver.size()-1] == ',')
        {
            receiver = receiver.erase(receiver.size()-1,1);
        }
        // Rebuild the message from tokens
        
        for(int i = 2; i < tokens.size(); i++)
        {
            if(i == 2)
            {
                msg += tokens[i];
            }
            else
            {
                msg += " " + tokens[i];
            }
        }

        std::cout << "+++++++++++To summarize++++++++++" << std::endl;
        std::cout << "This is the command: " << tokens[0] << std::endl;
        std::cout << "This is the group_ID: " << receiver << std::endl;
        std::cout << "This is my name: " << name << std::endl;
        std::cout << "This is the message: " << msg << std::endl;

        // Check if the servers is directly connected, if not then store the message.
        bool connected;
        std::cout << "Checking if we are directly connected to:" << receiver << std::endl;
        for(auto const& pair : servers)
        {
            std::cout << "comaparing this: |" << pair.second->name << "| tothis: |" << receiver << "|" << std::endl;
            if(pair.second->name == receiver)
            {   
                std::cout << "I should be here" << std::endl;
                connected = true;
                forwardSock = pair.second->sock;
            }
        }
        // If the receiver servers is 1-hop away then send directly to him
        if(connected)
        {
            std::cout << "sending to this sock" << forwardSock << std::endl;
            std::string forwardMsg = "";
            // SEND MSG,<FROM GROUP ID>,<TO GROUP ID>,<Message content>
            forwardMsg += "SEND_MSG," + name + "," + receiver + "," + msg;
            logMessage("SENT", forwardMsg);
            forwardMsg = addStartAndEnd(forwardMsg);
            send(forwardSock, forwardMsg.c_str(), forwardMsg.length(),0);
        }
        // Else store the message until he gets it.
        else
        {
            // Check if the map contains any a key for this receiver ID, if not add it.
            if(messageVault.find(receiver) == messageVault.end())
            {
                std::cout << "We are growing the map :D " << std::endl;
                std::vector<Message> messages;
                Message message = Message(name, msg);
                messages.push_back(message);
                messageVault[receiver] = messages;
            }
            // If the receiver ID is already in the map then add it to the vector of messages associated with him.
            else
            {
                Message message = Message(name, msg);
                messageVault[receiver].push_back(message);
            }
        }
        
        std::cout << "The size of the map: " << messageVault.size() << std::endl;
        std::cout << receiver << " has this many messages: " << messageVault[receiver].size() << std::endl;
    }
    // GETMSG, <GROUP_ID>. Gets one message for the group from the message vault and sends it to the server.
    else if((tokens[0].compare("GETMSG,") == 0) && (tokens.size() > 1))
    {
        std::string receiver = tokens[1];
        std::string msg = "";

        std::cout << "This is the group_ID: " << receiver << std::endl;
    
        // If receiver is the server himself then check if the server is storing any messages from the client to himself.
        std::cout << "He has this many messages: " << messageVault[receiver].size() << std::endl;
        if(messageVault[receiver].size() > 0)
        {   
            std::cout << "size of vector: " <<  messageVault[receiver].size() << std::endl;
            msg = messageVault[receiver][messageVault[receiver].size()-1].msg;
            messageVault[receiver].pop_back();
            std::cout << "size of vector: " <<  messageVault[receiver].size() << std::endl;
            send(clientSock, msg.c_str(), msg.length(),0);
        }
        else
        {
            std::cout << "The server is storing no messages for << " <<  receiver << std::endl;  
        }
    }
    // TEST COMMNAD TO TEST SEND AND GET FUNCTIONALITY
    else if((tokens[0].compare("TESTSENDMSG,") == 0))
    {
        std::string receiver = tokens[1];
        int sock = 0;
        std::string msg = "";

        std::cout << "This is the receiver: " << receiver << std::endl;
    
        msg += "SEND_MSG," + name + "," + tokens[1] + ",HEY HOMO, BROOO";

        for(auto const& pair : servers)
        {
            std::cout << "This is the pair.second->name: " << pair.second->name << std::endl;
            if(pair.second->name == receiver)
            {
                sock = pair.second->sock;
                std::cout << "This is the socket: " << sock << std::endl;
            }
        }
        msg = addStartAndEnd(msg);
        std::cout << "sending this: " << msg << std::endl;
        send(sock, msg.c_str(), msg.length(),0);
    }
    else if((tokens[0].compare("TESTGETMSG,") == 0))
    {
        std::string receiver = tokens[1];
        std::string from = tokens[2];
        int sock = 0;
        std::string msg = "";

        std::cout << "This is the receiver: " << receiver << std::endl;
    
        msg += "GET_MSG,"  + receiver;

        for(auto const& pair : servers)
        {
            std::cout << "This is the pair.second->name: " << pair.second->name << std::endl;
            if(pair.second->name == receiver)
            {
                sock = pair.second->sock;
                std::cout << "This is the socket: " << sock << std::endl;
            }
        }
        msg = addStartAndEnd(msg);
        std::cout << "sending this: " << msg << std::endl;
        send(sock, msg.c_str(), msg.length(),0);
    }
    else
    {
        std::cout << "Unknown command from client:" << buffer << std::endl;
    }
}

int main(int argc, char* argv[])
{
    get_local_ip(myIP);

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
    name = name + "_" + std::to_string(serverPort); // REMOVE THIS BEFORE SUBMISSION, THIS IS ONLY FOR LOCAL TESTING.

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
            // Second, accept any new connections to the server from other servers from the listen Server socket
            if(FD_ISSET(listenServerSock, &readSockets))
            {
                std::cout << "THIS IS THE SIZE OF THE MAP: " << servers.size() << std::endl;

                serverSock = accept(listenServerSock, (struct sockaddr *)&server,
                                    &serverLen);
                if(servers.size() >= maxServerConnections)
                {
                    close(serverSock);
                    closeServer(serverSock);
                } 
                else
                {
                    printf("accept***\n");
                    // Add new server to the list of open sockets
                    FD_SET(serverSock, &openSockets);

                    // And update the maximum file descriptor
                    maxfds = std::max(maxfds, serverSock);

                    // create a new client to store information.
                    servers[serverSock] = new Server(serverSock);

                    // Decrement the number of sockets waiting to be dealt with
                    n--;
                    std::string msg = "LISTSERVERS," + name;
                    msg = addStartAndEnd(msg);
                    send(serverSock, msg.c_str(), msg.length(),0);
                    printf("Server connected on the port: %d\n", serverPort);
                }
                
            }
            // Now check for commands from clients
            while(n-- > 0)
            {
                std::vector<int> clientsToRemove;
                std::vector<int> serversToRemove;
                for(auto const& pair : clients)
                {
                    Client *client = pair.second;

                    if(FD_ISSET(client->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        if(recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            std::cout << "Server closed connection:" << client->sock << std::endl;
                            close(client->sock);   
                            clientsToRemove.push_back(client->sock);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is somePort on the socket for us.
                        else
                        {
                            std::cout << "The size of the clients map: " << clients.size() << std::endl;
                            std::cout << "This is the buffer before calling client command: " << buffer << std::endl;
                            clientCommand(client->sock, &openSockets, &maxfds, 
                                        buffer);
                        }
                    }
                }
                for(int i = 0; i < clientsToRemove.size(); i++)
                {
                    closeServer(clientsToRemove[i]);
                }
                for(auto const& pair : servers)
                {
                    Server *server = pair.second;

                    if(FD_ISSET(server->sock, &readSockets))
                    {
                        memset(&buffer, 0, sizeof(buffer));
                        // recv() == 0 means client has closed connection
                        if(recv(server->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            std::cout << "Client closed connection:" << server->sock << std::endl;
                            close(server->sock);   
                            serversToRemove.push_back(server->sock);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is somePort on the socket for us.
                        else
                        {
                            // Tokenize the buffer by start and end characters, because more then one command might be in the buffer.
                            std::string strBuffer = buffer;
                            bool keepLooping = true;

                            // THIS IS ONLY FOR TESTING CONSOLE COMMANDS AS SERVER COMMANDS
                            /*if(strBuffer.find((char)0x01) == std::string::npos && strBuffer.find((char)0x04) == std::string::npos)
                            {
                                    strBuffer = addStartAndEnd(strBuffer);
                            }*/

                            while(strBuffer.size() > 0 && keepLooping)
                            {
                                if(strBuffer.find((char)0x01) != std::string::npos && strBuffer.find((char)0x04) != std::string::npos)
                                {
                                    std::cout << "******************************" << std::endl;
                                    // Find the position of first delimiter 
                                    int firstDelPos = strBuffer.find((char)0x01);
                                    // Find the position of second delimiter
                                    int secondDelPos = strBuffer.find((char)0x04);
                                    // Get the substring between two delimiters
                                    std::string strbetweenTwoDels = strBuffer.substr(firstDelPos+1, secondDelPos-firstDelPos-1); 

                                    strBuffer = strBuffer.erase(firstDelPos, (secondDelPos-firstDelPos)+1);

                                    std::cout << "Processing this command: " << strbetweenTwoDels << std::endl;
                                    serverSock = server->sock;
                                    serverCommand(server->sock, (char*)strbetweenTwoDels.c_str());
                                }
                                else
                                {
                                    std::cout << "Start end end characters were not found in the message" << std::endl;
                                    keepLooping = false;
                                }
                            } 
                        }
                    }
                }
                for(int i = 0; i < serversToRemove.size(); i++)
                {
                    closeServer(serversToRemove[i]);
                }
            }
        }
    }
}
