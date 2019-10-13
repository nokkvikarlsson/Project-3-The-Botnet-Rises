# Tölvusamskipti, Project 3: The Botnet Rises - nokkvi17 & egillt17
We developed this project on OSX, but it runs on skel as well.

The project contains two files.
* tsamvgroup29.cpp
* client.cpp

*tsamvgroup29.cpp* contains code for a botnet server and *client.cpp* contains code for a client that connects to the server.

# How to compile
To compile the code simply run the "*make*" command.
```sh
$ make
```

# How to run
After compiling two executable are created.
* tsamvgroup29
* client

Start by running the server. With a port number as the only argument.
```she
$ ./tsamvgroup <SERVER_LISTEN_PORT>
```
Now the server is listening for server connection on the given Server_Listen_Port.
When you run the server he will ask you to type in a port number to listen for client connetions.

Next run the client by with the IP address of the server and the port number you chose to listen for server connections.
```she
$ ./client <IP_OF_SERVER> <CLIENT_LISTEN_PORT>
```
Now the client is connected to the server and you can type in commands in the client that get sent to ther server.


# Supported Client Commands
* **CONNECT <IP_OF_SERVER> <SERVER_LISTEN_PORT>** : Tells the server to try to connect to a another server on the given IP_OF_SERVER and SERVER_LISTEN_PORT. 
* **LISTSERVERS** : Asks the server for a list of servers directly connected(1-hop) to him.
* **SENDMSG, <GROUP_ID>, <message>** : Sends the given message contents to the given GROUP_ID if the servers is directly connected to him, else he stores the message until someones gets it with a GETMSG command.
* **GETMSG, <GROUP_ID>, <message>** : Gets a single message from the server for the given GROUP_ID.
* **LEAVE <GROUP_ID>** : Tell the servers to send a LEAVE,<IP_OF_OUR_SERVER>,<PORT_OF_OUR_SERVER> to the given GROUP_ID
* **STATUSREQ, <GROUP_ID>** Tells the server to send a STATUSREQ command to given GROUP_ID

# How The Server Works (Design decisions)
All commands are shown working with screenshots in the pdf file called *BotnetScreenshots* that were submited with the project.
Here we will shortly explain some of the design decisions of how our server works that was not clear in the project description.

When the server receives a **CONNECT <IP_OF_SERVER> <SERVER_LISTEN_PORT>** from the client he tries to establish a connection to the server at the given IP_OF_SERVER and SERVER_LISTEN_PORT. If a connection was established he then sends a **LISTSERVERS,<MY_GROUP_ID>** command to the newly connected server. The other server should send a list of his directly connected servers which our server also tries to establish a connection to up to a maximum of 5 total directly connected servers.

When our server receives a **SEND_MSG,<FROM_GROUP_ID>,<TO_GROUP_ID>,<MESSAGE_CONTENTS>** from a server or **SENDMSG, <GROUP_ID>, <MESSAGE_CONTENTS>** from a client he sends the message to the server if he is directly connected to him, if not or the message is for our server he will store the message when a server or the client get the messages stored. If a server sends a **GET_MSG,<GROUP_ID>** the server sends him all the messages that he is storing that are for GROUP_ID and deletes them. If a client sends a **GET_MSG, <GROUP_ID>** the server will send a single message that is for GROUP_ID and delete it.

Our server sends a **KEEPALIVE<no. messages>** every 60 to a server after he has connected to him. If our server receives a **KEEPALIVE<no. messages>** and the no. of messages is greater than 0 then our server will send a **GET_MSG,<GROUP_ID>** to the server to get messages for him. If a directly connected server is connected and hasn't sent a **KEEPALIVE,<no. message>** in 5 minutes he sends a **LEAVE,<OUR_SERVER_IP>,<SERVER_LISTEN_PORT>** to the server and drops the connection.

##Logging Messages
We logged every message we either sent or received into the following .txt files
* *sentMessageLog.txt* includes all of the messages that we sent to other servers, with a timestamp of the time we sent it.
* *receivedMessageLog.txt* includes all of the messages that we received from other servers, with a timestamp of the time we received it.

# Author
Name: Nökkvi Karlsson & Egill Aron Þórisson.
Email: nokkvi17@ru.is & egillt17@ru.is