all:
	$ g++ -std=c++11 client.cpp -lpthread -o client
	$ g++ -std=c++11 server.cpp -o server

