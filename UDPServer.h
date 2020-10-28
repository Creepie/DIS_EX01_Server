//
// Created by Mario Eberth on 28.10.20.
//

#ifndef DIS_EX01_SERVER_UDPSERVER_H
#define DIS_EX01_SERVER_UDPSERVER_H

#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init

#define BUFFER_SIZE 1024

#define IPPORT (_argv[1])

class UDPServer{
public:
    UDPServer(int port);
    void initializeSocket();
    void startSocket();

private:
    int ipPort;
    int serverSocket;
};

#endif //DIS_EX01_SERVER_UDPSERVER_H
