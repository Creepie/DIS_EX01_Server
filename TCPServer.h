//
// Created by Mario Eberth on 28.10.20.
//

#ifndef DIS_EX01_SERVER_TCPSERVER_H
#define DIS_EX01_SERVER_TCPSERVER_H

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

static pthread_mutex_t mMutex;

class TCPServer {
public:
    TCPServer(int port);
    void initializeSocket();
    void startSocket();
    static void* clientCommunication(void* _parameter);


private:
    void incrementSem();
    void decrementSem();
    int ipPort;
    int serverSocket;
    struct SocketParam{
        int commSocket;
        int serverSocketParam;
        TCPServer *self;
    };
};

#endif //DIS_EX01_SERVER_TCPSERVER_H
