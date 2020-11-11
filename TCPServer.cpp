//
// Created by Mario Eberth on 28.10.20.
//

#include "TCPServer.h"

#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init
#include <sstream>

#define BUFFER_SIZE 1024

TCPServer::TCPServer(int _port) {
    ipPort = _port;

    sem_unlink("/semaphore01");
    mSem = sem_open("semaphore01", O_CREAT|O_EXCL, 0777, 1);

    mMutex = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_init(&mMutex, NULL) != 0){
        std::cout << "Fehler in der mMutex init" << std::endl;
    }
}

void TCPServer::initializeSocket() {
    /**
     * Socket
     */
    int _addressFormat = AF_INET;                                                  //Format Ipv4
    int _socketType = SOCK_STREAM;                                                 //TCP
    int _socketProtocol = 0;                                                       //communication protocol > self check

    serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    /**
     * Bind
     */
    struct sockaddr_in serverAddr;                                                 //creates a sockaddr_in object (in = internet)
    serverAddr.sin_family = AF_INET;                                               //Format Ipv4
    serverAddr.sin_port = ipPort;                                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    serverAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(serverAddr.sin_zero), '\0',8);                                // \0 get copied in the first 8 char character of sin_zero

    /**
     * check if the bind method got a error return value (<0)
     */
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {
        std::cout << "Fehler in der Bind" << std::endl;
        return;
    }

    /**
     * set SocketOptions
     */
    bool bOptVal = true;
    int bOptLen = sizeof(bool);
    if (setsockopt(serverSocket, SOL_SOCKET,SO_REUSEADDR,(char*)&bOptVal,bOptLen) == -1){
        std::cout << "socket Freigabe war nicht möglich" << std::endl;
    }

    /**
     * listen
     */
    int backlock = 20;                                                              //count of connections
    int serverListen = listen(serverSocket, backlock);                              //
}

/**
 * in this method i increment the sem
 */
void TCPServer::incrementSem() {
    sem_close(mSem);
   //pthread_mutex_unlock(&mMutex);
}

/**
 * in this method i decrement the sem
 */
void TCPServer::decrementSem() {
    sem_wait(mSem);
    //pthread_mutex_lock(&mMutex);
}

void * TCPServer::clientCommunication(void *_parameter) {

    SocketParam *param = (SocketParam*)_parameter;

    decrementSem();
    int commSocket = param->commSocket;
    int serverSocket = param->serverSocketParam;

    char msg[BUFFER_SIZE];

    /**
     * get timeStamp and save it in a String
     */
    time_t seconds;
    time(&seconds);
    std::stringstream ss;
    ss << seconds;
    std::string timeStamp = ss.str();

    while (strcmp(msg, "exit") != 0 && strcmp(msg, "shutdown") != 0 ) {
        /**
         * receive return val > 0 if no problem
         */
        memset(msg, '\0', sizeof(msg)+1);
        if (recv(commSocket, msg, BUFFER_SIZE, 0) >0) {                             //check if the recv method got a error return value (<=0) something goes wrong the the receive
            /**
             * send return val > 0 if no problem
             */
            std::cout << msg;

            /**
             * creating random numbers
             */
            int numberLight = rand() % 100 + 1;
            int numberNoise = rand() % 100 + 1;
            int numberAir = rand() % 100 + 1;

            std::string responseText;                                                  //create a ACK message
            if (strcmp(msg, "getSensortypes()#") == 0){
                responseText.append("light;noise;air#");
            } else if(strcmp(msg, "Sensor(light)#") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append(std::to_string(numberLight));
                responseText.append("#");
            } else if(strcmp(msg, "Sensor(noise)#") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append(std::to_string(numberNoise));
                responseText.append("#");
            }  else if(strcmp(msg, "Sensor(air)#") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                for (int i = 0; i < 2; i++){
                    responseText.append(std::to_string(rand() % 100 + 1));
                    responseText.append(";");
                }
                responseText.append(std::to_string(rand() % 100 + 1));
                responseText.append("#");
            }   else if(strcmp(msg, "getAllSensors()#") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append("light;");
                responseText.append(std::to_string(numberLight));
                responseText.append("|");
                responseText.append("noise;");
                responseText.append(std::to_string(numberNoise));
                responseText.append("|");
                responseText.append("air;");
                for (int i = 0; i < 2; i++){
                    responseText.append(std::to_string(rand() % 100 + 1));
                    responseText.append(";");
                }
                responseText.append(std::to_string(rand() % 100 + 1));
                responseText.append("#");
            } else{
                responseText.append("Echo: ");
                responseText.append(msg);
            }

            char sendMsg [BUFFER_SIZE];
            strcpy(sendMsg, responseText.c_str());
            if (!send(commSocket, sendMsg, strlen(sendMsg), 0) >0) {                   //send the ACK and check if the send method got a error return value (<=0)
                std::cout << "Error Sending message" << std::endl;
            }
            memset(sendMsg, '\0', sizeof(sendMsg)+1);
        } else {
            std::cout << "Fehler in der Übertragung" << std::endl;
            //return -1;
        }
    }
    int closeSocket = close(commSocket);                                        //close the client socket
    incrementSem();
    if (strcmp(msg, "shutdown")== 0 ){
        int closeServerSocket = close(serverSocket);
        exit(0);
    }
}

void TCPServer::startSocket() {
    std::cout << "waiting for connection" << std::endl;

    /**
     * accept
     */
    struct sockaddr_in clientAddr;                                              //creates a sockaddr_in object (in = internet)
    socklen_t clientAddrSize = sizeof(clientAddr);                              //creates a socklen_t variable with the size of clientAddr in it

        while (true){
            /**
             * commSocket > socket for each client
             */
            int commSocket = accept(serverSocket, (sockaddr *) &clientAddr,&clientAddrSize);    //creates the commSocket in the serverSocket

            SocketParam *param = new SocketParam;
            param->commSocket = commSocket;
            param->serverSocketParam = serverSocket;

            pthread_t threadID;
            if (pthread_create(&threadID,NULL,clientCommunication, param) != 0){
                std::cout << "Problem in der Thread Method" << std::endl;
            }
        }
}

