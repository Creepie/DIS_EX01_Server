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
    int mAddressFormat = AF_INET;                                                  //Format Ipv4
    int mSocketType = SOCK_STREAM;                                                 //TCP
    int mSocketProtocol = 0;                                                       //communication protocol > self check

    serverSocket = socket(mAddressFormat, mSocketType, mSocketProtocol);       //creates a server Socket

    /**
     * Bind
     */
    struct sockaddr_in mServerAddr;                                                 //creates a sockaddr_in object (in = internet)
    mServerAddr.sin_family = AF_INET;                                               //Format Ipv4
    mServerAddr.sin_port = ipPort;                                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    mServerAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(mServerAddr.sin_zero), '\0', 8);                                // \0 get copied in the first 8 char character of sin_zero

    /**
     * check if the bind method got a error return value (<0)
     */
    if (bind(serverSocket, (sockaddr *) &mServerAddr, sizeof(mServerAddr)) < 0) {
        std::cout << "Fehler in der Bind" << std::endl;
        return;
    }

    /**
     * set SocketOptions
     */
    bool mBOptVal = true;
    int mBOptLen = sizeof(bool);
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&mBOptVal, mBOptLen) == -1){
        std::cout << "socket Freigabe war nicht möglich" << std::endl;
    }

    /**
     * listen
     */
    int mBacklock = 20;                                                              //count of connections
    int serverListen = listen(serverSocket, mBacklock);                              //
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

    SocketParam *mParam = (SocketParam*)_parameter;

    decrementSem();
    int commSocket = mParam->commSocket;
    int serverSocket = mParam->serverSocketParam;

    char mMsg[BUFFER_SIZE];

    /**
     * get timeStamp and save it in a String
     */
    time_t mSeconds;
    time(&mSeconds);
    std::stringstream ss;
    ss << mSeconds;
    std::string timeStamp = ss.str();

    while (strcmp(mMsg, "exit") != 0 && strcmp(mMsg, "exit\n") != 0 && strcmp(mMsg, "shutdown") != 0 && strcmp(mMsg, "shutdown\n") != 0) {
        /**
         * receive return val > 0 if no problem
         */
        char mSendMsg [BUFFER_SIZE];
        memset(mSendMsg, '\0', sizeof(mSendMsg) + 1);
        memset(mMsg, '\0', sizeof(mMsg) + 1);
        if (recv(commSocket, mMsg, BUFFER_SIZE, 0) > 0) {                             //check if the recv method got a error return value (<=0) something goes wrong the the receive
            /**
             * send return val > 0 if no problem
             */
            std::cout << mMsg;


            /**
             * creating random numbers
             */
            int mNumberLight = rand() % 100 + 1;
            int mNumberNoise = rand() % 100 + 1;

            std::string responseText;    //create a ACK message
            if (strcmp(mMsg, "getSensortypes()#") == 0 || strcmp(mMsg, "getSensortypes()#\n") == 0){
                responseText.append("light;noise;air#\n");
            } else if(strcmp(mMsg, "Sensor(light)#") == 0 || strcmp(mMsg, "Sensor(light)#\n") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append(std::to_string(mNumberLight));
                responseText.append("#\n");
            } else if(strcmp(mMsg, "Sensor(noise)#") == 0 || strcmp(mMsg, "Sensor(noise)#\n") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append(std::to_string(mNumberNoise));
                responseText.append("#\n");
            }  else if(strcmp(mMsg, "Sensor(air)#") == 0 || strcmp(mMsg, "Sensor(air)#\n") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                for (int i = 0; i < 2; i++){
                    responseText.append(std::to_string(rand() % 100 + 1));
                    responseText.append(";");
                }
                responseText.append(std::to_string(rand() % 100 + 1));
                responseText.append("#\n");
            }   else if(strcmp(mMsg, "getAllSensors()#") == 0 || strcmp(mMsg, "getAllSensors()#\n") == 0){
                responseText.append(timeStamp);
                responseText.append("|");
                responseText.append("light;");
                responseText.append(std::to_string(mNumberLight));
                responseText.append("|");
                responseText.append("noise;");
                responseText.append(std::to_string(mNumberNoise));
                responseText.append("|");
                responseText.append("air;");
                for (int i = 0; i < 2; i++){
                    responseText.append(std::to_string(rand() % 100 + 1));
                    responseText.append(";");
                }
                responseText.append(std::to_string(rand() % 100 + 1));
                responseText.append("#\n");
            } else{
                responseText.append("Echo: ");
                responseText.append(mMsg);
            }


            strcpy(mSendMsg, responseText.c_str());
            if (!send(commSocket, mSendMsg, strlen(mSendMsg), 0) > 0) {                   //send the ACK and check if the send method got a error return value (<=0)
                std::cout << "Error Sending message" << std::endl;
            }

        } else {
            std::cout << "Fehler in der Übertragung" << std::endl;
            //return -1;
        }
    }
    incrementSem();
    std::cout << "thread kurz vor delte" << std::endl;
    if (strcmp(mMsg, "shutdown") == 0 || strcmp(mMsg, "shutdown\n") == 0){
        int mCloseSocket = close(commSocket);
        int mCloseServerSocket = close(serverSocket);
        exit(0);
    }
}

void TCPServer::startSocket() {
    std::cout << "waiting for connection" << std::endl;

    /**
     * accept
     */
    struct sockaddr_in mClientAddr;                                              //creates a sockaddr_in object (in = internet)
    socklen_t mClientAddrSize = sizeof(mClientAddr);                              //creates a socklen_t variable with the size of mClientAddr in it

        while (true){
            /**
             * mCommSocket > socket for each client
             */
            int mCommSocket = accept(serverSocket, (sockaddr *) &mClientAddr, &mClientAddrSize);    //creates the mCommSocket in the serverSocket

            SocketParam *mParam = new SocketParam;
            mParam->commSocket = mCommSocket;
            mParam->serverSocketParam = serverSocket;

            pthread_t mThreadID;
            if (pthread_create(&mThreadID, NULL, clientCommunication, mParam) != 0){
                std::cout << "Problem in der Thread Method" << std::endl;
            }
        }
}

