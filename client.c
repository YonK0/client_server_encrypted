#include "common.h"
/////////////////////////////////////::
int Establish_Connection()
{
    //initialisation 
    unsigned char encrypted[CIPHER_MAX_LEN];
    unsigned char public_key[MAX_PUBLIC_KEY_LEN];
    sockfd = 0;

    bzero(&servaddr, sizeof(servaddr));
    bzero(encrypted, sizeof(encrypted));
    bzero(public_key, sizeof(public_key));

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) 
    {
        debug("socket creation failed...\n");
        exit(FAIL);
    }

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(DEFAULT_HOST);
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (__CONST_SOCKADDR_ARG) &servaddr, sizeof(servaddr))!= 0) 
    {
        debug("connection with the server failed...\n");
        printf("can't connect \n");
        exit(FAIL);
    }

    //receive the public key first
    read(sockfd, public_key, sizeof(public_key));
    //encrypt symetric key with public key
    encrypt_symetric_key_with_public_key(public_key, symetric_key, strlen(symetric_key), encrypted);
    //send the encrypted symetric key
    write(sockfd, encrypted, sizeof(encrypted));
    return 0;
}

int main()
{
    pthread_t thread1, thread2;
    sockfd = 0;
    bzero(local_username, sizeof(local_username));

    //username for the current user
    printf("Enter a username:\n");
    scanf(" %[^\n]s", &local_username);
    
    //generate a random symetric key
    RAND_bytes(symetric_key, sizeof(symetric_key));

    //connect to remote
    Establish_Connection();

    //create and adding receive and send as threads
    pthread_create(&thread1, NULL, Receive_, NULL);
    pthread_create(&thread2, NULL, Send_, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    return SUCCESS;
}