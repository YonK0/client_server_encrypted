#include "common.h"

int Establish_Connection()
{
    int len = sizeof(client);
    unsigned char encrypted[CIPHER_MAX_LEN];

    bzero(&servaddr, sizeof(servaddr));
    bzero(encrypted, sizeof(encrypted));

    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) 
    { 
        debug("socket creation failed...\n"); 
        exit(FAIL); 
    } 
    else
    {
        debug("Socket successfully created..\n");
    }

    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // accept any address
    servaddr.sin_port = htons(PORT); // defined in macros 
  
    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (__CONST_SOCKADDR_ARG) &servaddr, sizeof(servaddr))) != 0) 
    { 
        debug("socket bind failed...\n"); 
        exit(FAIL); 
    } 
    else
    {
        debug("Socket successfully binded..\n");
    }
  
    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) 
    { 
        debug("Listen failed...\n"); 
        exit(FAIL); 
    }
    else
    {
        debug("Server listening..\n");
    }
    

    
    printf("Waiting for Connection ...\n");
    // Accept the data packet from client and verification 
    sockfd = accept(sockfd, (__SOCKADDR_ARG) &client, &len);

    if (sockfd < 0) 
    { 
        debug("server accept failed...\n"); 
        exit(FAIL); 
    }
    else
    {
        debug("server accept the client...\n");
    }
    
    //send public key to get symetric key
    write(sockfd, pub_key, strlen(pub_key));

    //receive encrypted symetric key
    int bytes_read = read(sockfd, encrypted, sizeof(encrypted));

    decrypt_symetric_key_with_private_key(pri_key, encrypted, sizeof(encrypted), symetric_key);
    return SUCCESS;
}

int main()
{
    pthread_t thread1, thread2;
    sockfd = 0;

    //enter username for current user
    printf("Enter a username:\n");
    scanf(" %[^\n]s", &local_username);

    //generate public and private key
    generate_key_pair();

    Establish_Connection();

    //functions declared in common.h
    pthread_create(&thread1, NULL, Receive_, NULL);
    pthread_create(&thread2, NULL, Send_, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    close(sockfd);
    free(pri_key);
    free(pub_key);
    return SUCCESS;
}