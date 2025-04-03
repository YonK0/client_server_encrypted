////////////INCLUDE//////////////////:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////::
#include <stdlib.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write() ...
#include <pthread.h>
#include <arpa/inet.h> // fixing inet_addr warning
#include "crypto.h"
////////////MACROS//////////////////:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////::
#if (debug == 1)
#define debug                               printf
#else//////////////////::
#define debug(...)
#endif
#define FAIL                                -1
#define SUCCESS                             0
#define PORT                                1234
#define MAX_BUFFER_LEN                      1024
#define USERNAME_lEN                        20
#define MAX_PUBLIC_KEY_LEN                  4096
#define DEFAULT_HOST                        (char *)"127.0.0.1"
////////////GLOBALS//////////////////::////////////////s//:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////::
int sockfd, connfd; 
struct sockaddr_in servaddr, client;
char local_username[USERNAME_lEN] = {0};
char symetric_key[KEY_MAX_LEN] = {0};
////////////FUNCTIONS/////////////////////////::////////////////s//:://////////////////:://////////////////:://////////////////:://////////////////:://////////////////::

void *Receive_()
{
    //initialisation
    char buffer[MAX_BUFFER_LEN];
    char Remote_Username[USERNAME_lEN] = {0};
    char decrypted_msg[CIPHER_MAX_LEN + VI_MAX_LEN] = {0};
    int  Bytes = 0;

    while(1)
    {
        bzero(buffer, MAX_BUFFER_LEN);
        if ((Bytes = read(sockfd, buffer, CIPHER_MAX_LEN + VI_MAX_LEN)) != 0) // while loop stop here every time -> msg received -> continue
        {
            decrypt_data_with_symetric_key(symetric_key, buffer, decrypted_msg);
            //printf("decrypted_msg = %s \n", decrypted_msg + sizeof(Remote_Username));
            //retreive username from received buffer 
            memcpy(Remote_Username, decrypted_msg, sizeof(Remote_Username));

            printf("\r[%s]: %s\n", Remote_Username, (decrypted_msg + sizeof(Remote_Username)));
            fflush(stdout);

            //fixing input after receiving a message from remote
            printf("[Me]: ");
            fflush(stdout);
        }
    }
}

void *Send_()
{
    //initialisation
    char buffer[MAX_BUFFER_LEN];
    unsigned char iv[VI_MAX_LEN];
    char encrypted[CIPHER_MAX_LEN + VI_MAX_LEN];

    while (1)
    {
        bzero(buffer, sizeof(buffer));
        bzero(iv, sizeof(iv));
        bzero(encrypted, sizeof(encrypted));

        printf("[Me] :");
        scanf(" %[^\n]s", (buffer + USERNAME_lEN)); // while loop stops here every time -> input -> continue

        //printf("buffer to be sent : %s\n", buffer);
        memcpy(buffer, local_username, USERNAME_lEN);

        //encrypt data then send it to remote
        encrypt_data_with_symetric_key(symetric_key, iv, buffer, encrypted);
        write(sockfd, encrypted, sizeof(encrypted));
    }
}