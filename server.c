#include<stdio.h>
#include<string.h>   	//strlen
#include<sys/socket.h>
#include<arpa/inet.h> 	//inet_addr
#include<unistd.h>    	//STDIN_FILENO
#include<stdlib.h> 	//for exit

#define DEFAULT_BUFLEN 512
#define SERVER_PORT 8080

int MessageExchange(int socketDesc)
{
	fd_set fset;                        
	puts("Send some messages..Ctrl^d for end.\n");
	char buffer[DEFAULT_BUFLEN];
	while(1)
	{
		int maxfd=socketDesc>STDIN_FILENO? socketDesc+1:STDIN_FILENO+1;
		FD_ZERO(&fset);
		FD_SET(socketDesc,&fset);
		FD_SET(STDIN_FILENO,&fset);
		
		if(select(maxfd,&fset,NULL,NULL,NULL)<0)
		{
		perror("select failed\n");
		break;
		}
		if(FD_ISSET(socketDesc,&fset))
		{
			memset(buffer,0,DEFAULT_BUFLEN);
			ssize_t n=recv(socketDesc,buffer,DEFAULT_BUFLEN,0);
			
			if(n<=0)
			{
				fprintf(stderr,"Client disconnected\n");
				break;
			}
			printf("Message from client: %s",buffer);
		}
		
		if(FD_ISSET(STDIN_FILENO,&fset))
		{
			memset(buffer,0,DEFAULT_BUFLEN);
			if(fgets(buffer,DEFAULT_BUFLEN,stdin)==NULL)
			{
			printf("end\n");
			break;
			}
			if(send(socketDesc,buffer,strlen(buffer),0)!=strlen(buffer))
			{
				perror("failed send to client\n");
				break;
			}
       
		}
		
	}
	printf("communication done\n");	
	return 0;
}

int main(int argc , char *argv[])
{
    int socketDesc , clientSock;
    struct sockaddr_in  client;
    socklen_t addrSize;
   
    //Create socket
    socketDesc = socket(AF_INET , SOCK_STREAM , 0);
    if (socketDesc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    client.sin_family = AF_INET;
    client.sin_addr.s_addr =inet_addr("127.0.0.1");
    client.sin_port = htons(SERVER_PORT);

    //Bind
    if( bind(socketDesc,(struct sockaddr *)&client , sizeof(client)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socketDesc , 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");

    //accept connection from an incoming client
    clientSock = accept(socketDesc, (struct sockaddr *)&client, &addrSize);
    if (clientSock < 0)
    {
        perror("accept failed");
        return 1;
    }
    puts("Connection accepted");
    
    if(MessageExchange(clientSock)==-1)
    {
    	fprintf(stderr,"message exchange failed\n");
    	close(socketDesc);  
    	return 1;
    }
    close(clientSock);
    
    return 0;
}

