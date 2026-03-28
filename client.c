#include<stdio.h>       //printf
#include<string.h>      //strlen
#include<sys/socket.h>  //socket
#include<arpa/inet.h>   //inet_addr
#include <unistd.h>     //for close, STDIN_FILENO
#include <stdlib.h> 	//for exit

#define DEFAULT_BUFLEN 512
#define PROXY_PORT 1080
#define SERVER_PORT 8080
#define SOCKS_VERSION 0x05
#define MAX_LEN 255

int SelectionMessage(int sockDesc)
{
	unsigned char message[4];
	message[0]=SOCKS_VERSION;
	message[1]=0x02; 	//num of methods
	message[2]=0x00; 	//no authentication required
	message[3]=0x02; 	//username/password
	
	if(send(sockDesc,message,sizeof(message),0)!=sizeof(message))
	{
		perror("Send failed\n");
		return -1;
	}

	puts("Method offer sent");
	return 0;
		
}
int MethodSelection(int sockDesc)
{
	unsigned char response[2];
	if(recv(sockDesc,response,2,0)!=2)
	{
		perror("Receive failed\n");
		return -1;
	}
	if(response[0]!=SOCKS_VERSION)
	{
		fprintf(stderr,"Unsupported version.\n");
		return -1;
	}
	if(response[1]==0xff)	
	{
		fprintf(stderr,"Method selection send failed.\n");	
		return -1;
	}
	if (response[1] == 0x02)
	{
		puts("Username/Password method selected by proxy");		
	}
	return 0;
}
int SubNegotiation(int sockDesc, const char* username,const char* password)
{
	size_t usernameLength=strlen(username);
	size_t passwordLength=strlen(password);
	if(usernameLength > MAX_LEN || passwordLength > MAX_LEN)
	{
		fprintf(stderr,"username or password too long\n");
		return -1;
	}
	
	unsigned char buffer[DEFAULT_BUFLEN];
	int offset=0;
	
	buffer[offset++]=0x01; 
	buffer[offset++]=usernameLength;
	memcpy(buffer+offset,username,usernameLength);
	offset+=usernameLength;
	
	buffer[offset++]=passwordLength;
	memcpy(buffer+offset,password,passwordLength);
	offset+=passwordLength;
	//username-password request
	if(send(sockDesc,buffer,offset,0)!=offset)
	{
		perror("Auth message send failed\n");
		return -1;
	}
	//puts("Auth message sent");
	//receive response
	unsigned char response[2];
	if(recv(sockDesc,response,2,0)!=2)
	{
		perror("Receive failed\n");
		return -1;
	}
	if(response[0]!=0x01 || response[1]!=0x00)
	{
		fprintf(stderr,"Invalid username or password.\n");
		return -1;												
	}
	
	return 0;
}
int SockRequest(int sockDesc)
{
	unsigned char request[10];
	request[0]=SOCKS_VERSION;
	request[1]=0x01; //connect
	request[2]=0x00; //reserved
	request[3]=0x01; //IPv4
	int offset=4;
	request[offset++]=127;
	request[offset++]=0;
	request[offset++]=0;
	request[offset++]=1;
	uint16_t port=htons(SERVER_PORT); //8080
	memcpy(request+offset,&port,2);
	offset+=2;
	if(send(sockDesc,request,offset,0)!=offset)
	{
		perror("send failed");
		return -1;
	}
	puts("Connecting to server...");
	return 0;
}
int SockResponse(int sockDesc)
{
	unsigned char message[10];
	if(recv(sockDesc,message,10,0)!=10)
	{
		fprintf(stderr,"receive from server failed\n");
		return -1;
	}
	unsigned char ver=message[0];
	unsigned char rep=message[1];
	unsigned char rsv=message[2];
	unsigned char atyp=message[3];
	if(ver!=SOCKS_VERSION)
	{
		fprintf(stderr,"invalid socks version\n");
		return -1;
	}
	if(rep!=0x00)
	{	
		switch(rep)
		{
			case 0x01: fprintf(stderr,"general socks server failure\n");
			break;
			case 0x02: fprintf(stderr,"not allowed by ruleset\n");
			break;
			case 0x03: fprintf(stderr,"network unreachable\n");
			break;
			case 0x04: fprintf(stderr,"host unreachable\n");
			break;
			case 0x05: fprintf(stderr,"connection refused\n");
			break;
			default:   fprintf(stderr,"general socks failure\n");
			break;
		}
		return -1;
	}
	if(rsv!=0x00)
	{
		fprintf(stderr,"rsv should be 0\n");
		return -1;
	}
	if(atyp!=0x01)
	{
		fprintf(stderr,"invalid ip version\n");
		return -1;
	}
	puts("Connected!");
	return 0;
}
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
		perror("Select failed\n");
		break;
		}
		if(FD_ISSET(socketDesc,&fset))
		{
			memset(buffer,0,DEFAULT_BUFLEN);
			ssize_t n=recv(socketDesc,buffer,DEFAULT_BUFLEN,0);
			
			if(n<=0)
			{
				fprintf(stderr,"Server disconnected\n");
				break;
			}
			printf("Message from server: %s",buffer);
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
				perror("failed send to server\n");
				break;
			}
			
		}
		
	}
	printf("communication done\n");	
	return 0;
}
int main(int argc , char *argv[])
{
    struct sockaddr_in server;
    int socketDesc;
    //Create socket
    socketDesc = socket(AF_INET , SOCK_STREAM , 0);
    if (socketDesc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); //PROXY_IP
    server.sin_port = htons(PROXY_PORT); //PROXY_PORT
   
    //Connect to remote server
    if (connect(socketDesc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("Error, connect to server failed.");
        close(socketDesc);
        return 1;
    }
    puts("Connected");
    if(SelectionMessage(socketDesc)==-1) //identifier-method selection message
     {
    	fprintf(stderr,"Id-method selection failed");
    	close(socketDesc);
    	return 1;
    }

    if(MethodSelection(socketDesc)==-1)//method-selection message
    {
    	fprintf(stderr,"Method selection failed\n");
    	close(socketDesc);
    	return 1;
    }
     //login with 3 attempts
	int maxAttempts = 3;
	int attempts = 0;
	int negotiationSuccess = 0;
	while ((attempts < maxAttempts) && !negotiationSuccess)
	{
		
		char username[MAX_LEN] = { 0 }; //MAX_LEN=255
		char password[MAX_LEN] = { 0 };
		printf("Username: \n");
		fgets(username, sizeof(username), stdin);
		username[strcspn(username, "\n")] = '\0';
		printf("Password: \n");
		fgets(password, sizeof(password), stdin);
		password[strcspn(password, "\n")] = '\0';
		attempts++;

		if (SubNegotiation(socketDesc, username, password) == -1)
		{
			fprintf(stderr, "Attempt %d/%d\n",attempts,maxAttempts);
			
			if (attempts == maxAttempts)
			{
				fprintf(stderr,"All attempts failed. Connection refused\n");
				close(socketDesc);
				return 1;
				
			}
		}
		else
		{
			puts("Sub negotiation successful! Proxy has approved the authentication");
			negotiationSuccess = 1;
		}
	}

    if(SockRequest(socketDesc)==-1)
    {
    	fprintf(stderr,"Socket request failed\n");
    	close(socketDesc);
    	return 1;
	}
	

    if(SockResponse(socketDesc)==-1)
    {
    	fprintf(stderr,"Socket response failed\n");
    	close(socketDesc);
    	return 1;
    }
	

    if(MessageExchange(socketDesc)==-1)
    {
    	fprintf(stderr,"Message exchange failed\n"); 
    	close(socketDesc);
    	return 1;
    }
    close(socketDesc);

    return 0;
}

