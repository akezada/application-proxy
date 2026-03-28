#include<stdio.h>
#include<string.h>    	//strlen
#include<sys/socket.h>
#include<sys/select.h>
#include<arpa/inet.h> 	//inet_addr
#include<unistd.h>    	
#include<stdlib.h>
#include<sodium.h>	//crypto_pwhash_str_verify
#include<errno.h>	//error num

#define DEFAULT_BUFLEN 512
#define PROXY_PORT   1080
#define SERVER_PORT   8080
#define SOCKS_VERSION 0x05
#define MAX_LEN 255


int MethodSelection(int sockDesc)
{
        unsigned char buffer[DEFAULT_BUFLEN];
	ssize_t n=recv(sockDesc,buffer,sizeof(buffer),0);
	if(n<=0)
	{
		perror("receive failed");
		return -1;
	}
	
	unsigned char ver=buffer[0];
	unsigned char nmethods=buffer[1];
	unsigned char methods[nmethods];
	if(ver!=SOCKS_VERSION)
	{
		fprintf(stderr,"invalid socks version");
		return -1;
	}
	if(nmethods<=0)
	{
		fprintf(stderr,"zero methods for authentication");
		return -1;
	}
	unsigned char supportedMethod=0xFF;
	for(int i=0;i<nmethods;i++)
	{
		methods[i]=buffer[i+2];
		if(methods[i]==0x02)
		{
			supportedMethod=0x02;
			puts("Username/password method selected for authentication");
			break;
		}
	}
	unsigned char response[2]={SOCKS_VERSION,supportedMethod};
	if(send(sockDesc,response,2,0)!=2)
	{
		perror("method selection message send failed");
		return -1;
	}
	
	return 0;
}
int SubNegotiation(int sockDesc)
{
	unsigned char ver, usernameLength,passwordLength;
	char username[MAX_LEN+1];
	char password[MAX_LEN+1];
	if(recv(sockDesc,&ver,1,0)!=1 ||ver!=0x01)
	{
	 	fprintf(stderr,"invalid auth subnegotiation version");
	 	return -1; 
	}
	//process username
	if(recv(sockDesc,&usernameLength,1,0)!=1)
	{
	 	perror("receive failed");
	 	return -1; 
	}
	if(usernameLength>MAX_LEN)
	{
		fprintf(stderr,"invalid username lenght");
	 	return -1; 
	}
	if(recv(sockDesc,username,usernameLength,0)!=usernameLength)
	{
	 	perror("receive failed");
	 	return -1; 
	}
	username[usernameLength]='\0';
	//process password
	if(recv(sockDesc,&passwordLength,1,0)!=1)
	{
	 	perror("receive failed");
	 	return -1; 
	}
	if(passwordLength>MAX_LEN)
	{
		fprintf(stderr,"invalid password lenght");
	 	return -1; 
	}
	if(recv(sockDesc,password,passwordLength,0)!=passwordLength)
	{
	 	perror("receive failed");
	 	return -1; 
	}
	password[passwordLength]='\0';
	unsigned char response[2]={0x01,0x01}; //fail
	
	FILE *fp=fopen("users.txt","r");
	if(!fp)
	{
		perror("Could not open users.txt");
		return -1;
	}
	char line[DEFAULT_BUFLEN];
	while(fgets(line,sizeof(line),fp))
	{
		char validUser[MAX_LEN];
		char hash[crypto_pwhash_STRBYTES+1];
		char *c=strchr(line,':');
		if(!c)continue;
		
		size_t len=c-line;
		if(len>=MAX_LEN) continue;
		strncpy(validUser,line,len);
		validUser[len]='\0';
		
		char *addrHash=c+1;
		addrHash[strcspn(addrHash,"\r\n")]='\0';
		strncpy(hash,addrHash,sizeof(hash)-1);
		hash[sizeof(hash)-1]='\0';
		
		if(strcmp(validUser,username)==0)
		{
			if(crypto_pwhash_str_verify(hash,password,strlen(password))==0)
			{
				response[1]=0x00; //success
			}
		}
		
	}
	
	if(send(sockDesc,response,2,0)!=2)
	{
		perror("send failed");
		return -1;
	}
	fclose(fp);
	return response[1]==0x00? 0:-1;
}
int SockMsg(int sockDesc,char *ipstr, uint16_t *port)
{
	unsigned char message[10];
	if(recv(sockDesc,message,10,0)!=10)
	{
		perror("receive failed");
		return -1;
	}
	unsigned char ver=message[0];
	unsigned char cmd=message[1];
	unsigned char rsv=message[2];
	unsigned char atyp=message[3];
	if(ver!=SOCKS_VERSION)
	{
		perror("invalid socks version");
		return -1;
	}
	if(cmd!=0x01)
	{
		perror("command not supported");
		return -1;
	}
	if(rsv!=0x00)
	{
		perror("rsv should be 0");
		return -1;
	}
	if(atyp!=0x01)
	{
		perror("invalid ip version");
		return -1;
	}
	printf("Connecting to server:");
	inet_ntop(AF_INET,&message[4],ipstr,16);
	printf(" %s:",ipstr); 				//ip
	*port=((uint16_t)message[8]<<8)|message[9];
	printf("%u...\n",(unsigned int)(*port));	//port
	
	return 0;
}
uint8_t ErrnoRep(int err)
{
	switch(err)
	{
		case ECONNREFUSED:	return 0x05; //Connection refused
		case ENETUNREACH:	return 0x03; //Network unreachable
		case EHOSTUNREACH: 	return 0x04; //Host unreachable
		case EACCES: 		return 0x02; //Not allowed by ruleset
		case ETIMEDOUT:		return 0x04; //Host unreachable
		case EADDRNOTAVAIL: 	return 0x05; //General failure
		default: 	    	return 0x01; //General socks server failure
	}
}
int SetServer(struct sockaddr_in proxyServer,int serverSock,char *ipstr, uint16_t port,uint8_t *rep)
{
	proxyServer.sin_family = AF_INET;
	proxyServer.sin_addr.s_addr = inet_addr(ipstr);
	proxyServer.sin_port = htons(port); 

	
	if (connect(serverSock, (struct sockaddr *)&proxyServer, sizeof(proxyServer)) < 0)
    	{
		perror("Error, connect to server failed.\n");
		*rep=ErrnoRep(errno);
		close(serverSock);
		return -1;
    	}
    	puts("Connected!\n");
    	*rep=0x00;
    	return 0;
}
int SocksResponse(int sockDesc,int sockProxy, uint8_t rep)
{
	struct sockaddr_in addrProxy;
	socklen_t addrLength=sizeof(addrProxy);
	
	if(getsockname(sockProxy,(struct sockaddr *)&addrProxy,&addrLength)<0)
	{
		perror("getsockname failed");
		return -1;
	}
	
	unsigned char reply[10];
	reply[0]=SOCKS_VERSION;
	reply[1]=rep;
	reply[2]=0x00; //rsv is always 0x00
	reply[3]=0x01; //adress type, 0x01 for IPv4
	
	memcpy(&reply[4],&addrProxy.sin_addr,4);
	memcpy(&reply[8],&addrProxy.sin_port,2);
	
	if(send(sockDesc,reply,10,0)!=10)
	{
	perror("send failed");
	return -1;
	}
	return 0;
}
int MsgForward(int serverSock, int clientSock)
{
	unsigned char buffer[DEFAULT_BUFLEN];
	printf("Forwarding messages..\n");
	while(1)
	{
		int maxfd=serverSock>clientSock? serverSock+1:clientSock+1;
		fd_set fset;
		FD_ZERO(&fset);
		FD_SET(serverSock,&fset);
		FD_SET(clientSock,&fset);
		
		if(select(maxfd,&fset,NULL,NULL,NULL)<0)
		{
		perror("select failed\n");
		break;
		}
		if(FD_ISSET(clientSock,&fset))
		{
			ssize_t n=recv(clientSock,buffer,DEFAULT_BUFLEN,0);
			if(n<=0)break;
			if(send(serverSock,buffer,n,0)!=n)
			{
				perror("failed send to server");
				break;
			}
			puts("A message has been forwarded to the server!");
		}
		
		if(FD_ISSET(serverSock,&fset))
		{
			ssize_t n=recv(serverSock,buffer,DEFAULT_BUFLEN,0);
			if(n<=0)break;
			if(send(clientSock,buffer,n,0)!=n)
			{
				perror("failed send to client");
				break;
			}
			puts("A message has been forwarded to the client!");
		}
		
	}
	printf("communication done\n");	
	return 0;
}
int main(int argc , char *argv[])
{
    int serverSock ,clientSock;
    struct sockaddr_in proxyClient,proxyServer;
    socklen_t addrSize;
    
    //za adresu i port:
    char ipstr[16]={0};
    uint16_t port=0;
    //Create socket
    serverSock = socket(AF_INET , SOCK_STREAM , 0);
    if (serverSock == -1)
    {
        printf("Could not create socket");
    }
    puts("Server socket created");
    
    clientSock = socket(AF_INET , SOCK_STREAM , 0);
    if (clientSock== -1)
    {
        printf("Could not create socket");
    }
    puts("Client socket created");
    //Prepare the sockaddr_in structure
    proxyClient.sin_family = AF_INET;
    proxyClient.sin_addr.s_addr = inet_addr("127.0.0.1");
    proxyClient.sin_port = htons(PROXY_PORT);	//1080

    if( bind(clientSock,(struct sockaddr *)&proxyClient , sizeof(proxyClient)) < 0)
    {
        perror("bind failed");
        return 1;
    }
    puts("Bind done");

    //Listen
    listen(clientSock, 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    	
    int clientDesc=accept(clientSock,(struct sockaddr *)&proxyClient,&addrSize);
    if(clientDesc<0)
    {
	    perror("Accept failed");
	    return 1;	
    }
    puts("Client connected");
	
    if(MethodSelection(clientDesc)==-1)
    {
	    perror("method selection failed\n");
	    return 1;
    }
	//login with 3 attempts
	int maxAttempts = 3;
	int attempts = 0;
	int negotiationSuccess = 0;
	while ((attempts < maxAttempts) && !negotiationSuccess)
	{
		attempts++;
		if (SubNegotiation(clientDesc) == -1)
		{
			fprintf(stderr,"Sub negotiation failed\n");
			printf("Attempt %d/%d\n", attempts, maxAttempts);
			
			if (attempts == maxAttempts)
			{
				fprintf(stderr, "All attempts failed, connection refused\n");
				return 1;
			}
		} 
		else
		{
			puts("Sub negotiation successful. Client has been authenticated");
			negotiationSuccess = 1;
		}
		
	}	

    if(SockMsg(clientDesc,ipstr,&port)==-1)
    {
	fprintf(stderr,"Socket message error\n");
    	return 1;
    }
    uint8_t rep=0x09;	 //unassigned
    if (SetServer(proxyServer, serverSock, ipstr, port, &rep) == -1)
    {
    	fprintf(stderr,"Sub negotiation failed\n");
    	return 1;
    }
    if(serverSock<=0)
    {
	fprintf(stderr,"Server set failed\n");
    	return 1;
    }
    if(SocksResponse(clientDesc,serverSock,rep)==-1)
    {
	fprintf(stderr,"Sock response error\n");
    	return 1;
    }
    if(MsgForward(serverSock,clientDesc)==-1)
    {
    	fprintf(stderr,"Message forward failed\n");
    	return 1;
    }
    close(serverSock);
    close(clientDesc);
    return 0;

}

