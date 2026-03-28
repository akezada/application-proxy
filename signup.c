#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define FILENAME "users.txt"
int HashPassword(const char *password, char *hashedPassword)
{
	if(crypto_pwhash_str(hashedPassword,password,strlen(password),
	crypto_pwhash_OPSLIMIT_INTERACTIVE,crypto_pwhash_MEMLIMIT_INTERACTIVE)!=0)
	{
		fprintf(stderr,"Error password hashing\n");
		return -1;
	}
	return 0;
}
int SaveUserToFile(const char *username, const char *hashedPassword)
{
	FILE *file=fopen(FILENAME,"a");
	if(file==NULL)
	{
		fprintf(stderr,"Error opening file\n");
		return -1;
	}
	fprintf(file,"%s:%s\n",username,hashedPassword);
	fclose(file);
	return 0;
}
int main()
{
	if(sodium_init()==-1)
	{
		fprintf(stderr,"Error libsodium\n");
		return 1;
	}
	char username[255];
	char password[255];
	char hashedPassword[crypto_pwhash_STRBYTES]; //128
	
	puts("Enter new username:");
	fgets(username, sizeof(username), stdin);
	username[strcspn(username, "\n")] = '\0';

	puts("Enter new password:");
	fgets(password, sizeof(password), stdin);
	password[strcspn(password, "\n")] = '\0';

	if(HashPassword(password,hashedPassword)!=0)
	{
		return 1;
	}
	if(SaveUserToFile(username,hashedPassword)!=0)
	{
		return 1;
	}
	printf("New user saved\n");
	return 0;
}
