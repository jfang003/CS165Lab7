//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337";
	//SSL_write
	int buff_len=0;
	buff_len = SSL_write(ssl, randomNumber.c_str(), BUFFER_SIZE);
    
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    char* buff="FIXME";
    int len=5;
	//SSL_read;
	buff_len=0;
	char buffs[128];
	memset(buffs, 0, sizeof(buffs));
	buff_len = SSL_read(ssl, buffs, 128);
	buff = buffs;

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, 128).c_str(), 128);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free

	BIO* mem = BIO_new(BIO_s_mem());//BIO_new(BIO_s_mem());
	if(BIO_write(mem, randomNumber.c_str(), randomNumber.size())<=0)//BIO_write
		printf("ERROR.\n");
	BIO* hash = BIO_new(BIO_f_md()); //BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());//BIO_set_md;
	BIO_push(hash, mem);//BIO_push;
	char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen = BIO_read(hash, mdbuf, EVP_MAX_MD_SIZE);//BIO_gets;

	BIO* rsapublic = BIO_new_file("rsapublickey.pem", "r");
	RSA* pub = PEM_read_bio_RSA_PUBKEY(rsapublic, NULL, 0, NULL);
	unsigned char* decrypt = (unsigned char*) malloc(RSA_size(pub));
	memset(decrypt, 0, RSA_size(pub));
	RSA_public_decrypt(128, (unsigned char*)buff, decrypt, pub, RSA_PKCS1_PADDING);
	
	string generated_key=buff2hex((unsigned char *)mdbuf,randomNumber.size());
	string decrypted_key=buff2hex(decrypt,randomNumber.size());
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	char* buffer_s;
	PAUSE(2);
	BIO_flush(client);
  //BIO_puts(client, filename);
	SSL_write(ssl, (unsigned char *)filename, BUFFER_SIZE);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...\n");

    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free
	BIO* boutfile = BIO_new_file("DocOut.txt", "w") ;
	int read_bytes = 0;
	char buffer[1024];
	memset(buffer,0,sizeof(buffer));
	while((read_bytes = SSL_read(ssl, buffer, BUFFER_SIZE/2))!=0)
	{
		if(read_bytes==-1)
		{
			printf("Error while reading file(ssl).\n");
      print_errors();
			exit(EXIT_FAILURE);
		}
		RSA_public_decrypt(128, (unsigned char*)buffer, decrypt, pub, RSA_PKCS1_PADDING);
		printf("%s", decrypt);
		memset(buffer,0,sizeof(buffer));	
		BIO_flush(client);
		BIO_write(boutfile, decrypt, read_bytes);
	}
	BIO_free(boutfile);

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	int shutdown =0;
	while(shutdown != 1)
	{
		if(shutdown==-1)
		{
			printf("ERROR.\n");
		}
		shutdown = SSL_shutdown(ssl);
	}
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!

	char buf[256];
int err;
while ((err = ERR_get_error()) != 0) {
ERR_error_string_n(err, buf, sizeof(buf));
printf("*** %s\n", buf);
}

	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
