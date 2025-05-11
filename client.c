#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <sys/socket.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void cleanup(SSL_CTX* ctx, SSL* ssl){
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main() {

    // CONSTANTS
    const int min_protocol_version = TLS1_3_VERSION; // could also allow TLS1_2_VERSION
    const char* hostname = "localhost";
    const char* port = "7788";
    const int inet_family = AF_INET;
    const char* message = "Hello there!\n";
    const bool ignore_cert_verify = true;

    // create ssl context used for instantiating SSL objects
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = NULL;
    if(ctx == NULL){
        printf("Failed to create SSL_CTX\n");
        cleanup(ctx, ssl);
        return 1;
    }

    // enable verification of the other party certificate
    if(ignore_cert_verify)
        printf("Certificate verification is turned off!\n");
    else
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // set location of trusted CA's certificates to the default location
    if(!SSL_CTX_set_default_verify_paths(ctx)){
        printf("Failed to set default trusted certificate store\n");
        cleanup(ctx, ssl);
        return 1;
    }

    if(!SSL_CTX_set_min_proto_version(ctx, min_protocol_version)){
        printf("Failed to set min protocol version\n");
        cleanup(ctx, ssl);
        return 1;
    }

    //create SSL object from this context
    ssl = SSL_new(ctx);
    if(ssl == NULL){
        printf("Failed to create SSL object");
        cleanup(ctx, ssl);
        return 1;
    }

    // we could use sockets directly, but the BIO provides it's own abstraction for that
    int sock;
    BIO_ADDRINFO* res;
    const BIO_ADDRINFO* ai = NULL;

    // get the ip addresses associated with this hostname
    if(!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, inet_family, SOCK_STREAM, 0, &res)){
        printf("No IP adresses found for the given hostname");
        cleanup(ctx, ssl);
        return 1;
    }

    // addresses are in a linked list, loop through them
    for(ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)){
        //attempt to create socket
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;
        
        //attempt to connect to other host
        if(!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)){
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
    }

    // TODO check if socket is okay

    BIO_ADDRINFO_free(res);


    //create BIO with the socket
    BIO* bio = BIO_new(BIO_s_socket());
    if(bio == NULL){
        printf("Failed to create BIO object\n");
        BIO_closesocket(sock);
        cleanup(ctx, ssl);
        return 1;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);

    //set this bio as the BIO for the SSL object
    SSL_set_bio(ssl, bio, bio);


    //set client hostname (which is needed for the client hello message)
    if(!SSL_set_tlsext_host_name(ssl, hostname)) {
        printf("Failed to set hostname\n");
        cleanup(ctx, ssl);
        return 1;
    }

    //then set the hostname again for the certificate check
    if(!SSL_set1_host(ssl, hostname)){
        printf("Failed to set the certificate verification\n");
        cleanup(ctx, ssl);
        return 1;
    }

    // do handshake
    if (SSL_connect(ssl) < 1) {
        printf("Failed to connect to the server\n");
        bool cert_error = false;
        // check if the failure happened due to certificate error
        if (SSL_get_verify_result(ssl) != X509_V_OK){
            printf("Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }

        cleanup(ctx, ssl);
        return 1;
    }

    // send a message
    size_t written;
    if (!SSL_write_ex(ssl, message, strlen(message), &written)){
        printf("Failed to send message");
        cleanup(ctx, ssl);
        return 1;
    }

    // indicate we don't want to send anything, by sending a shutdown notification
    SSL_shutdown(ssl);
    printf("Sent message: %s\n", message);

    // read response until buffer is empty
    size_t readbytes; // amount of bytes read
    char buf[1024];

    printf("Received message: ");
    while (SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {
        fwrite(buf, 1, readbytes, stdout);
    }
    printf("\n");

    if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        printf ("Failed reading remaining data\n");
        cleanup(ctx, ssl);
        return 1;
    }
    //if we get here, the other host already closed the connection

    if (SSL_shutdown(ssl) < 1) {
        //return value of 0 means, we closed the connection but the other host has not, so we shouldn't get that value in theory
        printf("Error shutting down\n");
    }


    //cleanup
    cleanup(ctx, ssl);
    return 0;
}