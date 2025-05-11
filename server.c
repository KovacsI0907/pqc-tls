#include <string.h>

#ifdef _WIN32
# include <stdarg.h>
# include <winsock2.h>
#else
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>
#endif

#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const char cache_id[] = "OpenSSL Demo Server";


// error handling funtions from the openssl wiki
#ifdef _WIN32
static const char *progname;

static void vwarnx(const char *fmt, va_list ap)
{
    if (progname != NULL)
        fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
}

static void errx(int status, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
    exit(status);
}

static void warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
#endif

int main()
{
    // return variable for main
    int res = EXIT_FAILURE;
    const char * port = "7788";
    SSL_CTX *ctx = NULL;
    const int min_protocol_version = TLS1_3_VERSION; // could also allow TLS1_2_VERSION

    // create server type CTX object
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create SSL_CTX");
    }

    if (!SSL_CTX_set_min_proto_version(ctx, min_protocol_version)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to set the minimum TLS protocol version");
    }

    // options copied from wiki
    long opts;
    /*
     * Tolerate clients hanging up without a TLS "shutdown".  Appropriate in all
     * application protocols which perform their own message "framing", and
     * don't rely on TLS to defend against "truncation" attacks.
     */
    opts = SSL_OP_IGNORE_UNEXPECTED_EOF;

    /*
     * Block potential CPU-exhaustion attacks by clients that request frequent
     * renegotiation.  This is of course only effective if there are existing
     * limits on initial full TLS handshake or connection rates.
     */
    opts |= SSL_OP_NO_RENEGOTIATION;

    /*
     * Most servers elect to use their own cipher preference rather than that of
     * the client.
     */
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;


    SSL_CTX_set_options(ctx, opts);

    // load chain cert file (chain of certs up to the rootCA)
    if (SSL_CTX_use_certificate_chain_file(ctx, "chain.pem") <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to load the server certificate chain file");
    }

    // load pkey and check if it matches the cert in chain.pem
    if (SSL_CTX_use_PrivateKey_file(ctx, "pkey.pem", SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error loading the server private key file or certificate-private key mismatch");
    }

    // needed for session resumption (ID to separate caches by)
    SSL_CTX_set_session_id_context(ctx, (void *)cache_id, sizeof(cache_id));
    // enable caching
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    // set how many connections to cache
    SSL_CTX_sess_set_cache_size(ctx, 1024);

    // time cache remains valid for (in seconds!)
    SSL_CTX_set_timeout(ctx, 3600);

    /*
     * Clients rarely employ certificate-based authentication, and so we don't
     * require "mutual" TLS authentication (indeed there's no way to know
     * whether or how the client authenticated the server, so the term "mutual"
     * is potentially misleading).
     *
     * Since we're not soliciting or processing client certificates, we don't
     * need to configure a trusted-certificate store, so no call to
     * SSL_CTX_set_default_verify_paths() is needed.  The server's own
     * certificate chain is assumed valid.
     */
    // set verification of the client's certificate
    // we don't verify the client
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // initialize listener BIO
    BIO* acceptor_bio = BIO_new_accept(port);
    if (acceptor_bio == NULL) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error creating acceptor bio");
    }

    printf("Listening on port %s\n", port);

    // socket is created here
    BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
    if (BIO_do_accept(acceptor_bio) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error setting up acceptor socket");
    }

    while (true) {
        // separate BIO for each client
        // SSL obj representing connection
        SSL *ssl;
        unsigned char buf[8192];
        size_t nread;
        size_t nwritten;
        size_t total = 0;

        // clear errors, so we only see ones relevant to this connection
        ERR_clear_error();

        // wait until client connects (blocking)
        if (BIO_do_accept(acceptor_bio) <= 0) {
            continue;
        }

        /* Pop the client connection from the BIO chain */
        BIO *client_bio = BIO_pop(acceptor_bio);
        printf("Client connected\n");

        // init SSL obj
        if ((ssl = SSL_new(ctx)) == NULL) {
            ERR_print_errors_fp(stderr);
            warnx("Error creating SSL object for new connection");
            BIO_free(client_bio);
            continue;
        }
        SSL_set_bio(ssl, client_bio, client_bio);

        // do TlS handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            warnx("Error performing TLS handshake");
            SSL_free(ssl);
            continue;
        }

        // read client message and immediately send back whatever we read
        while (SSL_read_ex(ssl, buf, sizeof(buf), &nread) > 0) {
            if (SSL_write_ex(ssl, buf, nread, &nwritten) > 0 && nwritten == nread) {
                total += nwritten;
                continue;
            }
            warnx("Error echoing client input");
            break;
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        printf("Client connection closed, %zu bytes sent\n", total);
    }

    // unreachable cleanup :)
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}