#ifdef _WIN32
#pragma once
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#undef UNICODE

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_RAND_S
#include <windows.h>
#include <winsock2.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <mstcpip.h>
#include <ws2tcpip.h>
#include <rpc.h>
#include <ntdsapi.h>
#include <stdio.h>
#include <tchar.h>
#include <limits.h>
#include <assert.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ntdsapi.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define TLS_MAX_PACKET_SIZE (16384+512)

typedef struct {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)
    int used;        // byte count used from incoming buffer to decrypt current packet
    int available;   // byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted inplace
    char incoming[TLS_MAX_PACKET_SIZE];
} TLS_SOCKET;

#elif __linux__
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
    int sock;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
} TLS_SOCKET;

#endif

typedef struct {
    char* resp_buf;
    int resp_length;
} RESPONSE;

static int tls_connect(TLS_SOCKET* tls_sock, const char* hostname, const char* port);
static void tls_disconnect(TLS_SOCKET* s);
static int tls_write(TLS_SOCKET* s, const void* buffer, int size);
static int tls_read(TLS_SOCKET* s, void* buffer, int size);
static int tls_handshake(TLS_SOCKET* s, const char* hostname, const char* resource);
static char* get_security_key(size_t length);
TLS_SOCKET* create_websocket_client(const char** uri);
void close_websocket_client(TLS_SOCKET* s);
int SEND(TLS_SOCKET* s, const char** command);
RESPONSE* RECV(TLS_SOCKET* s);