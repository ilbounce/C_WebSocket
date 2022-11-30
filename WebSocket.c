#include "WebSocket.h"

static char* get_security_key(size_t length) {
    char charset[] = "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char* key = malloc(length + 1);
    char* r_key = key;
    while (length-- > 0) {
        size_t index = (double)rand() / RAND_MAX * (sizeof charset - 1);
        *(key++) = charset[index];
    }
    *key = '\0';

    return r_key;
}

TLS_SOCKET* create_websocket_client(const char** uri)
{
    TLS_SOCKET* sock = malloc(sizeof(TLS_SOCKET));
    char serv[8];
    char hostname[100];
    char resource[8];
    char* port;
#ifdef _WIN32
    sscanf_s(*uri, "%[^:]://%[^/]%s", serv, 8, hostname, 100, resource, 8);
#elif __linux__
    sscanf(*uri, "%[^:]://%[^/]%s", serv, hostname, resource);
#endif
    if (strcmp(serv, "wss") == 0) {
        port = "443";
    }
    else port = "80";
    if (tls_connect(sock, hostname, port) != 0) {
        printf("Can't connect to %s\n", hostname);
        free(sock);
        return NULL;
    }

    if (tls_handshake(sock, hostname, resource) != 0) {
        free(sock);
        return NULL;
    }

    return sock;
}

void close_websocket_client(TLS_SOCKET* s)
{
    tls_disconnect(s);
}

int SEND(TLS_SOCKET* s, const char** command)
{
    char* frame = malloc(strlen(*command) + 3);
    char* frame_header = malloc(1);
    frame_header[0] = 1 << 7 | 1;

    register int len = strlen(*command);

    if (len < 0x7f) {
        frame_header = realloc(frame_header, 3);
        frame_header[1] = 0 << 7 | len;
        frame_header[2] = '\0';
    }

    else if (len < 1 << 16) {
        frame_header = realloc(frame_header, 5);
        frame_header[1] = 0 << 7 | 0x7e;
        frame_header[2] = (len >> 8) & 0xff;
        frame_header[3] = (len >> 0) & 0xff;
        frame_header[4] = '\0';
    }

    else {
        frame_header = realloc(frame_header, 11);
        frame_header[1] = 0 << 7 | 0x7f;
        for (register size_t i = 2; i < 10; i++) {
            frame_header[i] = (len >> (8 * (10 - i - 1))) & 0xff;
        }
        frame_header[10] = '\0';
    }

#ifdef _WIN32
    register int length = sprintf_s(frame, strlen(*command) + strlen(frame_header) + 2, "%s%s", frame_header, *command);
#elif __linux__
    register int length = sprintf(frame, "%s%s", frame_header, *command);
#endif

    if (tls_write(s, frame, length) != 0) {
        printf("Can't send command\n");
        tls_disconnect(s);
    }
}

char* RECV(TLS_SOCKET* s)
{
    char* resp_buf = NULL;
    char head_buf[2];
    if (tls_read(s, head_buf, sizeof(head_buf)) <= 0) {
        tls_disconnect(s);
        return NULL;
    }
    register size_t response_length = head_buf[1] & 0x7f;

    if (response_length == 0x7e) {
        char add_head_buf[2];
        if (tls_read(s, add_head_buf, sizeof(add_head_buf)) <= 0) {
            tls_disconnect(s);
            return NULL;
        }

        response_length = (unsigned short)((unsigned short)add_head_buf[0] << 8) | (unsigned char)add_head_buf[1];
        resp_buf = malloc(response_length + 1);

        tls_read(s, resp_buf, response_length);
        resp_buf[response_length] = '\0';

    }
    else if (response_length == 0x7f) {
        char add_head_buf[8];
        if (tls_read(s, add_head_buf, sizeof(add_head_buf)) <= 0) {
            tls_disconnect(s);
            return NULL;
        }

        response_length = 0;
        for (int i = 0; i < 8; i++) {
            response_length = (long long)((response_length << 8) | add_head_buf[i]);
        }

        resp_buf = malloc(response_length + 1);

        tls_read(s, resp_buf, response_length);
        resp_buf[response_length] = '\0';

    }

    else {
        resp_buf = malloc(response_length + 1);

        tls_read(s, resp_buf, response_length);
        resp_buf[response_length] = '\0';

    }

    return resp_buf;
}

static int tls_handshake(TLS_SOCKET* s, const char* hostname, const char* resource)
{
    char* key = get_security_key(16);
    char* handshake_response = malloc(5);
#ifdef _WIN32
    strcpy_s(handshake_response, 5, "GET ");
    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(resource) + 2);
    strcat_s(handshake_response, strlen(handshake_response) + strlen(resource) + 3, resource);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 39);
    strcat_s(handshake_response, strlen(handshake_response) + 40, " HTTP/1.1\r\nUpgrade: websocket\r\nHost: ");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(hostname) + 2);
    strcat_s(handshake_response, strlen(handshake_response) + strlen(hostname) + 3, hostname);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 19);
    strcat_s(handshake_response, strlen(handshake_response) + 20, "\r\nOrigin: http://");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(hostname) + 2);
    strcat_s(handshake_response, strlen(handshake_response) + strlen(hostname) + 3, hostname);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 23);
    strcat_s(handshake_response, strlen(handshake_response) + 24, "\r\nSec-WebSocket-Key: ");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(key) + 2);
    strcat_s(handshake_response, strlen(handshake_response) + strlen(key) + 3, key);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 53);
    strcat_s(handshake_response, strlen(handshake_response) + 54, "\r\nSec-WebSocket-Version: 13\r\nConnection: Upgrade\r\n\r\n");
#elif __linux__
    strcpy(handshake_response, "GET ");
    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(resource) + 2);
    strcat(handshake_response, resource);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 39);
    strcat(handshake_response, " HTTP/1.1\r\nUpgrade: websocket\r\nHost: ");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(hostname) + 2);
    strcat(handshake_response, hostname);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 19);
    strcat(handshake_response, "\r\nOrigin: http://");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(hostname) + 2);
    strcat(handshake_response, hostname);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 23);
    strcat(handshake_response, "\r\nSec-WebSocket-Key: ");

    handshake_response = realloc(handshake_response, strlen(handshake_response) + strlen(key) + 2);
    strcat(handshake_response, key);

    handshake_response = realloc(handshake_response, strlen(handshake_response) + 53);
    strcat(handshake_response, "\r\nSec-WebSocket-Version: 13\r\nConnection: Upgrade\r\n\r\n");
#endif
    if (tls_write(s, handshake_response, strlen(handshake_response)) != 0) {
        printf("Can't handshake to %s\n", hostname);
        tls_disconnect(s);
        return -1;
    }
    char buf[1024];
    if (tls_read(s, buf, sizeof(buf)) <= 0) {
        printf("Can't handshake to %s\n", hostname);
        tls_disconnect(s);
        return -1;
    }

    return 0;
}

static int tls_connect(TLS_SOCKET* tls_sock, const char* hostname, const char* port)
{
#ifdef _WIN32
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        return -1;
    }

    char ip[50];

    struct hostent* remoteHost;

    remoteHost = gethostbyname(hostname);

    struct in_addr* addr = malloc(sizeof(struct in_addr));

    if (remoteHost->h_addrtype == AF_INET)
    {
        addr->s_addr = *(u_long*)remoteHost->h_addr_list[0];
        printf("IP Address: %s\n", inet_ntoa(*addr));
    }

    // create TCP IPv4 socket
    tls_sock->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tls_sock->sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    // connect to server
    if (!WSAConnectByNameA(tls_sock->sock, inet_ntoa(*addr), port, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        closesocket(tls_sock->sock);
        WSACleanup();
        return -1;
    }

    // initialize schannel
    {
        SCHANNEL_CRED cred =
        {
            .dwVersion = SCHANNEL_CRED_VERSION,
            .dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
                     | SCH_CRED_MANUAL_CRED_VALIDATION  // automatically validate server certificate
                     | SCH_CRED_NO_DEFAULT_CREDS,     // no client certificate authentication
            .grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT,  // allow only TLS v1.2
        };

        if (AcquireCredentialsHandleA(hostname, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL,
            NULL, &tls_sock->handle, NULL) != SEC_E_OK)
        {
            closesocket(tls_sock->sock);
            WSACleanup();
            return -1;
        }

        tls_sock->received = tls_sock->used = tls_sock->available = 0;
        tls_sock->decrypted = NULL;

        // perform tls handshake
        // 1) call InitializeSecurityContext to create/update schannel context
        // 2) when it returns SEC_E_OK - tls handshake completed
        // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
        // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
        // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
        // 6) otherwise read data from server and go to step 1

        CtxtHandle* context = NULL;
        int result = 0;
        for (;;)
        {
            SecBuffer inbuffers[2] = { 0 };
            inbuffers[0].BufferType = SECBUFFER_TOKEN;
            inbuffers[0].pvBuffer = tls_sock->incoming;
            inbuffers[0].cbBuffer = tls_sock->received;
            inbuffers[1].BufferType = SECBUFFER_EMPTY;

            SecBuffer outbuffers[1] = { 0 };
            outbuffers[0].BufferType = SECBUFFER_TOKEN;

            SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
            SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

            DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_STREAM;
            SECURITY_STATUS sec = InitializeSecurityContextA(
                &tls_sock->handle,
                context,
                context ? NULL : (SEC_CHAR*)hostname,
                flags,
                0,
                0,
                context ? &indesc : NULL,
                0,
                context ? NULL : &tls_sock->context,
                &outdesc,
                &flags,
                NULL);

            // after first call to InitializeSecurityContext context is available and should be reused for next calls
            context = &tls_sock->context;

            if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                MoveMemory(tls_sock->incoming, tls_sock->incoming + (tls_sock->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
                tls_sock->received = inbuffers[1].cbBuffer;
            }
            else
            {
                tls_sock->received = 0;
            }

            if (sec == SEC_E_OK)
            {
                // tls handshake completed
                break;
            }
            else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
            {
                // server asked for client certificate, not supported here
                result = -1;
                break;
            }
            else if (sec == SEC_I_CONTINUE_NEEDED)
            {
                // need to send data to server
                char* buffer = outbuffers[0].pvBuffer;
                int size = outbuffers[0].cbBuffer;

                while (size != 0)
                {
                    int d = send(tls_sock->sock, buffer, size, 0);
                    if (d <= 0)
                    {
                        break;
                    }
                    size -= d;
                    buffer += d;
                }
                FreeContextBuffer(outbuffers[0].pvBuffer);
                if (size != 0)
                {
                    // failed to fully send data to server
                    result = -1;
                    break;
                }
            }
            else if (sec != SEC_E_INCOMPLETE_MESSAGE)
            {
                if (sec == SEC_E_CERT_EXPIRED) printf("%s\n", "SEC_E_CERT_EXPIRED");
                else if (sec == SEC_E_WRONG_PRINCIPAL) printf("%s\n", "SEC_E_WRONG_PRINCIPAL");
                else if (sec == SEC_E_UNTRUSTED_ROOT) printf("%s\n", "SEC_E_UNTRUSTED_ROOT");
                else if (sec == SEC_E_ILLEGAL_MESSAGE) printf("%s\n", "SEC_E_ILLEGAL_MESSAGE");
                else if (sec == SEC_E_ALGORITHM_MISMATCH) printf("%s\n", "SEC_E_ALGORITHM_MISMATCH");
                // SEC_E_CERT_EXPIRED - certificate expired or revoked
                // SEC_E_WRONG_PRINCIPAL - bad hostname
                // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
                // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
                result = -1;
                break;
            }

            // read more data from server when possible
            if (tls_sock->received == sizeof(tls_sock->incoming))
            {
                // server is sending too much data instead of proper handshake?
                result = -1;
                break;
            }

            int r = recv(tls_sock->sock, tls_sock->incoming + tls_sock->received, sizeof(tls_sock->incoming) - tls_sock->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // socket error
                result = -1;
                break;
            }
            tls_sock->received += r;
        }

        if (result != 0)
        {
            DeleteSecurityContext(context);
            FreeCredentialsHandle(&tls_sock->handle);
            closesocket(tls_sock->sock);
            WSACleanup();
            return result;
        }

        QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &tls_sock->sizes);

        return 0;
    }

#elif __linux__
    struct hostent* remoteHost;
    struct in_addr* addr = malloc(sizeof(struct in_addr));
    struct sockaddr_in serv_addr;
    char ip[50];

    remoteHost = gethostbyname(hostname);
    if (remoteHost->h_addrtype == AF_INET)
    {
        addr->s_addr = *(u_long*)remoteHost->h_addr_list[0];
        printf("IP Address: %s\n", inet_ntoa(*addr));
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(port));

    inet_pton(AF_INET, inet_ntoa(*addr), &serv_addr.sin_addr);

    tls_sock->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tls_sock->sock == -1) {
        return -1;
    }
    if (connect(tls_sock->sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(tls_sock->sock);
    }
    SSL_library_init();
    SSL_load_error_strings();

    tls_sock->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (tls_sock->ssl_ctx == NULL) {
        printf("%s\n", "Can't initialize SSL Context");
        close(tls_sock->sock);
        return -1;
    }
    tls_sock->ssl = SSL_new(tls_sock->ssl_ctx);
    if (tls_sock->ssl == NULL) {
        printf("%s\n", "Can't initialize SSL");
        close(tls_sock->sock);
        return -1;
    }

    if (!SSL_set_fd(tls_sock->ssl, tls_sock->sock)) {
        printf("%s\n", "Can't set SSL");
        close(tls_sock->sock);
        return -1;
    }

    if (SSL_connect(tls_sock->ssl) != 1) {
        printf("%s\n", "Can't connect SSL");
        close(tls_sock->sock);
        return -1;
    }

    return 0;
#endif
}

static void tls_disconnect(TLS_SOCKET* s)
{
#ifdef _WIN32
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
    WSACleanup();
#elif __linux__
    SSL_shutdown(s->ssl);
    SSL_free(s->ssl);
    SSL_ctx_free(s->ssl_ctx);
    shutdown(s->sock, SHUT_WR);
    close(s->sock);
#endif
}

static int tls_write(TLS_SOCKET* s, const void* buffer, int size)
{
#ifdef _WIN32
    while (size != 0)
    {
        int use = min(size, s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }
#elif __linux__
    SSL_write(s->ssl, buffer, size);
#endif

    return 0;
}

static int tls_read(TLS_SOCKET* s, void* buffer, int size)
{
    int result = 0;
#ifdef _WIN32

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            s->received += r;
        }
    }
#elif __linux__
    result = SSL_read(s->ssl, buffer, size);
#endif

    return result;
}