# C_WebSocket
Simple TLS Websocket in c implemented for Windows and Linux.

Linux compilation:
```console
gcc -o TLSSocket2 test.c WebSocket.c -lssl -lcrypto
```

Usage Example:
```C
const char* URI = "wss://stream.binance.com/ws";
TLS_SOCKET* sock = create_websocket_client(&URI);
if (sock) {
	const char* command = "{\"method\" : \"SUBSCRIBE\", \"params\" : [\"btcusdt@depth10@100ms\"],"
		"\"id\" : 0}";
	SEND(sock, &command);
	for (register size_t i = 0; i < 25; i++) {
		RESPONSE* response = RECV(sock);
		char* msg = response->resp_buf;
		printf("%s\n", msg);

		free(response->resp_buf);
		free(response);
	}

	close_websocket_client(sock);
}
```
