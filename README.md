# C_WebSocket
Simple TLS Websocket in c implemented for Windows and Linux.

Linux compilation:
```console
gcc -o TLSSocket2 test.c WebSocket.c -lssl -lcrypto
```

```C
const char* URI = "wss://stream.binance.com/ws";
TLS_SOCKET* sock = create_websocket_client(&URI);
if (sock) {
	const char* command = "{\"method\" : \"SUBSCRIBE\", \"params\" : [\"btcusdt@depth10@100ms\"],"
		"\"id\" : 0}";
	SEND(sock, &command);
	for (register size_t i = 0; i < 25; i++) {
		printf("%s\n", RECV(sock));
	}

	close_websocket_client(sock);
}
```
