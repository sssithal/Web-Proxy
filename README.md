Application Usage:
This application acts as a proxy server with SSL support, designed to intercept, forward, and 
potentially block HTTP and HTTPS requests based on a list of forbidden sites. Users launch it 
with command-line arguments specifying a listening port, a forbidden sites file, and a log file 
path.

Internal Design:
The proxy listens for client requests, forks a child process for each connection, and checks 
if the request targets a forbidden site. Allowed HTTP requests are directly forwarded, while 
HTTPS requests are relayed through an SSL-secured connection to the destination. Access details, 
including blocked attempts, are logged. The proxy can dynamically reload the forbidden sites list 
upon receiving a SIGINT signal, ensuring resource cleanup post-request handling.


List of Tests:
- ./myproxy 8080 /Users/shipraithal/Important/cse156/final/forbidden.txt /Users/shipraithal/Important/cse156/final/access.log
    curl -x http://localhost:8080/ http://www.youtube.com

- ./myproxy 8080 /Users/shipraithal/Important/cse156/final/forbidden.txt /Users/shipraithal/Important/cse156/final/access.log
    curl -x http://localhost:8080/ http://www.google.com

- ./myproxy 8080 /Users/shipraithal/Important/cse156/final/forbidden.txt /Users/shipraithal/Important/cse156/final/access.log
    curl -x http://localhost:8080/ http://www.example.com

- ./myproxy 8080 /Users/shipraithal/Important/cse156/final/forbidden.txt /Users/shipraithal/Important/cse156/final/access.log
    curl -x http://localhost:8080/ http://www.bookface.com

- ./myproxy 9090 /Users/shipraithal/Important/cse156/final/forbidden.txt /Users/shipraithal/Important/cse156/final/access.log
curl -x http://localhost:9090/ http://www.youtube.com
