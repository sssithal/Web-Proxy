#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <signal.h>
#include <unordered_set>
#include <vector>
#include <ctime>
#include <array>
#include <stdexcept>
#include <csignal>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <cstdio>
#include <ctime>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// constexpr size_t LINE = 1024;
constexpr size_t PIPE_MAX = 1024;
constexpr int BACKLOG = 10;  // Max number of pending connections
const int BUFFERSIZE = 1024; // Adjust the buffer size as needed

std::vector<std::string> forbiddenSites;
std::string forbiddenSitesFilePath; // Global variable to hold the path to the forbidden sites file
static std::string accessLogFilePath;

std::string currentClientIP;
std::string currentRequestLine;

struct RequestData
{
  std::string clientIP;
  std::string requestLine;
  int statusCode = 200; // Default to 200 OK
  int responseSize = 0;
};

void loadSiteFiles(const std::string &filePath)
{
  forbiddenSites.clear();
  std::ifstream file(filePath);
  std::string line;
  while (std::getline(file, line))
  {
    std::istringstream iss(line);
    std::string site;
    if (iss >> site)
    {
      forbiddenSites.push_back(line);
    }
  }
}

void logAccess(const std::string &logFilePath, const std::string &clientIP, const std::string &requestLine, int statusCode, int responseSize)
{
  std::cout << "logAccess called with logFilePath: " << logFilePath << std::endl;
  FILE *logFile = fopen(logFilePath.c_str(), "a"); // Open in append mode
  if (!logFile)
  {
    std::cerr << "Failed to open log file at: " << logFilePath << std::endl;
    return;
  }

  // Get current time in the desired format
  auto now = std::chrono::system_clock::now();
  auto nowTimeT = std::chrono::system_clock::to_time_t(now);
  auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

  std::tm *nowTm = std::localtime(&nowTimeT);
  fprintf(logFile, "%d-%02d-%02dT%02d:%02d:%02d.%03ldZ %s \"%s\" %d %d\n",
          nowTm->tm_year + 1900, nowTm->tm_mon + 1, nowTm->tm_mday,
          nowTm->tm_hour, nowTm->tm_min, nowTm->tm_sec,
          nowMs.count(),
          clientIP.c_str(), requestLine.c_str(), statusCode, responseSize);

  fclose(logFile); // Close the file
}

void signalHandler(int signum)
{
  std::cout << "Interrupt signal (" << signum << ") received. Reloading forbidden sites...\n";

  // Reload the forbidden sites file using the global variable
  loadSiteFiles(forbiddenSitesFilePath);

  std::cout << "Forbidden sites reloaded.\n";
}

void errorPrint(const std::string &message)
{
  std::cerr << "\tPID:" << getpid() << " error: " << message << std::endl;
}

void sendError(int clientFd, std::string &writePipe, int err, const std::string &errMsg, const std::string &logFilePath)
{
  writePipe.clear();
  std::ostringstream htmlStream;

  htmlStream << "HTTP/1.0 " << err << " " << errMsg << "\r\n"
             << "Content-Type: text/html; charset=UTF-8\r\n"
             << "Content-Length: 200\r\n\r\n"
             << "<!DOCTYPE html>\n<html lang=en>\n<meta charset=utf-8>\n"
             << "<title>" << err << " " << errMsg << "</title>\n"
             << "<p><b>" << err << "</b> <ins>" << errMsg << "</ins>\n</html>";

  writePipe = htmlStream.str();
  if (write(clientFd, writePipe.c_str(), writePipe.size()) < 0)
  {
    errorPrint("Unable to send to client");
  }

  std::cout << "Logging access for error response." << std::endl;

  std::cout << logFilePath << std::endl;
  std::cout << currentClientIP << std::endl;
  std::cout << currentRequestLine << std::endl;
  std::cout << err << std::endl;
  std::cout << writePipe.size() << std::endl;

  logAccess(logFilePath, currentClientIP, currentRequestLine, err, writePipe.size());
}

void checkHost(const std::string &host, int clientFd, std::string &writePipe)
{
  for (const auto &forbiddenHost : forbiddenSites)
  {
    if (host.find(forbiddenHost) != std::string::npos)
    {
      sendError(clientFd, writePipe, 403, "Forbidden", accessLogFilePath);
      close(clientFd);
      exit(EXIT_FAILURE);
    }
  }
}

int createHostSocket(const std::string &host, int clientFd, std::string &writePipe)
{
  struct addrinfo hints
  {
  }, *servinfo;
  int sockfd, rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(host.c_str(), "80", &hints, &servinfo)) != 0)
  {
    std::cerr << "PID:" << getpid() << " host:" << host << " port:80 addrinfo:" << gai_strerror(rv) << std::endl;
    return -1;
  }

  sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
  if (sockfd == -1)
  {
    errorPrint("Socket build error");
    return -1;
  }

  if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
  {
    errorPrint("Connect fail");
    freeaddrinfo(servinfo);
    return -1;
  }

  freeaddrinfo(servinfo);
  return sockfd;
}

void logError(const std::string &message)
{
  std::cerr << message << std::endl;
  ERR_print_errors_fp(stderr); // Log detailed OpenSSL errors
}

void secureAndSend(int clientFd, const std::string &request, const std::string &host, const std::string &port, const std::string &logFilePath)
{
  // create SSL connection: client -> proxy -> server
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  // method
  const SSL_METHOD *method = SSLv23_method();

  // context
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (ctx == NULL)
  {
    logError("Failed to create SSL context");
    close(clientFd);
    return;
  }

  // socket
  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL)
  {
    logError("Failed to create new SSL socket");
    SSL_CTX_free(ctx);
    close(clientFd);
    return;
  }

  // create new socket
  struct sockaddr_in destSSL_addr;
  int SSL_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (SSL_fd == -1)
  {
    logError("Create Socket Error");
    exit(EXIT_FAILURE);
  }
  else
  {
    logError("Socket created successfully!");
  }

  // initialize socket
  memset(&destSSL_addr, '0', sizeof(destSSL_addr));
  destSSL_addr.sin_family = AF_UNSPEC;
  destSSL_addr.sin_port = htons(std::stoi(port));
  std::cout << "Finished initializing SSL socket" << std::endl;

  struct addrinfo hints, *res;
  int status;
  char ipstr[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET; // Set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(host.c_str(), NULL, &hints, &res)) != 0)
  {
    logError("getaddrinfo: " + std::string(gai_strerror(status)));
    SSL_CTX_free(ctx);
    close(clientFd);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
  inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof ipstr);

  freeaddrinfo(res); // Free the linked list

  if (inet_pton(AF_INET, ipstr, &destSSL_addr.sin_addr) <= 0)
  {
    logError("Invalid IP Address after resolution!");
    SSL_CTX_free(ctx);
    close(clientFd);
    exit(EXIT_FAILURE);
  }
  else
  {
    logError("IP Address resolved and valid.");
  }

  // tcp connect to server
  if (connect(SSL_fd, (struct sockaddr *)&destSSL_addr, sizeof(destSSL_addr)) < 0)
  {
    logError("Connect error");
    exit(EXIT_FAILURE);
  }
  else
  {
    logError("Connected to the Server Successfully!");
  }

  // set fd
  SSL_set_fd(ssl, SSL_fd);
  std::cout << "Set file descriptor for SSL socket" << std::endl;

  // connection
  if (SSL_connect(ssl) <= 0)
  {
    unsigned long sslError = ERR_get_error();
    char errorString[256];
    ERR_error_string_n(sslError, errorString, sizeof(errorString));
    logError("Error connecting via SSL: " + std::string(errorString));
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(clientFd);
    return;
  }
  else
  {
    logError("Connected via SSL!");
    // get certificate
    SSL_get_peer_certificate(ssl);
    // verify it
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  }

  // Send HTTPS request
  if (SSL_write(ssl, request.c_str(), request.length()) <= 0)
  {
    logError("Error sending HTTPS request");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(clientFd);
    return;
  }
  else
  {
    logError("HTTPS Request Sent.");
  }

  // Pipeline data from server's socket to client's socket
  char read_buffer[BUFFERSIZE];
  int bytes_received;
  int totalBytesSent = 0;

  do
  {
    // Read data from the server's socket
    bytes_received = SSL_read(ssl, read_buffer, BUFFERSIZE);
    if (bytes_received > 0)
    {
      std::cout << "received  " << bytes_received << " bytes:" << std::endl;
      // Write data to the client's socket
      int bytes_sent = send(clientFd, read_buffer, bytes_received, 0);
      if (bytes_sent <= 0)
      {
        logError("Error sending data to client");
        break;
      }

      totalBytesSent += bytes_received;
    }
    else if (bytes_received < 0)
    {
      int ssl_error = SSL_get_error(ssl, bytes_received);
      if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
      {
        logError("Error reading data from server: " + std::to_string(ssl_error));
        break;
      }
    }
  } while (bytes_received > 0);
  

  std::cout << logFilePath << std::endl;
  std::cout << currentClientIP << std::endl;
  std::cout << currentRequestLine << std::endl;
  std::cout << totalBytesSent << std::endl;

  logAccess(logFilePath, currentClientIP, currentRequestLine, 200, totalBytesSent);



  // Clean up
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(clientFd);
}

bool parseHttpRequest(const std::string &request, std::string &method, std::string &uri, std::map<std::string, std::string> &headers)
{
  std::istringstream requestStream(request);
  std::string requestLine;

  // Get the request line
  if (!std::getline(requestStream, requestLine) || requestLine.empty())
  {
    return false; // Malformed request
  }

  std::istringstream requestLineStream(requestLine);
  requestLineStream >> method >> uri;
  if (method.empty() || uri.empty())
  {
    return false; // Missing method or URI
  }

  std::cout << "Parsed Request Line: " << method << " " << uri << std::endl;

  // Parse headers
  std::string headerLine;
  while (std::getline(requestStream, headerLine) && !headerLine.empty() && headerLine != "\r")
  {
    size_t colonPos = headerLine.find(':');
    if (colonPos == std::string::npos)
    {
      continue; // Invalid header line
    }

    std::string headerName = headerLine.substr(0, colonPos);
    std::string headerValue = headerLine.substr(colonPos + 1);
    headerValue.erase(0, headerValue.find_first_not_of(" \t\r\n")); // Trim leading whitespace
    headerValue.erase(headerValue.find_last_not_of(" \t\r\n") + 1); // Trim trailing whitespace

    headers[headerName] = headerValue;
    std::cout << "Parsed Header: " << headerName << ": " << headerValue << std::endl;
  }

  return true;
}

// Server and other necessary functions

int main(int argc, char **argv)
{
  if (argc != 4)
  {
    std::cerr << "Usage: ./myproxy [listen port] [forbidden sites file path] [access log file path]" << std::endl;
    return EXIT_FAILURE;
  }

  if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL))
  {
    std::cerr << "Failed to initialize OpenSSL" << std::endl;
    return EXIT_FAILURE;
  }
  std::string port = argv[1];
  std::string forbiddenSitesFilePath = argv[2];
  std::string accessLogFilePath = argv[3];

  std::cout << "Set accessLogFilePath in main: " << accessLogFilePath << std::endl;

  struct addrinfo hints
  {
  }, *res;

  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(nullptr, port.c_str(), &hints, &res) != 0)
  {
    std::cerr << "Unable to identify address" << std::endl;
    return EXIT_FAILURE;
  }

  std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> addrinfoPtr(res, freeaddrinfo);

  int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1)
  {
    std::cerr << "Socket build error" << std::endl;
    return EXIT_FAILURE;
  }

  int on = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&on), sizeof(on)) < 0)
  {
    std::cerr << "Unable to set SO_REUSEADDR option" << std::endl;
    return EXIT_FAILURE;
  }

  if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
  {
    std::cerr << "Socket bind error" << std::endl;
    return EXIT_FAILURE;
  }

  loadSiteFiles(forbiddenSitesFilePath);

  signal(SIGINT, signalHandler);

  while (true)
  {
    listen(sockfd, BACKLOG);
    struct sockaddr_storage theirAddr;
    socklen_t addrSize = sizeof(theirAddr);

    int newFd = accept(sockfd, reinterpret_cast<struct sockaddr *>(&theirAddr), &addrSize);
    if (newFd == -1)
    {
      std::cerr << "Unable to accept() a connection" << std::endl;
      continue;
    }

    std::cout << "accessLogFilePath before fork: " << accessLogFilePath << std::endl;
    int child = fork();
    if (child == 0)
    {
      std::cout << "accessLogFilePath in child: " << accessLogFilePath << std::endl;
      close(sockfd);

      char buffer[PIPE_MAX], writePipe[PIPE_MAX];
      std::memset(buffer, 0, PIPE_MAX);
      int dataSize = read(newFd, buffer, PIPE_MAX);
      if (dataSize <= 0)
      {
        close(newFd);
        exit(EXIT_FAILURE);
      }

      std::string request(buffer); // Convert to C++ string for easier handling
      std::string method, uri;
      std::map<std::string, std::string> headers;
      // Parse the request (This needs to be implemented properly)
      if (!parseHttpRequest(request, method, uri, headers))
      {
        std::string writeBuffer(writePipe);                                   // Convert char array to std::string
        sendError(newFd, writeBuffer, 400, "Bad Request", accessLogFilePath); // Send error if parsing failed
        close(newFd);
        exit(EXIT_FAILURE);
      }

      std::cout << "Method: " << method << ", URI: " << uri << std::endl;
      for (const auto &header : headers)
      {
        std::cout << "Header: " << header.first << " => " << header.second << std::endl;
      }

      // Right after accepting a connection:
      char clientIP[INET6_ADDRSTRLEN];
      getnameinfo((struct sockaddr *)&theirAddr, sizeof theirAddr, clientIP, sizeof clientIP, NULL, 0, NI_NUMERICHOST);
      currentClientIP = clientIP;

      // After parsing the request successfully:
      currentRequestLine = method + " " + uri + " HTTP/1.1";

      // Extract the hostname (and optionally the port) from the URI for the secureAndSend function
      std::string host;         // You'll need to extract the hostname from the URI
      std::string port = "443"; // Default HTTPS port, you may need to extract this from the URI if specified

  
      // Parse the URI to extract the hostname and port

      size_t hostStart = uri.find("://"); // Find the start of the hostname
      if (hostStart != std::string::npos)
      {
        hostStart += 3;                            // Move past "://"
        size_t hostEnd = uri.find("/", hostStart); // Find the end of the hostname
        if (hostEnd != std::string::npos)
        {
          std::string hostPort = uri.substr(hostStart, hostEnd - hostStart); // Extract the hostname and port
          size_t portStart = hostPort.find(":");                             // Check if a port is specified
          if (portStart != std::string::npos)
          {
            host = hostPort.substr(0, portStart);  // Extract the hostname
            port = hostPort.substr(portStart + 1); // Extract the port
          }
          else
          {
            host = hostPort; // No port specified, use default HTTPS port
          }
        }
        else
        {
          host = uri.substr(hostStart); // No path specified, use the entire string as hostname
        }
      }

      // Check if the request method is supported (GET and HEAD)
      if (method != "GET" && method != "HEAD")
      {
        std::string writeBuffer;                                                  // Use std::string for the write buffer
        sendError(newFd, writeBuffer, 501, "Not Implemented", accessLogFilePath); // Send an HTTP 501 error for unsupported methods
        close(newFd);
        exit(EXIT_FAILURE);
      }

      // Check if the host is forbidden
      for (const auto &forbiddenHost : forbiddenSites)
      {
        if (host.find(forbiddenHost) != std::string::npos)
        {
          std::string writeBuffer;                                            // Use std::string for the write buffer
          sendError(newFd, writeBuffer, 403, "Forbidden", accessLogFilePath); // Send an HTTP 403 error if the host is forbidden
          close(newFd);
          exit(EXIT_FAILURE);
        }
      }

      // Forward the request over HTTPS to the destination server and send the response back to the client
      try
      {
        secureAndSend(newFd, request, host, port, accessLogFilePath); // Call the secureAndSend function
      }
      catch (const std::exception &e)
      {
        std::cerr << "Error during secure send: " << e.what() << std::endl;
        // Optionally send an error response to the client before closing
      }

      close(newFd);       // Close the connection to the client
      exit(EXIT_SUCCESS); // Exit the child process

      // close(newFd);
      // return EXIT_SUCCESS;
    }
    close(newFd);
  }

  return EXIT_SUCCESS;
}
