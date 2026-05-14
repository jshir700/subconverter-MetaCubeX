#include <string>
#include <vector>
#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "server/socket.h"
#include "string.h"
#include "regexp.h"

std::string hostnameToIPAddr(const std::string &host)
{
    int retVal;
    std::string retAddr;
    char cAddr[128] = {};
    struct sockaddr_in *target;
    struct sockaddr_in6 *target6;
    struct addrinfo hint = {}, *retAddrInfo, *cur;
    retVal = getaddrinfo(host.data(), NULL, &hint, &retAddrInfo);
    if(retVal != 0)
    {
        freeaddrinfo(retAddrInfo);
        return "";
    }

    for(cur = retAddrInfo; cur != NULL; cur = cur->ai_next)
    {
        if(cur->ai_family == AF_INET)
        {
            target = reinterpret_cast<struct sockaddr_in *>(cur->ai_addr);
            inet_ntop(AF_INET, &target->sin_addr, cAddr, sizeof(cAddr));
            break;
        }
        else if(cur->ai_family == AF_INET6)
        {
            target6 = reinterpret_cast<struct sockaddr_in6 *>(cur->ai_addr);
            inet_ntop(AF_INET6, &target6->sin6_addr, cAddr, sizeof(cAddr));
            break;
        }
    }
    retAddr.assign(cAddr);
    freeaddrinfo(retAddrInfo);
    return retAddr;
}

bool isIPv4(const std::string &address)
{
    return regMatch(address, "^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");
}

bool isIPv6(const std::string &address)
{
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, address.c_str(), &(sa.sin6_addr)) == 1;
}

void urlParse(std::string &url, std::string &host, std::string &path, int &port, bool &isTLS)
{
    std::vector<std::string> args;
    string_size pos;

    if(startsWith(url, "https://"))
        isTLS = true;
    if(startsWith(url, "http://"))
        url.erase(0, 7);
    else if(startsWith(url, "https://"))
        url.erase(0, 8);
    pos = url.find("/");
    if(pos == url.npos)
    {
        host = url;
        path = "/";
    }
    else
    {
        host = url.substr(0, pos);
        path = url.substr(pos);
    }
    pos = host.rfind(":");
    if(regFind(host, "\\[(.*)\\]")) //IPv6
    {
        args = split(regReplace(host, "\\[(.*)\\](.*)", "$1,$2"), ",");
        if(args.size() == 2) //with port
            port = to_int(args[1].substr(1));
        host = args[0];
    }
    else if(pos != host.npos)
    {
        port = to_int(host.substr(pos + 1));
        host = host.substr(0, pos);
    }
    if(port == 0)
    {
        if(isTLS)
            port = 443;
        else
            port = 80;
    }
}

std::string getFormData(const std::string &raw_data)
{
    std::stringstream strstrm(raw_data);
    std::string line, boundary;

    std::getline(strstrm, line);
    if(line.size() > 1)
        boundary = line.substr(0, line.size() - 1); // Get boundary (remove trailing \r)

    // Skip headers until blank line, then extract file content up to boundary
    std::string::size_type body_start = raw_data.find("\r\n\r\n");
    if(body_start == std::string::npos)
        return "";
    body_start += 4;

    std::string::size_type body_end = raw_data.find(boundary, body_start);
    if(body_end == std::string::npos)
        return "";

    // Trim trailing \r\n before boundary
    std::string::size_type end = body_end;
    while(end > body_start && (raw_data[end - 1] == '\r' || raw_data[end - 1] == '\n'))
        end--;

    return raw_data.substr(body_start, end - body_start);
}
