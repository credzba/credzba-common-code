#ifndef IPADDRESS_H
#define IPADDRESS_H

// for STL_HASH_FUNC
#include <cpp_compat.h>

#include <string>
#include <boost/asio.hpp>
typedef boost::asio::ip::address_v4 IPv4Address;
typedef boost::asio::ip::address_v6 IPv6Address;
typedef boost::asio::ip::address IPAddress;

#include <boost/strong_typedef.hpp>

namespace common {

BOOST_STRONG_TYPEDEF(uint8_t, Prefix);

class IpConversionException : std::exception {
public:
    IpConversionException(const std::string& reason) 
        : _reason(reason)
    {}        
    virtual ~IpConversionException() throw() {} 
    
    virtual const char* what() const throw() {return _reason.c_str();} 
private:
    std::string _reason; 
};

    class hashIpAddress 
    {
    public:
         size_t operator()(const std::string& str) const
        {   
            return STL_HASH_FUNC<const char *>()(str.c_str());
        }
         size_t operator()(const IPAddress& ip) const
        {   
            std::string str = ip.to_string();
            return STL_HASH_FUNC<const char *>()(str.c_str());
        }
         size_t operator()(const IPv4Address& ip) const
        {   
            std::string str = ip.to_string();
            return STL_HASH_FUNC<const char *>()(str.c_str());
        }
         size_t operator()(const IPv6Address& ip) const
        {   
            std::string str = ip.to_string();
            return STL_HASH_FUNC<const char *>()(str.c_str());
        }
    };


 IPAddress   hostToIp(const std::string &  hostname, int family=AF_UNSPEC);
 IPv4Address calcNetworkId(const IPv4Address& originalIp, common::Prefix prefix); 
 IPv6Address calcNetworkId(const IPv6Address& originalIp, common::Prefix prefix); 
 IPAddress   calcNetworkId(const IPAddress& originalIp, common::Prefix prefix); 
 common::Prefix calculateNetmaskSize( const IPv4Address& netmask );
 IPv4Address generateNetmask( common::Prefix prefix ); 
 in_addr_t   to_in_addr_t(const IPv4Address& ipAddress); 
 std::string IP2ParamStr(const IPAddress& ip);
 IPAddress   ParamStr2IP(std::string ipStr);

}

#include "IPAddress.hpp"

#endif //IPADDRESS_H
