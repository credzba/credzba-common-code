#ifndef IPADDRESS_HPP
#define IPADDRESS_HPP

namespace {
inline void verify32bitPrefix(const common::Prefix& prefix) {
    const uint8_t maxIpv4Bitsize = 32; // ipv4 address are always based on 32 bits
    if(prefix > maxIpv4Bitsize) {
        std::ostringstream str;
        str << "Invalid netmask size (" << prefix << ") - may not exceed " << maxIpv4Bitsize << ".";
        throw std::out_of_range(str.str().c_str());
    }
}

inline void verify128bitPrefix(const common::Prefix& prefix) {
    const uint8_t maxIpv6Bitsize = 128; // ipv6 address are always based on 128 bits
    if(prefix > maxIpv6Bitsize) {
        std::ostringstream str;
        str << "Invalid netmask size (" << prefix << ") - may not exceed " << maxIpv6Bitsize << ".";
        throw std::out_of_range(str.str().c_str());
    }
}

const int ROUNDROBIN_ALG = 1;
const int NIC_LOADS_ALG  = 2;
const int NFS_CPU_ALG    = 3;               
}

namespace common {
    /** 
     * hostToIp converts a hostname (or ip address) to an IPAddress
     * 
     * @param hostname - hostname of string representation of an ip address
     * @param family defaults to AF_UNSPEC, can be specified as AF_INET or AF_INET6
     * 
     * @return IpConversionException if any error occurs. 
     *         IPAddress containing the appropriate ip address if successful
     */

    inline IPAddress hostToIp(const std::string &  hostname, int family) {
        char ipstr[INET6_ADDRSTRLEN+1];

        addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family   = family;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo *servinfo=0; 
        int status = getaddrinfo(hostname.c_str(), NULL, &hints, &servinfo);
        if (status < 0) {
            std::string buffer("getaddrinfo error: ");
            buffer.append(gai_strerror(status));
            throw IpConversionException(buffer);
        }

        for (addrinfo *addrInfo=servinfo; addrInfo!=NULL; addrInfo=addrInfo->ai_next) {
            in_addr  *addr;
            if (addrInfo->ai_family == AF_INET) {
                struct sockaddr_in *ipv = (struct sockaddr_in *)addrInfo->ai_addr;
                addr = &(ipv->sin_addr);
            } else {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addrInfo->ai_addr;
                addr = (struct in_addr *) &(ipv6->sin6_addr);
            }
            const char * temp = inet_ntop(addrInfo->ai_family, addr, ipstr, sizeof ipstr);
            if (NULL == temp) {
                std::string buffer("inet_ntop error: ");
                buffer.append(strerror(errno));
                freeaddrinfo(servinfo); 
                throw IpConversionException(buffer);
            }
        }
        IPAddress retIp = IPAddress::from_string(ipstr);
        freeaddrinfo(servinfo); 
        return retIp;
    }


/**
 * Computes the subnet portion of an address based on the prefix
 * 
 * @param originalIp - an ip from within the subnet
 * @param prefix  - the number of relevent bits to define the subnet
 * 
 * @return IPv4Address containing just the subnet portion of the address
 */
inline IPv4Address calcNetworkId(const IPv4Address& originalIp, common::Prefix prefix) {
        ulong ip = originalIp.to_ulong(); 
        verify32bitPrefix(prefix);

        int shift = 32 - prefix;
        ip = (ip >> shift) << shift;

        return IPv4Address(ip);
    }


/** 
 * Computes the subnet portion of an address based on the prefix
 * 
 * @param originalIp - an ip from within the subnet
 * @param prefix  - the number of relevent bits to define the subnet
 * 
 * @return IPv6Address containing just the subnet portion of the address
 */
inline IPv6Address calcNetworkId(const IPv6Address& originalIp, common::Prefix prefix) {
    if (prefix == 128) return originalIp;
    if (prefix == 0) return IPv6Address();


    boost::asio::ip::address_v6::bytes_type addrBytes = originalIp.to_bytes();
    verify128bitPrefix(prefix);
    
    // index to first partial byte 
    unsigned int index=prefix/8; 
    static const unsigned char maskList[]={
        0x0,   // 0
        0x80,  // 1
        0xc0,  // 2
        0xe0,  // 3
        0xf0,  // 4
        0xf8,  // 5
        0xfc,  // 6
        0xfe   // 7
    };
    // The last byte may be a partial set of bits, so we use the masked bits to determine the final byte of the network address
    addrBytes[index] &= maskList[prefix%8]; 
    
    // zero all the rest of the bytes
    for (index++; index<addrBytes.size(); index++ ) {
        addrBytes.at( index ) =0;
    }
    
    return IPv6Address(addrBytes);
}

    /** 
     * Computes the subnet portion of an address based on the prefix
     * 
     * @param originalIp - an ip from within the subnet
     * @param prefix  - the number of relevent bits to define the subnet
     * 
     * @return IPAddress containing just the subnet portion of the address
     */
inline IPAddress calcNetworkId(const IPAddress& originalIp, common::Prefix prefix) {
    if (originalIp.is_v4()) {
        return calcNetworkId(originalIp.to_v4(), prefix);
    }     

    return calcNetworkId(originalIp.to_v6(), prefix);
}


inline common::Prefix calculateNetmaskSize( const IPv4Address& netmask ) {
        ulong countBits = netmask.to_ulong();        
        return common::Prefix(__builtin_popcount(countBits));
    }

inline IPv4Address generateNetmask( common::Prefix prefix ) {
    if(prefix == 0) {
        return IPv4Address();
    }
    verify32bitPrefix(prefix);

    const unsigned int maxIpv4Bitsize = 32;
    unsigned int calcAddr = (int32_t(-1) << (maxIpv4Bitsize - prefix));
    return IPv4Address(calcAddr);    
}

inline 
in_addr_t to_in_addr_t(const IPv4Address& ipAddress) {
    return boost::asio::detail::socket_ops::host_to_network_long(ipAddress.to_ulong());
}

inline
IPv4Address from_in_addr_t(const in_addr_t& nativeIpv4Address) {
    IPv4Address::bytes_type bytes;
    memcpy(&bytes, &nativeIpv4Address, 4);
    return IPv4Address(bytes);
}

/** 
 * Format an ip address replacing the . with _
 * so that it can be used as a param text
 * 
 * @param ip IPv4 or IPv6 Address 
 * 
 * @return string containing the address in 255_255_255_255 or 4096:4096::4096 format
 */
inline std::string IP2ParamStr(const IPAddress& ip)
{
    std::string ip_str(ip.to_string());
    std::replace( ip_str.begin(), ip_str.end(), '.', '_');  // fix up ipv4 delimiters
    // no need to change ipv6 : delimiter
    return ip_str;
}


/** 
 * Formats an ipv4 or ipv6 address from param into IPAddress
 * 
 * @param ipStr ip in param string format (255_255_255_255 or 4096:4096::4096)
 * 
 * @return the ip address 
 */
inline IPAddress ParamStr2IP(std::string ipStr)
{
    std::replace( ipStr.begin(), ipStr.end(), '_', '.');  // fix up ipv4 delimiters
    return IPAddress::from_string(ipStr);
}
    
}
#endif //IPADDRESS_H
