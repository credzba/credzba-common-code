#ifndef IPADDRESS_H
#define IPADDRESS_H

#include <string>
#include <boost/asio.hpp>
#include <boost/strong_typedef.hpp>

typedef boost::asio::ip::address_v4 IPv4Address;
typedef boost::asio::ip::address_v6 IPv6Address;
typedef boost::asio::ip::address IPAddress;

namespace common
{
BOOST_STRONG_TYPEDEF(int, Prefix);

inline IPv4Address generateNetmask( common::Prefix prefix ) {
    
    if(prefix == 0) {
        return IPv4Address();    
    }   

    const unsigned int max_ipv4_bitsize = 32; // ipv4 address are always based on 32 bits
    if(prefix > max_ipv4_bitsize ) {
        std::ostringstream str;
        str << "Invalid netmask size (" << prefix << ") - may not exceed " << max_ipv4_bitsize << ".";
        throw std::out_of_range(str.str().c_str());
    }

    unsigned int calcAddr = (int32_t(-1) << (max_ipv4_bitsize - prefix));

    return IPv4Address(calcAddr);
}

    /** 
     * Computes the subnet portion of an address based on the prefix
     * 
     * @param originalIp - an ip from within the subnet
     * @param prefix  - the number of relevent bits to define the subnet
     * 
     * @return IPAddress containing just the subnet portion of the address
     */
    IPAddress calcNetworkId(const IPAddress& originalIp, int prefix) {
        if (originalIp.is_v4()) {
            return calcNetworkId(originalIp.to_v4(), prefix);
        } 
        
        return calcNetworkId(originalIp.to_v6(), prefix);
    }

    /** 
     * Computes the subnet portion of an address based on the prefix
     * 
     * @param originalIp - an ip from within the subnet
     * @param prefix  - the number of relevent bits to define the subnet
     * 
     * @return IPv4Address containing just the subnet portion of the address
     */
    IPv4Address calcNetworkId(const IPv4Address& originalIp, int prefix) {
        ulong ip = originalIp.to_ulong();
        if (prefix < 32) {
            int shift = 32 - prefix;
            ip = (ip >> shift) << shift;
        }
        const IPv4Address networkId(ip);
        return networkId;
    }


    /** 
     * Computes the subnet portion of an address based on the prefix
     * 
     * @param originalIp - an ip from within the subnet
     * @param prefix  - the number of relevent bits to define the subnet
     * 
     * @return IPv6Address containing just the subnet portion of the address
     */
    IPv6Address calcNetworkId(const IPv6Address& originalIp, int prefix) {
        boost::asio::ip::address_v6::bytes_type addrBytes = originalIp.to_bytes();
        if (prefix < 128) {
            unsigned int index=prefix/8; // index to first partial byte 
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
            addrBytes[index] &= maskList[prefix%8];
            for (index++; index<addrBytes.size(); index++ ) {
                addrBytes.at( index ) = 0;
            }
        }

        const IPv6Address networkId(addrBytes);
        return networkId;
    }


    unsigned int calculateNetmaskSize( const IPv4Address& netmask ) {
        ulong countBits = netmask.to_ulong();        
        unsigned int maskSize = 0;
        while(countBits)
        {
            countBits <<= 1;
            ++maskSize;
        }
        return maskSize;
    }


    static const int ROUNDROBIN_ALG = 1;
    static const int NIC_LOADS_ALG  = 2;
    static const int NFS_CPU_ALG    = 3;               


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
