#ifndef MACADDR_H
#define MACADDR_H

#include <net/ethernet.h>
#include <string>
#include <boost/array.hpp>
#include "commonExceptions.h"
#include "memory.h"
#include <cstdio>

class MacAddr : public boost::array<unsigned char, ETH_ALEN> {
 public:
    MacAddr(const u_int8_t source[ETH_ALEN]) {
        memcpy(this->c_array(), &(source[0]), this->size()); 
    }
    
    MacAddr() {}
    
    MacAddr(const MacAddr& other) 
        : boost::array<unsigned char, ETH_ALEN>(other)
    {}
    
    std::string to_string() const {
        std::stringstream stream;
        
        char prev;
        for (size_t i=0; i < size();i++)
        {
            prev = stream.fill('0');
            stream.width(2);stream << std::nouppercase <<std::hex << (unsigned short)(*this)[i];
            stream.fill(prev);
            if (i != 5) stream << ":";
        }
        
        return stream.str();
    }
    
    static const MacAddr& broadcast_arp() 
    {
        static const MacAddr broadcast = MacAddr::from_string("ff:ff:ff:ff:ff:ff");
        return broadcast;       
    }
  
    static const MacAddr& empty_addr() {
        static const MacAddr empty = MacAddr::from_string("00:00:00:00:00:00");
        return empty;
    }
    
    // just a dummy mac - one used in the lab.
    static const MacAddr& bad_addr() {
        static const MacAddr bad = MacAddr::from_string("00:30:48:28:E3:10");
        return bad;
    }

    static MacAddr from_string(const std::string macStr) {
        MacAddr dest;
        const char* begin = macStr.c_str();
        unsigned char* pdest = dest.data();        
        unsigned short       tmp;
        
        for (size_t i=0; i < dest.size(); i++)
        {
            if ( sscanf(begin, "%hx", &tmp) != 1)
            throw common::InvalidArg();// invalid hex octet 
            
            *pdest++ = tmp;
            if (i != 5)
            {
                begin += 2;
                if (*begin != ':')
                throw common::InvalidArg();// delimiter missing 
                begin++;                  // Get past delimiter 
            }
        }
        
        // check that the last octet is totaly hex
        if (!(isxdigit(begin[0]) && isxdigit(begin[1]))) {
            throw common::InvalidArg();
        }
        
        return dest;
    }
    
};


#endif
