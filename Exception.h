#ifndef EXCEPTION_HPP
#define EXCEPTION_HPP

#include <exception>
#include <string>

class Exception : public std::exception {
public:
    Exception () throw() {}
    Exception (const std::string& reason) throw() 
        : _reason(reason)
    {}
    virtual ~Exception() throw() {}
    virtual const char* what() const throw()
    { return _reason.c_str(); }
private:
    std::string _reason;
};
    
#endif
