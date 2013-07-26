#ifndef COMMONEXCEPTIONS_H
#define COMMONEXCEPTIONS_H

#include "Exception.h"
#include <sstream>

namespace common
{

    class InvalidArg: public Exception
    {
    public:
        InvalidArg():Exception("Invalid argument"){}
    };

}

#endif // COMMONEXCEPTIONS_H
