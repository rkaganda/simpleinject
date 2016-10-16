#ifndef UTIL_HPP_INCLUDED
#define UTIL_HPP_INCLUDED

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13


void DisplayError(
    char const* szAPI    // pointer to failed API name
    );

#endif // UTIL_HPP_INCLUDED
