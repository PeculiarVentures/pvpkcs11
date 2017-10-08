#pragma once

#define LOGGER_FILE "PVPKCS11.log"

#define LOGGER_LEVEL_INFO       0x0001
#define LOGGER_LEVEL_WARN       0x0002
#define LOGGER_LEVEL_ERROR      0x0004
#define LOGGER_LEVEL_DEBUG      0x0008
#define LOGGER_LEVEL_TRACE      0x0010

#define LOGGER_LEVEL_ALL LOGGER_LEVEL_INFO | LOGGER_LEVEL_WARN | LOGGER_LEVEL_ERROR | LOGGER_LEVEL_DEBUG | LOGGER_LEVEL_TRACE
#define LOGGER_LEVEL_MIN LOGGER_LEVEL_INFO | LOGGER_LEVEL_WARN | LOGGER_LEVEL_ERROR
#define LOGGER_LEVEL_DEVELOP LOGGER_LEVEL_INFO | LOGGER_LEVEL_WARN | LOGGER_LEVEL_ERROR | LOGGER_LEVEL_DEBUG

class Logger {
public:
    Logger();
    ~Logger();
    void print
    (
     int level,
     const char* file,
     int line,
     const char* function,
     const char* message,
     ...
     );
protected:
    int     level;
    FILE*   file;
    
    void init();
};

