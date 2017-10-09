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
    
    static Logger* getInstance();
    
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

#define LOGGER_PRINT(level, message, ...) Logger::getInstance()->print(level, __FILE__, __LINE__, __FUNCTION__, message, ## __VA_ARGS__)
#define LOGGER_INFO(message, ...) LOGGER_PRINT(LOGGER_LEVEL_INFO, message, ## __VA_ARGS__)
#define LOGGER_WARN(message, ...) LOGGER_PRINT(LOGGER_LEVEL_WARN, message, ## __VA_ARGS__)
#define LOGGER_ERROR(message, ...) LOGGER_PRINT(LOGGER_LEVEL_ERROR, message, ## __VA_ARGS__)
#define LOGGER_DEBUG(message, ...) LOGGER_PRINT(LOGGER_LEVEL_DEBUG, message, ## __VA_ARGS__)
#define LOGGER_TRACE(message, ...) LOGGER_PRINT(LOGGER_LEVEL_TRACE, message, ## __VA_ARGS__)

#define LOGGER_FUNCTION_BEGIN LOGGER_TRACE("BEGIN:%s", __FUNCTION__)

