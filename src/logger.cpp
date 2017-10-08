#include <stdio.h>
#include <stdlib.h>
#include <cstdarg>
#include <ctime>
#include <string>

#include "logger.h"

Logger::Logger()
{
    init();
}

Logger::~Logger()
{
    if (file) {
        fclose(file);
    }
}

void Logger::print
(
 int level,
 const char* file,
 int line,
 const char* function,
 const char* message,
 ...
 )
{
    va_list args;
    va_start(args, message);
    
    if (this->file && (this->level & level)) {
        
        // Time
        time_t curTime = time(NULL);
        struct tm aTm;
#ifdef _WIN32
        localtime_s(&aTm, &curTime);
#else
        localtime_r(&curTime, &aTm);
#endif
        char time[30];
        strftime(time, 30, "%Y-%m-%d %H:%M:%S", &aTm);
        
        // Level name
        const char* levelName;
        switch (level) {
            case LOGGER_LEVEL_INFO:
                levelName = "INFO  ";
                break;
            case LOGGER_LEVEL_WARN:
                levelName = "WARN  ";
                break;
            case LOGGER_LEVEL_ERROR:
                levelName = "ERROR ";
                break;
            case LOGGER_LEVEL_DEBUG:
                levelName = "DEBUG ";
                break;
            case LOGGER_LEVEL_TRACE:
                levelName = "TRACE ";
                break;
            default:
                levelName = "UKNOWN";
        }
        
        // message
        char buffer[2048];
        vsprintf(buffer, message, args);
        
        // skip '../../src/'
        const char* slicedFile = (const char*)(file + 10);
        
        fprintf(this->file, "%s %s %s %s:%ul %s\n", time, function, levelName, slicedFile, line, buffer);
        fflush(this->file);
        
        va_end(args);
    }
}

void Logger::init()
{
    // default values
    file = NULL;
    level = LOGGER_LEVEL_MIN;
    
    // get full path for log file
    std::string path("");
#ifdef _WIN32
    path += std::getenv("TMP");
    path += "\\";
#else
    path += "/tmp/";
#endif // _WIN32
    path += LOGGER_FILE;
    
    // get env variables
    const char* ENV_ERROR = NULL;
    const char* ENV_ERROR_LEVEL = NULL;
#ifdef _WIN32
#define __std std::
#else
#define __std
#endif
    ENV_ERROR = __std getenv("PV_PKCS11_ERROR");
    ENV_ERROR_LEVEL = __std getenv("PV_PKCS11_ERROR_LEVEL");
#undef __std
 
    if (ENV_ERROR) {
        file = fopen(path.c_str(), "w+");
        if (ENV_ERROR_LEVEL) {
            int errorLevel = strtol(ENV_ERROR_LEVEL, NULL, 10);
            if (errorLevel > 0) {
                level = errorLevel;
            }
        }
    }
    
}
