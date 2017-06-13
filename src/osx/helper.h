#pragma once

#include "../stdafx.h"
#include <CoreFoundation/CoreFoundation.h>


namespace osx {
    
    template<typename T>
    class CFRef {
    public:
        CFRef() : value(NULL), free(CFRelease) {
//            fprintf(stdout, "%s\n", __FUNCTION__, typeid(value).name());
        }
        
        CFRef(T value) : value(value), free(CFRelease) {
//            fprintf(stdout, "%s:%s %p\n", __FUNCTION__, typeid(value).name(), value);
        }
        
        CFRef(T value, void (*free)(const void* ref)) : value(value), free(free) {
//            fprintf(stdout, "%s:$s %p %p\n", __FUNCTION__, value, typeid(value).name(), free);
        }
        
        ~CFRef(){
            if (value && free) {
//                fprintf(stdout, "%s:%s\n", __FUNCTION__, typeid(value).name());
                free(value);
                value = NULL;
            }
        }
        
        T Get() {
            return value;
        }
        
        CFRef<T>& operator=(const T data) {
            value = data;
            return *this;
        }
        
        T operator&() {
            return value;
        }
        
        bool IsEmpty() {
            return value == NULL;
        }
        
    protected:
        T value;
        void (*free)(const void* ref);
    };

}
