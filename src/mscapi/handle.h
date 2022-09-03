#pragma once

#include "../stdafx.h"
#include "../core/excep.h"

namespace mscapi
{

    template <typename T>
    class Handle
    {
    public:
        Handle() : handle(NULL)
        {
        }

        Handle(T handle) : handle(handle)
        {
        }

        ~Handle()
        {
            if (!IsEmpty())
            {
                Dispose();
                handle = NULL;
            }
        }

        T Get()
        {
            if (IsEmpty())
            {
                THROW_EXCEPTION("handle is empty");
            }
            return handle;
        }

        void Set(T handle)
        {
            LOGGER_FUNCTION_BEGIN;

            Dispose();
            this->handle = handle;
        }

        T *Ref()
        {
            return &handle;
        }

        BOOL IsEmpty()
        {
            return !handle;
        }

        virtual void Dispose()
        {
            handle = NULL;
        }

    private:
        T handle;
    };

}