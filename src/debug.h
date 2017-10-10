#pragma once

#include "stdafx.h"


/**
 Returns list of CKA_ATTRIBUTE in text format [<name>, ...]

 @param pTmpl       Pointer to array of CKA_ATTRIBUTE
 @param ulTmplLen   Number of CKA_ATTRIBUTE in array
 @return text
 */
std::string printTemplate
(
 CK_ATTRIBUTE_PTR       pTmpl,
 CK_ULONG               ulTmplLen
 );


/**
 Returns address of value in text format 0x00000000 | NULL

 @param pValue Pointer to the value
 @return text
 */
std::string printAddress
(
 CK_VOID_PTR            pValue
 );


/**
 Returns handle in text format 0x00000000

 @param ulHandle <#ulHandle description#>
 @return <#return value description#>
 */
std::string printHandle
(
 CK_ULONG               ulHandle
 );
