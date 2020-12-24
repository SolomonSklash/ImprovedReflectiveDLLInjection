#include "ReflectiveLoader.h"
#include <stdio.h>

/* This function is exported and will be called by the reflective loader.
 * It is identified via the hash of its name. A parameter can be passed
 * to it, for doing .NET execution. */
DLLEXPORT BOOL
MyFunction( LPVOID lpUserdata, DWORD nUserdataLen )
{
	LPSTR str = malloc( 32 + ( size_t )nUserdataLen );
	sprintf_s( str, 32 + ( size_t )nUserdataLen, "MyFunction param: %s!", ( PCHAR )lpUserdata );
	MessageBoxA( NULL, str, ( LPCSTR )lpUserdata, MB_OK );
	free( str );
	return TRUE;
}
