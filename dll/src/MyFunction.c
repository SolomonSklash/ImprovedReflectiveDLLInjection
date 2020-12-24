#include "ReflectiveLoader.h"
#include <stdio.h>

DLLEXPORT BOOL
MyFunction( LPVOID lpUserdata, DWORD nUserdataLen )
{
	LPSTR str = malloc( 32 + ( size_t )nUserdataLen );
	sprintf_s( str, 32 + ( size_t )nUserdataLen, "Hello from MyFunction: %s!", ( PCHAR )lpUserdata );
	MessageBoxA( NULL, str, ( LPCSTR )lpUserdata, MB_OK );
	free( str );
	return TRUE;
}
