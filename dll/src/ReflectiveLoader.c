//===============================================================================================//
#include "ReflectiveLoader.h"
//===============================================================================================//

typedef BOOL ( *EXPORTFUNC )( LPVOID, DWORD );

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;

/* This is the position independent reflective DLL loader. It parses the DLL image, 
 * loads it, and calls the exported function identified by the hashed function name
 * dwFunctionHash. */
   
DLLEXPORT VOID WINAPI ReflectiveLoader( LPVOID lpParameter, LPVOID lpLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen )
{
	// The functions needed, defined in ReflectiveLoader.h
	LOADLIBRARYA   pLoadLibraryA	   = NULL;
	GETPROCADDRESS pGetProcAddress	   = NULL;
	VIRTUALALLOC   pVirtualAlloc       = NULL;
	EXITTHREAD     pExitThread		   = NULL;
	EXITTHREAD	   pRtlExitUserThread  = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT usCounter;

	// The initial location of this image in memory
	ULONG_PTR uiLibraryAddress = ( ULONG_PTR )NULL;
	// The kernels base address and later this image's newly loaded base address
	ULONG_PTR uiBaseAddress    = (ULONG_PTR)NULL;

	// Variables for processing the kernel's export table
	ULONG_PTR uiAddressArray = ( ULONG_PTR )NULL;
	ULONG_PTR uiNameArray    = ( ULONG_PTR )NULL;
	ULONG_PTR uiExportDir    = ( ULONG_PTR )NULL;
	ULONG_PTR uiNameOrdinals = ( ULONG_PTR )NULL;
	DWORD dwHashValue		 = 0;
	DWORD dwNumberOfNames	 = 0;

	// Variables for loading this image
	ULONG_PTR uiHeaderValue = ( ULONG_PTR )NULL;
	ULONG_PTR uiValueA		= ( ULONG_PTR )NULL;
	ULONG_PTR uiValueB		= ( ULONG_PTR )NULL;
	ULONG_PTR uiValueC		= ( ULONG_PTR )NULL;
	ULONG_PTR uiValueD		= ( ULONG_PTR )NULL;
	ULONG_PTR uiValueE		= ( ULONG_PTR )NULL;

	// Exit code for current thread
	DWORD dwExitCode = 1;

	uiLibraryAddress = ( ULONG_PTR )lpLibraryAddress;

	// STEP 1: process the kernel's exports for the functions the loader needs

	// Get the PEB
	// TODO: Use kernel structure method instead of this way
#ifdef WIN_X64
	uiBaseAddress = __readgsqword( 0x60 );
#else
	uiBaseAddress = __readfsdword( 0x30 );
#endif

	// Get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708( VS.85 ).aspx
	uiBaseAddress = ( ULONG_PTR )(( _PPEB )uiBaseAddress )->pLdr;

	// Get the first entry of the InMemoryOrder module list
	uiValueA = ( ULONG_PTR )(( PPEB_LDR_DATA )uiBaseAddress )->InMemoryOrderModuleList.Flink;
	while ( uiValueA )
	{
		// Get pointer to current modules name ( unicode string )
		uiValueB = ( ULONG_PTR )(( PLDR_DATA_TABLE_ENTRY )uiValueA )->BaseDllName.pBuffer;
		// Set bCounter to the length for the Loop
		usCounter = (( PLDR_DATA_TABLE_ENTRY )uiValueA )->BaseDllName.Length;
		// Clear uiValueC which will store the hash of the module name
		uiValueC = 0;

		// Compute the hash of the module name...
		do
		{
			// TODO: Change hash function to FNV-1a
			uiValueC = ror(( DWORD )uiValueC );
			// Normalize to uppercase if the module name is in lowercase
			if ( *(( PBYTE )uiValueB ) >= 'a' )
				uiValueC += *(( PBYTE )uiValueB ) - 0x20;
			else
				uiValueC += *(( PBYTE )uiValueB );
			uiValueB++;
		} while ( --usCounter );

		// Compare the hash with that of kernel32.dll
		if (( DWORD )uiValueC == KERNEL32DLL_HASH )
		{
			// Get this modules base address
			uiBaseAddress = ( ULONG_PTR )(( PLDR_DATA_TABLE_ENTRY )uiValueA )->DllBase;

			// Get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + (( PIMAGE_DOS_HEADER )uiBaseAddress )->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = ( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiExportDir )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// Get the VA of the export directory
			uiExportDir = ( uiBaseAddress + (( PIMAGE_DATA_DIRECTORY )uiNameArray )->VirtualAddress );

			// Get the VA for the array of name pointers
			uiNameArray = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfNames );
			
			// Get the VA for the array of name ordinals
			uiNameOrdinals = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfNameOrdinals );

			usCounter = 4;

			// Loop while we still have imports to find
			while ( usCounter > 0 )
			{
				// compute the hash values for this function name
				dwHashValue = hash(( PCHAR )( uiBaseAddress + DEREF_32( uiNameArray )) );
				
				// If we have found a function we want we Get its virtual address
				if ( dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH || dwHashValue == EXITTHREAD_HASH )
				{
					// Get the VA for the array of addresses
					uiAddressArray = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfFunctions );

					// Use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof( DWORD ));

					// Store this functions VA
					if ( dwHashValue == LOADLIBRARYA_HASH )
						pLoadLibraryA = ( LOADLIBRARYA )( uiBaseAddress + DEREF_32( uiAddressArray ));
					else if ( dwHashValue == GETPROCADDRESS_HASH )
						pGetProcAddress = ( GETPROCADDRESS )( uiBaseAddress + DEREF_32( uiAddressArray ));
					else if ( dwHashValue == VIRTUALALLOC_HASH )
						pVirtualAlloc = ( VIRTUALALLOC )( uiBaseAddress + DEREF_32( uiAddressArray ));
					else if ( dwHashValue == EXITTHREAD_HASH )
						pExitThread = ( EXITTHREAD )( uiBaseAddress + DEREF_32( uiAddressArray ));
			
					// Decrement our counter
					usCounter--;
				}

				// Get the next exported function name
				uiNameArray += sizeof( DWORD );

				// Get the next exported function name ordinal
				uiNameOrdinals += sizeof( WORD );
			}
		}
		else if (( DWORD )uiValueC == NTDLLDLL_HASH )
		{
			// Get this modules base address
			uiBaseAddress = ( ULONG_PTR )(( PLDR_DATA_TABLE_ENTRY )uiValueA )->DllBase;

			// Get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + (( PIMAGE_DOS_HEADER )uiBaseAddress )->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = ( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiExportDir )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// Get the VA of the export directory
			uiExportDir = ( uiBaseAddress + (( PIMAGE_DATA_DIRECTORY )uiNameArray )->VirtualAddress );

			// Get the VA for the array of name pointers
			uiNameArray = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfNames );
			
			// Get the VA for the array of name ordinals
			uiNameOrdinals = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfNameOrdinals );

			// Get total number of named exports
			dwNumberOfNames = (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->NumberOfNames;

			usCounter = 2;

			// Loop while we still have imports to find
			while ( usCounter > 0 && dwNumberOfNames > 0 )
			{
				// Compute the hash values for this function name
				dwHashValue = hash(( PCHAR )( uiBaseAddress + DEREF_32( uiNameArray )) );
				
				// If we have found a function we want we get its virtual address
				if ( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH || dwHashValue == RTLEXITUSERTHREAD_HASH )
				{
					// Get the VA for the array of addresses
					uiAddressArray = ( uiBaseAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfFunctions );

					// Use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof( DWORD ));

					// Store this functions VA
					if ( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
						pNtFlushInstructionCache = ( NTFLUSHINSTRUCTIONCACHE )( uiBaseAddress + DEREF_32( uiAddressArray ));
					else if ( dwHashValue == RTLEXITUSERTHREAD_HASH )
						pRtlExitUserThread = ( EXITTHREAD )( uiBaseAddress + DEREF_32( uiAddressArray ));

					// Decrement our counter
					usCounter--;
				}

				// Get the next exported function name
				uiNameArray += sizeof( DWORD );

				// Get the next exported function name ordinal
				uiNameOrdinals += sizeof( WORD );

				// Decrement our # of names counter
				dwNumberOfNames--;
			}
		}

		// Stop searching when we have found everything we need
		if ( pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pExitThread && pNtFlushInstructionCache ) {
			break;
		}

		// Get the next entry
		uiValueA = DEREF( uiValueA );
	}

	// STEP 2: Load our image into a new permanent location in memory

	// Get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + (( PIMAGE_DOS_HEADER )uiLibraryAddress )->e_lfanew;

	// Allocate all the memory for the DLL to be loaded into. We can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = ( ULONG_PTR )pVirtualAlloc( NULL, (( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// Copy over the headers
	uiValueA = (( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while ( uiValueA-- ) {
		*( PBYTE )uiValueC++ = *( PBYTE )uiValueB++;
	}

	// STEP 3: Load all the sections

	// uiValueA = the VA of the first section
	uiValueA = (( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader + (( PIMAGE_NT_HEADERS )uiHeaderValue )->FileHeader.SizeOfOptionalHeader );
	
	// Iterate through all sections, loading them into memory.
	uiValueE = (( PIMAGE_NT_HEADERS )uiHeaderValue )->FileHeader.NumberOfSections;
	while ( uiValueE-- )
	{
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + (( PIMAGE_SECTION_HEADER )uiValueA )->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = ( uiLibraryAddress + (( PIMAGE_SECTION_HEADER )uiValueA )->PointerToRawData );

		// Copy the section over
		uiValueD = (( PIMAGE_SECTION_HEADER )uiValueA )->SizeOfRawData;

		while ( uiValueD-- )
			*( PBYTE )uiValueB++ = *( PBYTE )uiValueC++;

		// Get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 4: Process our image's import table

	// uiValueB = the address of the import directory
	uiValueB = ( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	// Assume there is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + (( PIMAGE_DATA_DIRECTORY )uiValueB )->VirtualAddress );
	
	// Iterate through all imports
	while ((( PIMAGE_IMPORT_DESCRIPTOR )uiValueC )->Name )
	{
		// Use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = ( ULONG_PTR )pLoadLibraryA(( LPCSTR )( uiBaseAddress + (( PIMAGE_IMPORT_DESCRIPTOR )uiValueC )->Name ));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = ( uiBaseAddress + (( PIMAGE_IMPORT_DESCRIPTOR )uiValueC )->OriginalFirstThunk );
	
		// uiValueA = VA of the IAT ( via first thunk not origionalfirstthunk )
		uiValueA = ( uiBaseAddress + (( PIMAGE_IMPORT_DESCRIPTOR )uiValueC )->FirstThunk );

		// Iterate through all imported functions, importing by ordinal if no name present
		while ( DEREF( uiValueA ))
		{
			// Sanity check uiValueD as some compilers only import by FirstThunk
			if ( uiValueD && (( PIMAGE_THUNK_DATA )uiValueD )->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// Get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + (( PIMAGE_DOS_HEADER )uiLibraryAddress )->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = ( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiExportDir )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// Get the VA of the export directory
				uiExportDir = ( uiLibraryAddress + (( PIMAGE_DATA_DIRECTORY )uiNameArray )->VirtualAddress );

				// Get the VA for the array of addresses
				uiAddressArray = ( uiLibraryAddress + (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->AddressOfFunctions );

				// Use the import ordinal ( - export ordinal base ) as an index into the array of addresses
				uiAddressArray += (( IMAGE_ORDINAL((( PIMAGE_THUNK_DATA )uiValueD )->u1.Ordinal ) - (( PIMAGE_EXPORT_DIRECTORY )uiExportDir )->Base ) * sizeof( DWORD ));

				// Patch in the address for this imported function
				DEREF( uiValueA ) = ( uiLibraryAddress + DEREF_32( uiAddressArray ));
			}
			else
			{
				// Get the VA of this functions import by name struct
				uiValueB = ( uiBaseAddress + DEREF( uiValueA ));

				// Use GetProcAddress and patch in the address for this imported function
				DEREF( uiValueA ) = ( ULONG_PTR )pGetProcAddress(( HMODULE )uiLibraryAddress, ( LPCSTR )(( PIMAGE_IMPORT_BY_NAME )uiValueB )->Name );
			}
			// Get the next imported function
			uiValueA += sizeof( ULONG_PTR );
			if ( uiValueD ) {
				uiValueD += sizeof( ULONG_PTR );
			}
		}

		// Get the next import
		uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: Process all of the image's relocations

	// Calculate the base address delta and perform relocations ( even if we load at desired image base )
	uiLibraryAddress = uiBaseAddress - (( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = ( ULONG_PTR )&(( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// Check if their are any relocations present
	if ((( PIMAGE_DATA_DIRECTORY )uiValueB )->Size )
	{
		// uiValueC is now the first entry ( IMAGE_BASE_RELOCATION )
		uiValueC = ( uiBaseAddress + (( PIMAGE_DATA_DIRECTORY )uiValueB )->VirtualAddress );

		// Iterate through all entries
		while ((( PIMAGE_BASE_RELOCATION )uiValueC )->SizeOfBlock )
		{
			// uiValueA = the VA for this relocation block
			uiValueA = ( uiBaseAddress + (( PIMAGE_BASE_RELOCATION )uiValueC )->VirtualAddress );

			// uiValueB = number of entries in this relocation block
			uiValueB = ((( PIMAGE_BASE_RELOCATION )uiValueC )->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( IMAGE_RELOC );

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof( IMAGE_BASE_RELOCATION );

			//Iterate through all the entries in the current block
			while ( uiValueB-- )
			{
				// Perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// We don't use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if ((( PIMAGE_RELOC )uiValueD )->type == IMAGE_REL_BASED_DIR64 ) {
					*( ULONG_PTR * )( uiValueA + (( PIMAGE_RELOC )uiValueD )->offset ) += uiLibraryAddress;
				}
				else if ((( PIMAGE_RELOC )uiValueD )->type == IMAGE_REL_BASED_HIGHLOW ) {
					*( PDWORD )( uiValueA + (( PIMAGE_RELOC )uiValueD )->offset ) += ( DWORD )uiLibraryAddress;
				}
				else if ((( PIMAGE_RELOC )uiValueD )->type == IMAGE_REL_BASED_HIGH ) {
					*( PWORD )( uiValueA + (( PIMAGE_RELOC )uiValueD )->offset ) += HIWORD( uiLibraryAddress );
				}
				else if ((( PIMAGE_RELOC )uiValueD )->type == IMAGE_REL_BASED_LOW ) {
					*( PWORD )( uiValueA + (( PIMAGE_RELOC )uiValueD )->offset ) += LOWORD( uiLibraryAddress );
				}

				// Get the next entry in the current relocation block
				uiValueD += sizeof( IMAGE_RELOC );
			}

			// Get the next entry in the relocation directory
			uiValueC = uiValueC + (( PIMAGE_BASE_RELOCATION )uiValueC )->SizeOfBlock;
		}
	}

	// STEP 6: Call our image's entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = ( uiBaseAddress + (( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.AddressOfEntryPoint );

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache(( HANDLE )-1, NULL, 0 );

	// Call our respective entry point, fudging our hInstance value.
	// If we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter ( via the DllMain lpReserved parameter )
	(( DLLMAIN )uiValueA )(( HINSTANCE )uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter );

	do
	{
		PIMAGE_DATA_DIRECTORY directory = &(( PIMAGE_NT_HEADERS )uiHeaderValue )->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if ( directory->Size == 0 ) {
			break;
		}

		PIMAGE_EXPORT_DIRECTORY exports = ( PIMAGE_EXPORT_DIRECTORY )( uiBaseAddress + directory->VirtualAddress );
		if ( exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0 ) {
			break;
		}

		// Search function name in list of exported names
		int idx = -1;
		DWORD *nameRef = ( PDWORD )( uiBaseAddress + exports->AddressOfNames );
		WORD *ordinal = ( PWORD )( uiBaseAddress + exports->AddressOfNameOrdinals );
		for ( DWORD i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++ )
		{
			if ( hash(( PCHAR )( uiBaseAddress + ( *nameRef ))) == dwFunctionHash ) {
				idx = *ordinal;
				break;
			}
		}
		if ( idx == -1 ) {
			break;
		}

		// AddressOfFunctions contains the RVAs to the "real" functions
		EXPORTFUNC f = ( EXPORTFUNC )( uiBaseAddress + (*( PDWORD )( uiBaseAddress + exports->AddressOfFunctions + ( idx * 4 ))) );
		if ( !f( lpUserData, nUserdataLen )) {
			break;
		}

		dwExitCode = 0;
	} while ( 0 );

	// Done, exit thread
	if ( pRtlExitUserThread ) {
		pRtlExitUserThread( dwExitCode );
	}
	else {
		pExitThread( dwExitCode );
	}
}
