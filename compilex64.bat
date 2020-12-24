cl.exe /nologo /GL /O1 /MT /W4 /GS- /permissive- /diagnostics:caret /D_USRDLL /D_WINDLL /Tc dll/src/*.c /link "User32.lib" /MACHINE:x64 /DLL /OUT:reflectivex64.dll

del *.obj
