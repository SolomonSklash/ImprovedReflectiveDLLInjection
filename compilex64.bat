cl.exe /nologo /GL /O1 /MT /W4 /GS- /permissive- /diagnostics:caret /D_USRDLL /D_WINDLL /Tc dll/src/*.c /link "User32.lib" /MACHINE:x64 /DLL /OUT:reflective-x64.dll

del *.obj
del *.lib
del *.exp