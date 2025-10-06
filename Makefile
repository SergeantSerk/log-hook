# Makefile (MSVC) - run this from a Visual Studio Developer Command Prompt

CL ?= cl
LINK ?= link

INCDIR = third_party/MinHook/include
LIBDIR = third_party/MinHook/lib

CFLAGS = /nologo /MD /W3 /EHsc /Zi
LDFLAGS = /nologo

SRCDIR = src
OUTDIR = out

HOOK_OBJ = $(OUTDIR)/hook_vsnprintf.obj
HOOK_DLL = $(OUTDIR)/HookDLL.dll
INJ_OBJ = $(OUTDIR)/injector.obj
INJ_EXE = $(OUTDIR)/injector.exe

all: dirs hook injector

dirs:
\t@if not exist $(OUTDIR) mkdir $(OUTDIR)

hook: $(HOOK_DLL)

$(HOOK_OBJ): $(SRCDIR)/hook_vsnprintf.cpp
\t$(CL) $(CFLAGS) /I"$(INCDIR)" /Fo"$(HOOK_OBJ)" /c $(SRCDIR)/hook_vsnprintf.cpp

$(HOOK_DLL): $(HOOK_OBJ)
\t$(LINK) $(LDFLAGS) /DLL /OUT:$(HOOK_DLL) $(HOOK_OBJ) "$(LIBDIR)/MinHook.lib" Kernel32.lib User32.lib

injector: $(INJ_EXE)

$(INJ_OBJ): $(SRCDIR)/injector.cpp
\t$(CL) $(CFLAGS) /Fo"$(INJ_OBJ)" /c $(SRCDIR)/injector.cpp

$(INJ_EXE): $(INJ_OBJ)
\t$(LINK) $(LDFLAGS) /OUT:$(INJ_EXE) $(INJ_OBJ) Kernel32.lib

clean:
\t-@del /Q "$(OUTDIR)\*" 2>nul || true

.PHONY: all dirs hook injector clean
