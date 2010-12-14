#
# $Id: makefile 74 2010-02-22 11:42:26Z ahto.truu $
#
# Copyright 2009-2010 GuardTime AS
#
# This file is part of the GuardTime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License. 
#
#
# This is the top-level NMake makefile.
#
# To build one version of the libraries, issue
#     nmake
# To build all versions of the libraries, issue
#     nmake all
# To build the example programs, issue
#     nmake check
# To build the full documentation, issue
#     nmake doc
# To build just the HTML documentation, issue
#     nmake htmldoc
#
# Specify building a static library or a DLL with DLL=lib or DLL=dll
# and the debug/release version and the runtime library to use with
# RTL=MT, RTL=MTd, RTL=MD, or RTL=MDd, for example
#     nmake DLL=dll RTL=MDd
# The default is fully static linking, release version. The DLL and
# RTL options also affect the way examples are compiled and linked.
#
# To pass extra settings for compilation, set CCEXTRA. To pass extra
# settings for linking (for both DLLs and EXEs), set LDEXTRA.
#

# Default to full static linking, relase version
!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

MODEL = DLL=$(DLL) RTL=$(RTL)
EXTRA = CCEXTRA=$(CCEXTRA) LDEXTRA=$(LDEXTRA)

default:
	cd .\src\base
	nmake $(MODEL) $(EXTRA)
	cd ..\..
	cd .\src\http
	nmake $(MODEL) $(EXTRA)
	cd ..\..
	cd .\src\png
	nmake $(MODEL) $(EXTRA)
	cd ..\..

all: libMT libMTd libMD libMDd dllMT dllMTd dllMD dllMDd

libMT:
	nmake DLL=lib RTL=MT $(EXTRA)

libMTd:
	nmake DLL=lib RTL=MTd $(EXTRA)

libMD:
	nmake DLL=lib RTL=MD $(EXTRA)

libMDd:
	nmake DLL=lib RTL=MDd $(EXTRA)

dllMT:
	nmake DLL=dll RTL=MT $(EXTRA)

dllMTd:
	nmake DLL=dll RTL=MTd $(EXTRA)

dllMD:
	nmake DLL=dll RTL=MD $(EXTRA)

dllMDd:
	nmake DLL=dll RTL=MDd $(EXTRA)

check:
	cd .\src\base
	nmake check $(MODEL) $(EXTRA)
	cd ..\..
	cd .\src\http
	nmake check $(MODEL) $(EXTRA)
	cd ..\..
	cd .\src\png
	nmake check $(MODEL) $(EXTRA)
	cd ..\..

doc: htmldoc pdfdoc

htmldoc:
	cd .\doc
	nmake htmldoc
	cd ..

pdfdoc:
	cd .\doc
	nmake pdfdoc
	..

clean:
	@for %i in (obj out doc\html doc\latex) do if exist .\%i rmdir /s /q .\%i
	@for %i in (src\base src\http src\png) do if exist .\%i\*.pdb del /q .\%i\*.pdb
