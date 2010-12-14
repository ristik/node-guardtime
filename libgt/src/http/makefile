#
# $Id: makefile 98 2010-12-01 13:19:04Z ahto.truu $
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
# This is the NMake makefile.
#
# For usage info, go to the directory two levels up from here
# and look in the makefile there.
#
#

!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

SRC_DIR = .
OBJ_DIR = ..\..\obj\$(DLL)$(RTL)
INC_DIR = ..\..\out\include
LIB_DIR = ..\..\out\$(DLL)
BIN_DIR = ..\..\out

LIB = libgthttp

LIB_INC = gt_http.h

LIB_OBJ = \
	$(OBJ_DIR)\gt_http.obj

LIB_DEF = $(SRC_DIR)\$(LIB).def

EXT_LIB = libgtbase$(RTL).lib \
	libeay32$(RTL).lib \
	wininet.lib wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib advapi32.lib

EXT_DEP =  $(LIB_DIR)\libgtbase$(RTL).lib

LIB_LIC = \
	$(BIN_DIR)\license.txt \
	$(BIN_DIR)\license.openssl.txt

.SUFFIXES: .txt

CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) /I$(INC_DIR)
LDFLAGS = /NOLOGO /LIBPATH:$(LIB_DIR)
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF
!IF "$(DLL)" == "lib"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\lib"
!ELSE
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\dll"
!ENDIF
CCFLAGS = $(CCFLAGS) $(CCEXTRA)
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(VCINSTALLDIR)\lib" /LIBPATH:"$(WINDOWSSDKDIR)lib"
LDFLAGS = $(LDFLAGS) $(LDEXTRA)

default: $(LIB_DIR) $(LIB_DIR)\$(LIB)$(RTL).$(DLL) $(INC_DIR) $(INC_DIR)\$(LIB_INC) $(LIB_LIC)

$(LIB_DIR)\$(LIB)$(RTL).lib: $(OBJ_DIR)\$(LIB).lib
	copy /y $(OBJ_DIR)\$(LIB).lib $(LIB_DIR)\$(LIB)$(RTL).lib

$(OBJ_DIR)\$(LIB).lib: $(LIB_OBJ)
	link /LIB /OUT:$@ $(LIB_OBJ)

$(LIB_DIR)\$(LIB)$(RTL).dll: $(OBJ_DIR)\$(LIB).dll
	copy /y $(OBJ_DIR)\$(LIB).dll $(LIB_DIR)\$(LIB)$(RTL).dll
	copy /y $(OBJ_DIR)\$(LIB).lib $(LIB_DIR)\$(LIB)$(RTL).lib

$(OBJ_DIR)\$(LIB).dll: $(LIB_OBJ) $(LIB_DEF)
	link /DLL $(LDFLAGS) /OUT:$@ /IMPLIB:$*.lib /DEF:$(LIB_DEF) $(LIB_OBJ) $(EXT_LIB)

check: default $(BIN_DIR) $(BIN_DIR)\http_create.exe $(BIN_DIR)\http_extend.exe $(BIN_DIR)\http_verify.exe

$(BIN_DIR)\http_create.exe: $(OBJ_DIR)\http_create.obj $(LIB_DIR)\$(LIB)$(RTL).lib $(EXT_DEP)
	link $(LDFLAGS) /OUT:$@ $** $(LIB)$(RTL).lib $(EXT_LIB)

$(BIN_DIR)\http_extend.exe: $(OBJ_DIR)\http_extend.obj $(LIB_DIR)\$(LIB)$(RTL).lib $(EXT_DEP)
	link $(LDFLAGS) /OUT:$@ $** $(LIB)$(RTL).lib $(EXT_LIB)

$(BIN_DIR)\http_verify.exe: $(OBJ_DIR)\http_verify.obj $(LIB_DIR)\$(LIB)$(RTL).lib $(EXT_DEP)
	link $(LDFLAGS) /OUT:$@ $** $(LIB)$(RTL).lib $(EXT_LIB)

$(INC_DIR)\$(LIB_INC): $(INC_DIR) $(SRC_DIR)\$(LIB_INC)
	copy /y $(SRC_DIR)\$(LIB_INC) $@

$(LIB_OBJ): $(OBJ_DIR)

{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

$(LIB_LIC): $(BIN_DIR)

{$(SRC_DIR)\..\}.txt{$(BIN_DIR)\}.txt:
	copy /y $< $@

$(OBJ_DIR) $(INC_DIR) $(LIB_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@
