#
# $Id: makefile 195 2014-01-20 19:28:39Z ahto.truu $
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

!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

!IF "$(OPENSSL_CA_FILE)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_FILE=\"$(OPENSSL_CA_FILE:\=\\)\"
!ENDIF

!IF "$(OPENSSL_CA_DIR)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_DIR=\"$(OPENSSL_CA_DIR:\=\\)\" 
!ENDIF

SRC_DIR = .
OBJ_DIR = ..\..\obj\$(DLL)$(RTL)
INC_DIR = ..\..\out\include
LIB_DIR = ..\..\out\$(DLL)
BIN_DIR = ..\..\out

LIB_NAME = libgtbase

LIB_INC = gt_base.h

LIB_OBJ = \
	$(OBJ_DIR)\asn1_time_get.obj \
	$(OBJ_DIR)\base32.obj \
	$(OBJ_DIR)\gt_asn1.obj \
	$(OBJ_DIR)\gt_base.obj \
	$(OBJ_DIR)\gt_crc32.obj \
	$(OBJ_DIR)\gt_datahash.obj \
	$(OBJ_DIR)\gt_fileio.obj \
	$(OBJ_DIR)\gt_info.obj \
	$(OBJ_DIR)\gt_internal.obj \
	$(OBJ_DIR)\gt_publicationsfile.obj \
	$(OBJ_DIR)\gt_timestamp.obj \
	$(OBJ_DIR)\gt_truststore.obj \
	$(OBJ_DIR)\hashchain.obj

LIB_DEF = $(SRC_DIR)\$(LIB_NAME).def

EXT_LIB = libeay32$(RTL).lib \
	user32.lib gdi32.lib advapi32.lib crypt32.lib

CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) /I$(INC_DIR)
LDFLAGS = /NOLOGO /LIBPATH:$(LIB_DIR)
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include"
!IF "$(DLL)" == "lib"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\lib"
!ELSE
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\dll"
!ENDIF
CCFLAGS = $(CCFLAGS) $(CCEXTRA) $(TRUSTSTORE_MACROS)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)

default: $(LIB_DIR) $(LIB_DIR)\$(LIB_NAME)$(RTL).$(DLL) $(INC_DIR) $(INC_DIR)\$(LIB_INC)

$(LIB_DIR)\$(LIB_NAME)$(RTL).lib: $(OBJ_DIR)\$(LIB_NAME).lib
	copy /y $(OBJ_DIR)\$(LIB_NAME).lib $(LIB_DIR)\$(LIB_NAME)$(RTL).lib

$(OBJ_DIR)\$(LIB_NAME).lib: $(LIB_OBJ)
	link /LIB /OUT:$@ $(LIB_OBJ)

$(LIB_DIR)\$(LIB_NAME)$(RTL).dll: $(OBJ_DIR)\$(LIB_NAME).dll
	copy /y $(OBJ_DIR)\$(LIB_NAME).dll $(LIB_DIR)\$(LIB_NAME)$(RTL).dll
	copy /y $(OBJ_DIR)\$(LIB_NAME).lib $(LIB_DIR)\$(LIB_NAME)$(RTL).lib

$(OBJ_DIR)\$(LIB_NAME).dll: $(LIB_OBJ) $(LIB_DEF)
	link /DLL $(LDFLAGS) /OUT:$@ /IMPLIB:$*.lib /DEF:$(LIB_DEF) $(LIB_OBJ) $(EXT_LIB)

check: default $(BIN_DIR)

$(INC_DIR)\$(LIB_INC): $(INC_DIR) $(SRC_DIR)\$(LIB_INC)
	copy /y $(SRC_DIR)\$(LIB_INC) $@

$(LIB_OBJ): $(OBJ_DIR)

{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

$(OBJ_DIR) $(INC_DIR) $(LIB_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@
