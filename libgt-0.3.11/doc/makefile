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
# This is the NMake makefile.
#
# For usage info, go to the directory one level up from here
# and look in the makefile there.
#

DOCSRC = ..\src\overview.dox \
         ..\src\base\overview.dox \
         ..\src\base\gt_base.h \
         ..\src\http\overview.dox \
         ..\src\http\gt_http.h \
         ..\src\png\overview.dox \
         ..\src\png\gt_png.h

HTMLSRC = .\TspOverview.png \
          .\ApiVerifyTimestamp.png

PDFSRC = .\TspOverview.pdf \
         .\ApiVerifyTimestamp.pdf

doc: htmldoc pdfdoc

htmldoc: .\html\index.html

pdfdoc: .\latex\refman.pdf

.\html\index.html: .\doxyfile.public $(DOCSRC) $(HTMLSRC)
	doxygen .\doxyfile.public

.\latex\refman.pdf: .\latex\refman.tex
	cd .\latex
	pdflatex .\refman.tex
	makeindex .\refman.idx
	pdflatex .\refman.tex
	pdflatex .\refman.tex
	pdflatex .\refman.tex
	cd ..

.\latex\refman.tex: .\doxyfile.public $(DOCSRC) $(PDFSRC)
	doxygen .\doxyfile.public
