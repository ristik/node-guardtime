set PRF=libgt-0.3.8

del %PRF%*.zip

nmake clean
if errorlevel 1 goto done

zip -ro %PRF%-src.zip config doc src test build-linux.txt build-win32.txt changelog configure.ac GNUmakefile.am makefile -x *.pdb

nmake all
if errorlevel 1 goto done

cd out
zip -ro ..\%PRF%-bin.zip *
cd ..

nmake check
if errorlevel 1 goto done

nmake doc
if errorlevel 1 goto done

copy doc\latex\refman.pdf doc\refman.pdf
zip -ro %PRF%-doc.zip doc\html doc\refman.pdf

:done
