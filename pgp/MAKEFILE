OBJ1 = rsalib.obj rsaio.obj keygen.obj fprims.obj random.obj
OBJ2 =	basslib.obj basslib2.obj lfsr.obj memmgr.obj md4.obj lzh.obj
SRCS1 = rsalib.c rsalib.h keygen.c keygen.h rsaio.c rsaio.h fprims.asm
SRCS2 =	random.c random.h memmgr.c memmgr.h
SRCS3 =	basslib.c basslib2.c lfsr.c basslib.h basslib2.h lfsr.h
SRCS4 = md4.c md4.h md4.doc lzh.c


pgp.exe : 	pgp.obj $(OBJ1) $(OBJ2)
		link /M /STACK:8192 pgp.obj $(OBJ1) $(OBJ2) ;
		- pgp

pgp.obj : 	pgp.c rsalib.h rsaio.h keygen.h random.h basslib.h basslib2.h md4.h
		cl /c /Oxaz /DDEBUG pgp.c

keygen.obj : 	keygen.c rsalib.h random.h
		del keygen.lst
		cl /c /Oxaz /Za /DDEBUG keygen.c

rsalib.obj : 	rsalib.c rsalib.h
		del rsalib.lst
		cl /c /Oxaz /Za rsalib.c

rsaio.obj : 	rsaio.c rsalib.h rsaio.h
		del rsaio.lst
		cl /c /Oxaz /Za rsaio.c

fprims.obj : 	fprims.asm
		masm fprims ;


random.obj :	random.c random.h
		cl /c /Ox random.c

basslib.obj : 	basslib.c basslib.h memmgr.h lfsr.h
		cl /c /Oxaz /Za basslib.c

basslib2.obj : 	basslib2.c basslib2.h
		cl /c /Oxaz /Za /DDEBUG basslib2.c

lfsr.obj : 	lfsr.c lfsr.h
		cl /c /Oxaz /Za /DDEBUG lfsr.c

memmgr.obj : 	memmgr.c memmgr.h
		cl /c /Oxaz /Za /DDEBUG memmgr.c

lzh.obj :       lzh.c
                cl /c /Oxaz /Za lzh.c

md4.obj : 	md4.c md4.h
		cl /c /Oxaz md4.c


# The following section is for making a release disk...

pgpguide.lst :	pgpguide.doc
		lp pgpguide.doc pgpguide.lst /T1 /B6
		pgp -se pgpguide.doc bond smart testfile.ctx

pgp.ctx :	pgp.exe
		pgp -sb pgp.exe prz

pgpguide.ctx :	pgpguide.lst
		pgp -sb pgpguide.lst prz

pgp10src.ctx :	pgp10src.zip
		pgp -sb pgp10src.zip prz

pgp10.zip :	keyring.sec keyring.pub pgp.ctx prz.pub pgpguide.ctx pgp.exe pgpguide.lst pgp10src.zip setup.doc
		- pkzip -i pgp10src.zip pgp.c pgp.obj pgformat.doc testfile.ctx
		pgp -sb pgp10src.zip prz
		- del pgp10.zip
		pkzip -a pgp10.zip keyring.sec keyring.pub pgp.exe pgpguide.lst setup.doc
		pkzip -a pgp10.zip pgp.ctx pgpguide.ctx pgp10src.ctx prz.pub
		pkzip -v pgp10.zip

pgp10src.zip :	$(SRCS1) $(SRCS2) $(SRCS3) $(SRCS4) $(OBJ1) $(OBJ2) makefile
		- del pgp10src.zip
		pkzip -a pgp10src.zip $(SRCS1)
		pkzip -a pgp10src.zip $(SRCS2)
		pkzip -a pgp10src.zip $(SRCS3)
		pkzip -a pgp10src.zip $(SRCS4) makefile
		pkzip -a pgp10src.zip $(OBJ1)
		pkzip -a pgp10src.zip $(OBJ2)
		pkzip -a pgp10src.zip copyleft.txt
		pkzip -a pgp10src.zip pgp.c pgp.obj pgformat.doc testfile.ctx
		dir pgp10src.zip

pgpsetup.exe :	pgp10.zip
		copy pgp10.zip pgpsetup.zip
		zip2exe pgpsetup
		del pgpsetup.zip

a:pgpsetup.exe : pgpsetup.exe
		copy pgpsetup.exe a: /v

a:pgp10.zip :	pgp10.zip
		copy pgp10.zip a: /v

a:pgp10src.zip :	pgp10src.zip
		copy pgp10src.zip a: /v

a:readme.txt :	readme.txt
		copy readme.txt a: /v

pgrelease :	a:pgp10src.zip a:pgp10.zip a:readme.txt pgpsetup.exe
		dir a:


# The following section is for bringing in source files from elsewhere...

md4 = ..\md4
b = ..\basso
rnd = ..\random
rsa = ..\rsa

rsalib.c :	$(rsa)\rsalib.c
		copy $(rsa)\rsalib.c

rsalib.h :	$(rsa)\rsalib.h
		copy $(rsa)\rsalib.h

rsaio.c :	$(rsa)\rsaio.c
		copy $(rsa)\rsaio.c

rsaio.h :	$(rsa)\rsaio.h
		copy $(rsa)\rsaio.h

keygen.c :	$(rsa)\keygen.c
		copy $(rsa)\keygen.c

keygen.h :	$(rsa)\keygen.h
		copy $(rsa)\keygen.h

random.c :	$(rnd)\random.c
		copy $(rnd)\random.c

random.h :	$(rnd)\random.h
		copy $(rnd)\random.h

basslib.c :	$(b)\basslib.c
		copy $(b)\basslib.c

basslib.h :	$(b)\basslib.h
		copy $(b)\basslib.h

basslib2.c :	$(b)\basslib2.c
		copy $(b)\basslib2.c

basslib2.h :	$(b)\basslib2.h
		copy $(b)\basslib2.h

lfsr.c :	$(b)\lfsr.c
		copy $(b)\lfsr.c

lfsr.h :	$(b)\lfsr.h
		copy $(b)\lfsr.h

memmgr.c :	$(b)\memmgr.c
		copy $(b)\memmgr.c

memmgr.h :	$(b)\memmgr.h
		copy $(b)\memmgr.h

fprims.asm :	$(rsa)\fprims.asm
		copy $(rsa)\fprims.asm

md4.c 	:	$(md4)\md4.c
		copy $(md4)\md4.c

#md4.h 	:	$(md4)\md4.h
#		copy $(md4)\md4.h
# Commented out because of inexplicable bug in NDMAKE make utility.



