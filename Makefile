CXX=i686-w64-mingw32-g++
CFLAGS=-fexec-charset=gbk -static -O1 -I /usr/share/mingw-w64/include/ddk
EXEFILES = main.exe

.SUFFIXES:
.SUFFIXES: .exe .o .cpp

all: $(EXEFILES)

.cpp.exe:
	$(CXX) $*.cpp $(CFLAGS) -o $*.exe

clean:
	rm -f *.exe
