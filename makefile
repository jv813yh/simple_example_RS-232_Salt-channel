CC=gcc
CFLAGS=-c -O2 -Wall -fcommon -I./INC


#meno vytvorenej kniznice
LIBRARY=libcrypto.a
#umiestnenie zdrojakov kniznice
SRC_LIB_DIR=SRC_LIB

#automateicke generovanie zdrojakov kniznice
SRC_LIB := $(wildcard $(SRC_LIB_DIR)/*.c)
OBJ_LIB=$(SRC_LIB:.c=.o)

#meno vykonatelneho programu
EXECUTABLE= client server
#vymenovanie zdrojakov aplikacie
SRC_EXE=client00.c server00.c
OBJ_EXE=$(SRC_EXE:.c=.o)


all: $(SRC_EXE) $(SRC_LIB) $(EXECUTABLE)

%: %00.o $(LIBRARY)
	$(CC) -o $@ $+ 
	
.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(LIBRARY): $(OBJ_LIB) #linkovanie suborov kniznice do statickej kniznice
	ar rcu $@ $+
	ranlib $@

clean:
	rm -f $(EXECUTABLE).exe *.o *.a SRC_LIB/*.o

