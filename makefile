##################################################
## Diplomova praca                              ##
## Meno studenta: Jozef Vendel                  ##
## Veduci DP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 02.04.2022	                ##
##################################################

CC=gcc
CFLAGS=-c -O2 -Wall -fcommon -I./INC
LDFLAGS= -lm

#meno vytvorenej kniznice
LIBRARY=salt_example_rs-232.a
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
	$(CC) -o $@ $+ $(LDFLAGS)
	
.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

$(LIBRARY): $(OBJ_LIB) #linkovanie suborov kniznice do statickej kniznice
	ar rcu $@ $+
	ranlib $@

clean:
	rm -f $(EXECUTABLE).exe *.o *.a SRC_LIB/*.o

