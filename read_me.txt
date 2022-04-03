##################################################
## Diplomova  praca                             ##
## Meno studenta: Jozef Vendel                  ##
## Veduci DP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 24.12.2021	                ##
##################################################

Zoznam suborov
  
 simple_example_RS-232_Salt-channel
      |__INC
      |__SCR_LIB
      |__client00.c
      |__server00.c
      |__makefile
      |__readme.txt
      |__client.bat
      |__server.bat


Demonstrovanie prikladu vyuzivajuceho komunikacny kanal RS-232 s
implementaciou aplikacneho kryptografickeho protokolu salt-channelv2
jazyku C. Aplikacia client.exe nacita vstupny subor, ktory je predany
a inicializuje salt handshake medzi klientom
a serverom.Klient, taktiez odosle serveru
velkost prenasaneho suboru a velkost blokoch, v ktorych sa subor prenasa.
Ak salt handshake sa vykona uspesne, je nadviazane bezpecne 
spojenie klient-server. Klient odosle nacitany subor serveru
, server ho prijme desifruje a vypisuje do suboru. 
Pomocou konstant protokolu SALT_SUCCESS a SALT_ERROR sa overuje uspesnost
prenasanych dat. Ak cely proces sa vykona v poriadku, server odosle
klientovi potvrdzujucu spravu, ze vymena dat prebehla spravne, ak nie
odosle mu, ze vymena dat neprebehla spravne a je nutne proces vymenny dat
zopakovat. Prijimaju a odosielaju sa data v ramci COM portov (cislo, 
je potrebne upravit v zdrojokoych kodoch).

Program je kompilovatelny pomocou Makefile suboru. Je pridana funkcia 
pre nacitanie vstupneho suboru, ktory sa odosiela, taktiez funkcia vykonava
operaciu, ak uzivatel chce vytvorit vlastny testovaci subor a ten odoslat kanalom.

Kompilovane na Windowse pomocou WinLibs: 
https://winlibs.com/
Na Linuxe pomocou Ubuntu 20.04 GCC 9.4.0

Protokol salt channel je pohanay kryptografickou kniznicou tweetNaCl: 
https://tweetnacl.cr.yp.to/

Na simulovanie hardverovych rozhrani RS-232 vyuzivam emulator na Windows: 
https://www.ai-media.tv/wp-content/uploads/2019/07/com0com_setup.pdf
Na Linuxeje potrebne sa priradit so skupiny "dialout" a mat aktivne porty.
