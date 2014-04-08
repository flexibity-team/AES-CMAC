


CC= gcc
CFLAGS=-g -Wall -DSHA2_USE_INTTYPES_H -DWITH_SHA256 
INCLUDEDIR= -I sha2
EXT_SOURCES= TI_aes_128.c aes_cbc.c





EXT_OBJ=$(EXT_SOURCES:.c=.o)
EXECUTABLE= testcbc


all: $(EXT_SOURCES) $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) -c $< -o $@

$(EXECUTABLE): $(EXT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDEDIR) $(EXT_OBJ) $@.c -o $@

clean:
	rm -f $(EXT_OBJ) $(EXECUTABLE)


