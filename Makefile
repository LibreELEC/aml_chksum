PROJECT = aml_chksum
OBJECTS = aml_chksum.o sha256.o

CFLAGS = -Wall -Werror -pedantic -std=c99
ifeq (${DEBUG},1)
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -O2
endif

# Make soft links and include from local directory otherwise wrong headers
# could get pulled in from firmware tree.
INCLUDE_PATHS = -I.

CC := gcc
RM := rm -rf

.PHONY: all clean

all: ${PROJECT}

${PROJECT}: ${OBJECTS} Makefile
	@echo "  LD      $@"
	${Q}${CC} ${OBJECTS} -o $@

%.o: %.c %.h Makefile
	@echo "  CC      $<"
	${Q}${CC} -c ${CFLAGS} ${INCLUDE_PATHS} $< -o $@

clean:
	${Q}${RM} ${PROJECT}
	${Q}${RM} ${OBJECTS}
