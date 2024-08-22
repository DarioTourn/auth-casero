# Nombre del módulo y el archivo .so
NOMBRE_MODULO = pam_auth_casero
ARCHIVO_SALIDA = /lib/x86_64-linux-gnu/security/$(NOMBRE_MODULO).so

# Compilador y opciones
CC = gcc
CFLAGS = -fPIC -Wall -shared
LIBS = -lpam -lcotp -lpam_misc

# Archivos de código fuente
SRC = src/$(NOMBRE_MODULO).c

# Objetivos
all: $(ARCHIVO_SALIDA) generador-seed

# Regla para compilar el módulo PAM
$(ARCHIVO_SALIDA): $(SRC)
	$(CC) $(CFLAGS) -o $(ARCHIVO_SALIDA) $(SRC) $(LIBS)
	@echo "Módulo PAM $(ARCHIVO_SALIDA) compilado con éxito."

# Regla para compilar generador-seed
generador-seed: generador_seed.c
	$(CC) -o generador-seed generador_seed.c
	@echo "Generador-seed compilado con éxito."
.PHONY: all clean install