# Nombre del módulo y el archivo .so
NOMBRE_MODULO = pam_auth_casero

NOMBRE_GENERADOR = genereador-seed
ARCHIVO_SALIDA = /lib/x86_64-linux-gnu/security/$(NOMBRE_MODULO).so
ARCHIVO_SALIDA_GENERADOR = /usr/local/bin/$(NOMBRE_GENERADOR).so

# Compilador y opciones
CC = gcc
CFLAGS = -fPIC -Wall -shared
LIBS = -lpam -lcotp -lpam_misc

# Archivos de código fuente
SRC = src/$(NOMBRE_MODULO).c

SRC_GENERADOR = $(NOMBRE_GENERADOR).c

# Objetivos
all: $(ARCHIVO_SALIDA) $(ARCHIVO_SALIDA_GENERADOR)

# Regla para compilar el módulo PAM
$(ARCHIVO_SALIDA): $(SRC)
	$(CC) $(CFLAGS) -o $(ARCHIVO_SALIDA) $(SRC) $(LIBS)
	@echo "Módulo PAM $(ARCHIVO_SALIDA) compilado con éxito."

# Regla para compilar generador-seed
$(ARCHIVO_SALIDA_GENERADOR): $(SRC_GENERADOR)
	$(CC) -o $(NOMBRE_GENERADOR) generador_seed.c
	@echo "Generador-seed compilado con éxito."
  
# Regla para limpiar los archivos temporales
clean:
	rm -f $(ARCHIVO_SALIDA)
	@echo "Archivos limpios."

# Instalación del módulo en el directorio de módulos PAM
install: all
	@echo "Módulo PAM instalado en $(ARCHIVO_SALIDA)."

.PHONY: all clean install
