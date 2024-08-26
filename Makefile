MAKEFLAGS += -s

# Nombre del módulo y el archivo .so
NOMBRE_MODULO = pam_auth_casero

NOMBRE_GENERADOR = generador-seed
ARCHIVO_SALIDA = /lib/x86_64-linux-gnu/security/$(NOMBRE_MODULO).so
ARCHIVO_SALIDA_GENERADOR = /usr/local/bin/$(NOMBRE_GENERADOR)

# Archivos de código fuente
SRC = src/$(NOMBRE_MODULO).c
SRC_GENERADOR = $(NOMBRE_GENERADOR).c

# Archivo a mover
ARCHIVO_PAM = generador-seed-pam
RUTA_PAM = /etc/pam.d/$(ARCHIVO_PAM)

# Compilador y opciones
CC = gcc
CFLAGS = -fPIC -Wall -shared
LIBS_GENERADOR = -lpam -lpam_misc
LIBS = -lpam -lcotp -lpam_misc

# Objetivos
all: $(ARCHIVO_SALIDA) $(ARCHIVO_SALIDA_GENERADOR) $(RUTA_PAM)

# Regla para compilar el módulo PAM
$(ARCHIVO_SALIDA): $(SRC)
	$(CC) $(CFLAGS) -o $(ARCHIVO_SALIDA) $(SRC) $(LIBS)
	@echo "Módulo PAM $(ARCHIVO_SALIDA) compilado con éxito."

# Regla para compilar generador-seed
$(ARCHIVO_SALIDA_GENERADOR): $(SRC_GENERADOR)
	$(CC) -o $(ARCHIVO_SALIDA_GENERADOR) $(SRC_GENERADOR) $(LIBS_GENERADOR)
	@echo "Generador-seed compilado con éxito."

# Regla para mover el archivo PAM
$(RUTA_PAM): $(ARCHIVO_PAM)
	cp $(ARCHIVO_PAM) $(RUTA_PAM)
	chown root:root $(RUTA_PAM)
	chmod 644 $(RUTA_PAM)
	@echo "Archivo $(ARCHIVO_PAM) movido a $(RUTA_PAM)."

install: all
	@echo "Instalación completada."	

# Regla para limpiar los archivos temporales
clean:
	rm -f $(ARCHIVO_SALIDA)
	rm -f $(ARCHIVO_SALIDA_GENERADOR)
	rm -f $(RUTA_PAM)
	@echo "Archivos limpios."

.PHONY: all clean install
