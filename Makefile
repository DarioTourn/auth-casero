MAKEFLAGS += -s

# Nombre de los módulos y archivos .so
NOMBRE_MODULO_TOTP = pam_auth_casero
NOMBRE_MODULO_ENCRIPTADOR = pam_encriptador_seed

# Nombre de la aplicacion generadora
NOMBRE_GENERADOR = generador-seed

# Rutas de instalacion de los modulos y aplicacion
ARCHIVO_SALIDA_TOTP = /lib/x86_64-linux-gnu/security/$(NOMBRE_MODULO_TOTP).so
ARCHIVO_SALIDA_ENCRIPTADOR = /lib/x86_64-linux-gnu/security/$(NOMBRE_MODULO_ENCRIPTADOR).so
ARCHIVO_SALIDA_GENERADOR = /usr/local/bin/$(NOMBRE_GENERADOR)

# Archivos de código fuente
SRC_TOTP = src/$(NOMBRE_MODULO_TOTP).c
SRC_ENCRIPTADOR = src/$(NOMBRE_MODULO_ENCRIPTADOR).c
SRC_GENERADOR = $(NOMBRE_GENERADOR).c

# Archivo de configuracion a mover
ARCHIVO_CONF_GENERADOR = generador-seed-pam
RUTA_CONF_GENERADOR = /etc/pam.d/$(ARCHIVO_CONF_GENERADOR)

# Compilador y opciones
CC = gcc
CFLAGS = -fPIC -Wall -shared

# Librerias
LIBS_GENERADOR = -lpam -lpam_misc
LIBS_TOTP = -lpam -lcotp -lpam_misc
LIBS_ENCRIPTADOR = -lpam -lpam_misc

# Objetivos
all: $(ARCHIVO_SALIDA_TOTP) $(ARCHIVO_SALIDA_GENERADOR) $(ARCHIVO_SALIDA_ENCRIPTADOR) $(RUTA_CONF_GENERADOR)

# Regla para compilar el módulo TOTP
$(ARCHIVO_SALIDA_TOTP): $(SRC_TOTP)
	$(CC) $(CFLAGS) -o $(ARCHIVO_SALIDA_TOTP) $(SRC_TOTP) $(LIBS_TOTP)
	@echo "Módulo PAM $(ARCHIVO_SALIDA_TOTP) compilado con éxito."

# Regla para compilar el módulo encriptador
$(ARCHIVO_SALIDA_ENCRIPTADOR): $(SRC_ENCRIPTADOR)
	$(CC) $(CFLAGS) -o $(ARCHIVO_SALIDA_ENCRIPTADOR) $(SRC_ENCRIPTADOR) $(LIBS_ENCRIPTADOR)
	@echo "Módulo PAM $(ARCHIVO_SALIDA_ENCRIPTADOR) compilado con éxito."

# Regla para compilar generador-seed
$(ARCHIVO_SALIDA_GENERADOR): $(SRC_GENERADOR)
	$(CC) -o $(ARCHIVO_SALIDA_GENERADOR) $(SRC_GENERADOR) $(LIBS_GENERADOR)
	@echo "Generador-seed compilado con éxito."

# Regla para mover el archivo de configuracion del generador
$(RUTA_CONF_GENERADOR): $(ARCHIVO_CONF_GENERADOR)
	cp $(ARCHIVO_CONF_GENERADOR) $(RUTA_CONF_GENERADOR)
	chown root:root $(RUTA_CONF_GENERADOR)
	chmod 644 $(RUTA_CONF_GENERADOR)
	@echo "Archivo $(ARCHIVO_CONF_GENERADOR) movido a $(RUTA_CONF_GENERADOR)."

install: all
	@echo "Instalación completada."	

# Regla para limpiar los archivos temporales
clean:
	rm -f $(ARCHIVO_SALIDA_TOTP)
	rm -f $(ARCHIVO_SALIDA_GENERADOR)
	rm -f $(ARCHIVO_SALIDA_ENCRIPTADOR)
	rm -f $(RUTA_CONF_GENERADOR)
	@echo "Archivos limpios."

.PHONY: all clean install
