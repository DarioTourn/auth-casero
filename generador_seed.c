#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"

void generar_seed(char *semilla) {
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < 32; ++i) {
        semilla[i] = base32_chars[rand() % 32];
    }
    semilla[32] = '\0'; // Asegurarse de que la cadena esté terminada en nulo
}

int main() {
    char semilla[33]; // Debería ser de 33 para incluir el terminador nulo
    char ruta[512];

    // Inicializar el generador de números aleatorios
    srand((unsigned int) time(NULL));

    // Obtener el nombre de usuario
    char *dir_home = getenv("HOME");
    if (dir_home == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la ruta del archivo");
        return 1; // Error al obtener el nombre de usuario
    }

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta);

    FILE *archivo = fopen(ruta, "r");

    if (archivo == NULL) {
        // Si el archivo no existe, generar una nueva semilla
        generar_seed(semilla);
        archivo = fopen(ruta, "w");
        if (archivo == NULL) {
            syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
            return 1; // Error al abrir el archivo
        }
        fwrite(semilla, 1, 32, archivo);
        printf("Su semilla es: %s\n", semilla);
        fclose(archivo);
    } else {
        char nueva_ruta[512];
        
        snprintf(nueva_ruta, sizeof(nueva_ruta), "%s/%s", dir_home, ".seed_auth_casero_nuevo");
        FILE *nuevo_archivo = fopen(nueva_ruta, "w");
        if (nuevo_archivo == NULL) {
            syslog(LOG_ERR, "Error al abrir el nuevo archivo de semilla de autenticación");
            fclose(archivo);
            return 1; // Error al abrir el nuevo archivo
        }
        generar_seed(semilla);
        fwrite(semilla, 1, 32, nuevo_archivo);
        fclose(archivo);
        fclose(nuevo_archivo);
        remove(ruta);
        rename(nueva_ruta, ruta);
        printf("Su semilla es: %s\n", semilla);
    }

    return 0;
}