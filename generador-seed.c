#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h> // Necesario para chmod	
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"

static struct pam_conv conv = {
    misc_conv, /* Conversation function defined in pam_misc.h */
    NULL /* We don't need additional data now*/
};

void generar_seed(char *semilla) {
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < 32; ++i) {
        semilla[i] = base32_chars[rand() % 32];
    }
    semilla[32] = '\0'; // Asegurarse de que la cadena esté terminada en nulo
}

void nueva_semilla() {
    char semilla[33]; // Debería ser de 33 para incluir el terminador nulo
    char ruta[512];

    // Inicializar el generador de números aleatorios
    srand((unsigned int) time(NULL));

    // Obtener el nombre de usuario
    char *dir_home = getenv("HOME");
    if (dir_home == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la ruta del archivo");
        return; // Error al obtener el nombre de usuario
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
            return;
        }
        fwrite(semilla, 1, 32, archivo);
        fclose(archivo);

        // Cambiar permisos del archivo
        if (chmod(ruta, S_IRUSR | S_IWUSR) != 0) {
            syslog(LOG_ERR, "Error al cambiar los permisos del archivo");
            printf("Error al cambiar los permisos del archivo");
            return;
        }

        printf("Su semilla es: %s\n", semilla);
    } else {
        char nueva_ruta[512];
        
        snprintf(nueva_ruta, sizeof(nueva_ruta), "%s/%s", dir_home, ".seed_auth_casero_nuevo");
        FILE *nuevo_archivo = fopen(nueva_ruta, "w");
        if (nuevo_archivo == NULL) {
            syslog(LOG_ERR, "Error al abrir el nuevo archivo de semilla de autenticación");
            fclose(archivo);
            return;
        }
        generar_seed(semilla);
        fwrite(semilla, 1, 32, nuevo_archivo);
        fclose(archivo);
        fclose(nuevo_archivo);
        if (remove(ruta) != 0) {
            syslog(LOG_ERR, "Error al eliminar el archivo antiguo");
            printf("Error al eliminar el archivo antiguo");
            return;
        }
        if (rename(nueva_ruta, ruta) != 0) {
            syslog(LOG_ERR, "Error al renombrar el archivo nuevo");
            printf("Error al renombrar el archivo nuevo");
            return;
        }

        // Cambiar permisos del archivo
        if (chmod(ruta, S_IRUSR | S_IWUSR) != 0) {
            syslog(LOG_ERR, "Error al cambiar los permisos del archivo");
            printf("Error al cambiar los permisos del archivo");
            return;
        }

        printf("Su semilla es: %s\n", semilla);
    }
}

void leer_semilla() {
    char semilla[33];
    char ruta[512];
    char *dir_home = getenv("HOME");
    if (dir_home == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la ruta del archivo");
        printf("No se pudo obtener la ruta del archivo\n");
        return;
    }
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);
    FILE *archivo = fopen(ruta, "r");
    if (archivo == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        printf("Error al abrir el archivo de semilla de autenticación\n");
        return;
    }
    if (fgets(semilla, sizeof(semilla), archivo) == NULL) {
        syslog(LOG_ERR, "Error al leer la semilla de autenticación");
        printf("Error al leer la semilla de autenticación\n");
        fclose(archivo);
        return;
    }
    printf("La semilla es: %s\n", semilla);
    syslog(LOG_INFO, "Semilla encontrada con éxito");
    fclose(archivo);
}

int main() {
    pam_handle_t *pamh = NULL;
    const char *service_name = "generador-seed-pam";
    int val_retorno;

    openlog("generador-seed", LOG_PID | LOG_CONS, LOG_AUTH);
    syslog(LOG_INFO, "Iniciando autenticación PAM");

    val_retorno = pam_start(service_name, NULL, &conv, &pamh);
    if (val_retorno != PAM_SUCCESS) {
        syslog(LOG_ERR, "Error al iniciar la autenticación: %s", pam_strerror(pamh, val_retorno));
        printf("Error al iniciar la autenticación: %s\n", pam_strerror(pamh, val_retorno));
        return 1;
    }

    int res = pam_authenticate(pamh, 0);
    if (res != PAM_SUCCESS) {
        syslog(LOG_ERR, "Error en la autenticación: %s", pam_strerror(pamh, res));
        printf("Error en la autenticación: %s\n", pam_strerror(pamh, res));
        pam_end(pamh, res);
        return 0;
    }

    const char *password;
    int ret;

    // Obtener la contraseña ingresada por el usuario
    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (ret != PAM_SUCCESS) {
        syslog(LOG_ERR, "Error al obtener la contraseña: %s", pam_strerror(pamh, ret));
        printf("Error al obtener la contraseña: %s\n", pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return ret;
    }

    if (password == NULL) {
        syslog(LOG_ERR, "No se ingresó ninguna contraseña.");
        printf("No se ingresó ninguna contraseña.\n");
        pam_end(pamh, PAM_AUTH_ERR);
        return PAM_AUTH_ERR;
    }

    printf("Contraseña ingresada: %s\n", password);

    int opcion;
    do {
        printf("Elija una opción: \n");
        printf("1. Generar nueva semilla\n");
        printf("2. Leer Semilla Actual\n");
        printf("3. Salir\n");
        if (scanf("%d", &opcion) != 1) {
            printf("Entrada inválida\n");
            while (getchar() != '\n'); // Limpiar el buffer de entrada
            continue;
        }
        switch (opcion) {
            case 1:
                nueva_semilla();
                break;
            case 2:
                leer_semilla();
                break;
            case 3:
                break;
            default:
                printf("Opción inválida\n");
                break;
        }
    } while (opcion != 3);

    pam_end(pamh, PAM_SUCCESS);
    closelog();
    return 0;
}