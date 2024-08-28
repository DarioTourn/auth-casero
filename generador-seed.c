#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h> // Necesario para chmod	
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <unistd.h>
#include <pwd.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"

static struct pam_conv conv = {
    misc_conv, /* Conversation function defined in pam_misc.h */
    NULL /* We don't need additional data now*/
};

/*
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
*/

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
    int retval;
    const char *user;
    struct passwd *pw;
    struct pam_conv conv = {
        misc_conv,
        NULL
    };
    openlog("generador-seed", LOG_PID | LOG_CONS, LOG_AUTH);

    // Obtener el nombre del usuario actual
    pw = getpwuid(getuid());
    if (pw == NULL) {
        printf("Error al obtener el nombre de usuario\n");
        return 1;
    }
    user = pw->pw_name;

    int opcion;
    do {
        printf("\n");
        printf("\n");
        printf("Elija una opción: \n");
        printf("1. Generar nueva semilla\n");
        printf("2. Leer Semilla Actual\n");
        printf("3. Salir\n");
        scanf("%d", &opcion);
        switch (opcion) {
            case 1:
                retval = pam_start("generador-seed-pam-escritura", user, &conv, &pamh);
                if (retval != PAM_SUCCESS) {
                    syslog(LOG_ERR, "Error al iniciar PAM: %s", pam_strerror(pamh, retval));
                    printf("Error al iniciar PAM: %s\n", pam_strerror(pamh, retval));
                    closelog();
                    return 1;
                }
                retval = pam_authenticate(pamh, 0);
                if (retval != PAM_SUCCESS) {
                    syslog(LOG_ERR, "Error en la autenticación: %s", pam_strerror(pamh, retval));
                    printf("Error en la autenticación: %s\n", pam_strerror(pamh, retval));
                    pam_end(pamh, retval);
                    closelog();
                    return 1;
                }
                // Aquí puedes agregar el código para generar una nueva semilla
                pam_end(pamh, PAM_SUCCESS);
                break;
            case 2:
                retval = pam_start("generador-seed-pam-lectura", user, &conv, &pamh);
                if (retval != PAM_SUCCESS) {
                    syslog(LOG_ERR, "Error al iniciar PAM: %s", pam_strerror(pamh, retval));
                    printf("Error al iniciar PAM: %s\n", pam_strerror(pamh, retval));
                    closelog();
                    return 1;
                }
                retval = pam_authenticate(pamh, 0);
                if (retval != PAM_SUCCESS) {
                    syslog(LOG_ERR, "Error en la autenticación: %s", pam_strerror(pamh, retval));
                    printf("Error en la autenticación: %s\n", pam_strerror(pamh, retval));
                    pam_end(pamh, retval);
                    closelog();
                    return 1;
                }
                pam_end(pamh, PAM_SUCCESS);
                break;
            case 3:
                break;
            default:
                break;
        }
    } while (opcion != 3);
    closelog();
    return 0;
}