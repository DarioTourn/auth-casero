#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    struct passwd *pw;

    openlog("pam_encriptador_seed_lectura", LOG_PID | LOG_CONS, LOG_AUTH);

    // Obtener el nombre de usuario
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        syslog(LOG_ERR, "No se pudo obtener el nombre de usuario");
        printf("No se pudo obtener el nombre de usuario\n");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener el nombre de usuario
    }

    // Obtener la información del usuario
    pw = getpwnam(user);
    if (pw == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la información del usuario");
        printf("No se pudo obtener la información del usuario\n");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener la información del usuario
    }

    // Obtener el directorio home del usuario
    const char *dir_home = pw->pw_dir;
    if (dir_home == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la ruta del archivo");
        printf("No se pudo obtener la ruta del archivo\n");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener la ruta del archivo
    }

    // Construir la ruta del archivo de semilla
    char semilla[33];
    char ruta[512];
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);

    // Abrir el archivo de semilla
    FILE *archivo = fopen(ruta, "r");
    if (archivo == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        printf("Error al abrir el archivo de semilla de autenticación\n");
        closelog();
        return PAM_AUTH_ERR; // Error al abrir el archivo de semilla de autenticación
    }

    // Leer la semilla del archivo
    if (fgets(semilla, sizeof(semilla), archivo) == NULL) {
        syslog(LOG_ERR, "Error al leer la semilla de autenticación");
        printf("Error al leer la semilla de autenticación\n");
        fclose(archivo);
        closelog();
        return PAM_AUTH_ERR; // Error al leer la semilla de autenticación
    }
    printf("Semilla: %s\n", semilla);

    //DEBO AGREGAR EL LECTOR ACA PARA QUE DESENCRIPTE LA SEMILLA


    // Cerrar el archivo
    fclose(archivo);

    // Aquí puedes agregar el código para usar la semilla leída

    closelog();
    return PAM_SUCCESS; // Autenticación exitosa
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}