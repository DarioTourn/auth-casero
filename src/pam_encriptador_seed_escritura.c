#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <syslog.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    const char *user;
    struct passwd *pw;
    int retval;
    srand(time(NULL));

    openlog("pam_encriptador_seed_escritura", LOG_PID | LOG_CONS, LOG_AUTH);

    // Obtener el nombre de usuario
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        printf("No se pudo obtener el nombre de usuario\n");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener el nombre de usuario
    }

    pw = getpwnam(user);
    if (pw == NULL) {
        printf("No se pudo obtener la información del usuario\n");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener la información del usuario
    }

    const char *dir_home = pw->pw_dir;

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (retval != PAM_SUCCESS || password == NULL) {
        printf("No se pudo obtener la contraseña.\n");
        closelog();
        return PAM_AUTH_ERR;
    }

    // Crear la semilla
    char semilla[33];
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < 32; ++i) {
        semilla[i] = base32_chars[rand() % 32];
    }
    semilla[32] = '\0'; // Asegurarse de que la cadena esté terminada en nulo

    // Se construye la ruta del archivo de autenticación
    char ruta[512];
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);

    FILE *archivo = fopen(ruta, "w");
    if (archivo == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        closelog();
        return PAM_AUTH_ERR;
    }
    fwrite(semilla, 1, 32, archivo);
    fclose(archivo);

    printf("Su semilla es: %s\n", semilla);
    syslog(LOG_INFO, "Semilla generada con éxito");
    
    closelog();
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}