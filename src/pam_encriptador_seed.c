#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h> // Agregado para compatibilidad con getpwnam

#define ARCHIVO_SEMILLA ".seed_auth_casero"

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    struct passwd *pw;
    char *user;
    int retval;


    // Obtener el nombre de usuario
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        printf("No se pudo obtener el nombre de usuario\n");
        return PAM_AUTH_ERR; // Error al obtener el nombre de usuario
    }

    pw = getpwnam(user);
    if (pw == NULL) {
        //syslog(LOG_ERR, "No se pudo obtener la información del usuario");
        //closelog();
        printf("No se pudo obtener la información del usuario\n");
        return PAM_AUTH_ERR; // Error al obtener la información del usuario
    }

    const char *dir_home = pw->pw_dir;

    // Obtener la contraseña del usuario
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (retval != PAM_SUCCESS || password == NULL) {
        //pam_syslog(pamh, LOG_ERR, "No se pudo obtener la contraseña.");
        printf("No se pudo obtener la contraseña.\n");
        return PAM_AUTH_ERR;
    }

    // COMO PRUEBA VOY A ESCRIBIR LA CONTRASEÑA EN UN ARCHIVO
    // ACA IRIA LA PARTE DE ENCRIPTAR


    int encrypted_data_len = strlen(password);
    char ruta[512];
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);
    
    FILE *file = fopen(ruta, "wb");
    if (file) {
        fwrite(password, 1, encrypted_data_len, file);
        fclose(file);
    } else {
        
        printf("No se pudo abrir el archivo de salida.\n");
        
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}
