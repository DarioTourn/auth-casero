#include <stddef.h> // Añadir antes de incluir cotp.h
#include <cotp.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../include/auth-casero.h"
#define PASSWORD "123456"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password = NULL;
    int pam_code;

    // Pedir la contraseña al usuario
    pam_code = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &password, "Ingrese su contraseña (Debugg): ");
    if (pam_code != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Error al solicitar la contraseña: %d", pam_code);
        return PAM_AUTH_ERR;
    }

    // Imprimir la contraseña en el syslog
    pam_syslog(pamh, LOG_DEBUG, "Contraseña ingresada: %s", password);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
