#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stddef.h>
#include <cotp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <pwd.h>
#define ARCHIVO_SEMILLA ".seed_auth_casero"

/* Función para leer la semilla de autenticación de un archivo.
 Retorna la semilla leída o NULL en caso de error.
 La semilla debe tener 32 caracteres. El archivo debe estar en el directorio home del usuario, 
 y llamarse '.seed_auth_casero'.
 El archivo debe contener la semilla en la primera línea.
*/
const char *leer_semilla_de_archivo(const char *dir_home) 
{
    static char semilla[33]; // 32 caracteres + 1 para el terminador nulo
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta); // debug

    FILE *archivo = fopen(ruta, "r");

    if (archivo == NULL)
    {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        return NULL; // Error al abrir el archivo
    }

    if (fgets(semilla, sizeof(semilla), archivo) == NULL)
    {
        fclose(archivo);
        syslog(LOG_ERR, "Error al leer la semilla de autenticación");
        return NULL; // Error al leer la semilla
    }

    fclose(archivo);

    // Eliminar el salto de línea al final de la semilla
    int largo = strlen(semilla);
    if (largo > 0 && semilla[largo - 1] == '\n')
    {
        semilla[largo - 1] = '\0';
    }

    return semilla;
}

int chequear_totp(const char *semilla, const char *totp_usuario) 
{
    // Generar el TOTP con la semilla y el tiempo actual y comparar con el ingresado por el usuario
    char *totp_generado;
    cotp_error_t error;

    totp_generado = get_totp(semilla, 6, 30, SHA1, &error);

    if (totp_generado == NULL) 
    {
        syslog(LOG_ERR, "Error al generar el TOTP");
        return 0;
    }
    
    int resultado = strcmp(totp_generado, totp_usuario) == 0;
    free(totp_generado); // Asegúrate de liberar la memoria

    return resultado;
}

bool verificar_usado(const char *totp_usuario, const char *dir_home){
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ".tokens_usados.txt");
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta); // debug
    FILE *tokens_usados = fopen(ruta, "r");
    if (tokens_usados == NULL) {
        return false; // Si no se puede abrir el archivo, asumimos que el token no ha sido usado
    }

    char token[7];
    while(fgets(token, sizeof(token), tokens_usados) != NULL){
        // Eliminar el salto de línea al final del token
        int largo = strlen(token);
        if (largo > 0 && token[largo - 1] == '\n') {
            token[largo - 1] = '\0';
        }
        if(strcmp(token, totp_usuario) == 0){
            fclose(tokens_usados);
            return true;
        }
    }
    fclose(tokens_usados);
    return false;
}

void agregar_token_usado(const char *totp_usuario, const char *dir_home){
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ".tokens_usados.txt");
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta); // debug
    FILE *tokens_usados = fopen(ruta, "a");
    if (tokens_usados != NULL) {
        fprintf(tokens_usados, "%s\n", totp_usuario);
        fclose(tokens_usados);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    struct passwd *pw;
    int retorno;
    char *totp_usuario = NULL;

    // Inicio el log
    openlog("pam_aut_casero", LOG_PID | LOG_CONS, LOG_AUTH);

    // Obtener el nombre de usuario
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        syslog(LOG_ERR, "No se pudo obtener el nombre de usuario");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener el nombre de usuario
    }

    // Obtener la estructura passwd del usuario
    pw = getpwnam(user);
    if (pw == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la información del usuario");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener la información del usuario
    }
    const char *dir_home = pw->pw_dir;

    // Solicitar el código TOTP al usuario
    retorno = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &totp_usuario, "Ingrese el código TOTP: ");
    if (retorno != PAM_SUCCESS || totp_usuario == NULL) {
        syslog(LOG_ERR, "Error al obtener el código TOTP del usuario: %d", retorno);
        closelog();
        free(totp_usuario);
        return PAM_AUTH_ERR;
    }

    // Verificar si el token ya ha sido usado
    if (verificar_usado(totp_usuario, dir_home)) {
        syslog(LOG_ERR, "El token ya fue usado");
        closelog();
        free(totp_usuario);
        return PAM_AUTH_ERR;
    }

    // Leer la semilla de autenticación del archivo
    const char *semilla = leer_semilla_de_archivo(dir_home);
    if (semilla == NULL) {
        syslog(LOG_ERR, "No se pudo leer la semilla de autenticación");
        closelog();
        free(totp_usuario);
        return PAM_AUTH_ERR;
    }

    // Verificar el código TOTP
    if (chequear_totp(semilla, totp_usuario)) {
        syslog(LOG_INFO, "TOTP válido, acceso permitido");
        agregar_token_usado(totp_usuario, dir_home);
        free(totp_usuario);
        closelog();
        return PAM_SUCCESS; // TOTP es válido
    } else {
        syslog(LOG_INFO, "TOTP inválido, acceso denegado");
        free(totp_usuario);
        closelog();
        return PAM_AUTH_ERR; // TOTP inválido
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}