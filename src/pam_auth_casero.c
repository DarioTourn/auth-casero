#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <cotp.h>
//#include "/home/dario-tourn/Descargas/libcotp-2.0.1/src/cotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"

const char* leer_semilla_de_archivo() {
    
    static char semilla[256];
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", getenv("HOME"), ARCHIVO_SEMILLA);
    
    FILE *archivo = fopen(ruta, "r");

    if (archivo == NULL) {
        return NULL; // Error al abrir el archivo
    }

    if (fgets(semilla, sizeof(semilla), archivo) == NULL) {
        fclose(archivo);
        return NULL; // Error al leer el código
    }

    fclose(archivo);

    // Eliminar el salto de línea al final de la seed
    int largo = strlen(semilla);

    //Si el largo es mayor a 0 y el último caracter es un salto de línea, se elimina
    if (largo > 0 && semilla[largo - 1] == '\n') {
        semilla[largo - 1] = '\0';
    }

    return semilla;
}

int chequear_totp(const char *semilla, const char *totp_usuario) {
    // Generar el TOTP con la semilla y el tiempo actual y comparar con el ingresado por el usuario
    char *totp_generado;
    cotp_error_t error;

    totp_generado = get_totp(semilla, 6, 30, SHA1, &error);

    return strcmp(totp_generado, totp_usuario) == 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   int retorno;
   
   // Obtener el código TOTP ingresado por el usuario
   const char *totp_usuario;
   retorno = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&totp_usuario);
   if (retorno != PAM_SUCCESS || totp_usuario == NULL) //(No se aceptan valores nulos)
   {
       return PAM_AUTH_ERR;
   }


    // Leer la semilla de autenticación del archivo
   const char *semilla = leer_semilla_de_archivo();


    // Verificar el código TOTP
   if (chequear_totp(semilla, totp_usuario))
   {
       return PAM_SUCCESS; // TOTP es válido
   }
   else
   {
       return PAM_AUTH_ERR; // TOTP inválido
   }
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}



