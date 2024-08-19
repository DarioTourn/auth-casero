#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <cotp.h>


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{


   const char *usuario;
   int retorno;
   retorno = pam_get_user(pamh, &usuario, "Nombre de usuario: ");
   if (retorno != PAM_SUCCESS)
   {
       return retorno;
   }


   // Obtener el código TOTP ingresado por el usuario
   const char *totp;
   retorno = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&totp);
   if (retorno != PAM_SUCCESS || totp == NULL) //(No se aceptan valores nulos)
   {
       return PAM_AUTH_ERR;
   }


   //INCOMPLETO
   //Acá me falta implementar la funcion esta y ver como hacer para generar y guardar la semilla
   const char *semilla = get_seed_from_file(const char* usuario);


   // Validar el código TOTP
   if (cotp_verify(semilla, totp, NULL, 30))
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



