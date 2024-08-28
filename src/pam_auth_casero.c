#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stddef.h>
#include <cotp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <pwd.h>
#include <gcrypt.h>

#define ARCHIVO_SEMILLA ".seed_auth_casero"
#define SEED_SIZE 32 // Cambiar el tamaño del seed a 32 bytes
#define IV_SIZE 16
#define SALT_SIZE 16
#define ITERATIONS 10000
#define KEY_SIZE 32

void handle_error(const char *msg, gcry_error_t err) {
    syslog(LOG_ERR, "%s: %s", msg, gpg_strerror(err));
    exit(EXIT_FAILURE);
}

// Declarar gcry_threads_pthread
GCRY_THREAD_OPTION_PTHREAD_IMPL;

void init_gcrypt() {
    if (!gcry_check_version(GCRYPT_VERSION)) {
        syslog(LOG_ERR, "libgcrypt version mismatch");
        exit(EXIT_FAILURE);
    }
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    if (gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_SIZE, ITERATIONS, KEY_SIZE, key) != 0) {
        syslog(LOG_ERR, "Key derivation failed");
        exit(EXIT_FAILURE);
    }
}

void derive_salt_iv(const char *password, unsigned char *salt, unsigned char *iv) {
    unsigned char hash[32]; // SHA-256 produces a 32-byte hash

    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, password, strlen(password));

    // Use the first 16 bytes of the hash as the salt
    memcpy(salt, hash, SALT_SIZE);

    // Use the next 16 bytes of the hash as the IV
    memcpy(iv, hash + SALT_SIZE, IV_SIZE);
}

void decrypt_seed(const char *password, const unsigned char *encrypted_seed, unsigned char *seed) {
    unsigned char key[KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];

    derive_salt_iv(password, salt, iv);
    derive_key(password, salt, key);

    gcry_cipher_hd_t handle;
    gcry_error_t err;

    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        handle_error("Failed to open cipher", err);
    }

    err = gcry_cipher_setkey(handle, key, KEY_SIZE);
    if (err) {
        handle_error("Failed to set key", err);
    }

    err = gcry_cipher_setiv(handle, iv, IV_SIZE);
    if (err) {
        handle_error("Failed to set IV", err);
    }

    err = gcry_cipher_decrypt(handle, seed, SEED_SIZE, encrypted_seed, SEED_SIZE);
    if (err) {
        handle_error("Decryption failed", err);
    }

    gcry_cipher_close(handle);
}

const char *leer_semilla_de_archivo(const char *dir_home, const char *password) {
    static unsigned char semilla[SEED_SIZE + 1]; // 32 bytes + 1 for null terminator
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta); // debug

    FILE *archivo = fopen(ruta, "rb");
    if (archivo == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        return NULL; // Error al abrir el archivo
    }

    unsigned char semilla_encriptada[SEED_SIZE];
    if (fread(semilla_encriptada, 1, SEED_SIZE, archivo) != SEED_SIZE) {
        syslog(LOG_ERR, "Error al leer la semilla de autenticación");
        fclose(archivo);
        return NULL; // Error al leer la semilla
    }

    fclose(archivo);

    // Desencriptar la semilla
    decrypt_seed(password, semilla_encriptada, semilla);
    semilla[SEED_SIZE] = '\0'; // Null-terminate the string

    return (const char *)semilla;
}

int chequear_totp(const char *semilla, const char *totp_usuario) {
    // Generar el TOTP con la semilla y el tiempo actual y comparar con el ingresado por el usuario
    char *totp_generado;
    cotp_error_t error;

    totp_generado = get_totp(semilla, 6, 30, SHA1, &error);

    if (totp_generado == NULL) {
        syslog(LOG_ERR, "Error al generar el TOTP");
        return 0;
    }

    int resultado = strcmp(totp_generado, totp_usuario) == 0;
    free(totp_generado); // Asegúrate de liberar la memoria

    return resultado;
}

bool verificar_usado(const char *totp_usuario, const char *dir_home) {
    char ruta[512];

    // Se construye la ruta del archivo de autenticación
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ".tokens_usados.txt");
    syslog(LOG_INFO, "Ruta para buscar la semilla: %s", ruta); // debug
    FILE *tokens_usados = fopen(ruta, "r");
    if (tokens_usados == NULL) {
        return false; // Si no se puede abrir el archivo, asumimos que el token no ha sido usado
    }

    char token[7];
    while (fgets(token, sizeof(token), tokens_usados) != NULL) {
        // Eliminar el salto de línea al final del token
        int largo = strlen(token);
        if (largo > 0 && token[largo - 1] == '\n') {
            token[largo - 1] = '\0';
        }
        if (strcmp(token, totp_usuario) == 0) {
            fclose(tokens_usados);
            return true;
        }
    }
    fclose(tokens_usados);
    return false;
}

void agregar_token_usado(const char *totp_usuario, const char *dir_home) {
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
    const char *password;

    // Inicio el log
    openlog("pam_aut_casero", LOG_PID | LOG_CONS, LOG_AUTH);
    init_gcrypt();

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

    // Obtener la contraseña del usuario
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS || password == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la contraseña del usuario");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener la contraseña del usuario
    }

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
    const char *semilla = leer_semilla_de_archivo(dir_home, password);
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