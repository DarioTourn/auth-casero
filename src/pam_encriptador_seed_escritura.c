#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h> // Incluir la biblioteca para la función rand()
#include <gcrypt.h> // Mantener la inclusión de gcrypt.h

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

void encrypt_seed(const char *password, const unsigned char *seed, unsigned char *encrypted_seed) {
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

    err = gcry_cipher_encrypt(handle, encrypted_seed, SEED_SIZE, seed, SEED_SIZE);
    if (err) {
        handle_error("Encryption failed", err);
    }

    gcry_cipher_close(handle);
}

void generate_random_seed(unsigned char *seed, size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // Base32 charset
    for (size_t i = 0; i < length; i++) {
        seed[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    seed[length] = '\0'; // Null-terminate the string
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    struct passwd *pw;
    const char *password;
    openlog("_seed_escritura", LOG_PID | LOG_CONS, LOG_AUTH);
    init_gcrypt();

    // Inicializar el generador de números aleatorios
    srand(time(NULL));

    // Obtener el nombre de usuario
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        syslog(LOG_ERR, "No se pudo obtener el nombre de usuario");
        closelog();
        return PAM_AUTH_ERR; // Error al obtener el nombre de usuario
    }

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

    // Generar una nueva semilla aleatoria
    unsigned char semilla[SEED_SIZE + 1];
    generate_random_seed(semilla, SEED_SIZE);
    printf("Semilla generada: %s\n", semilla);
    unsigned char semilla_encriptada[SEED_SIZE];

    // Encriptar la semilla
    encrypt_seed(password, semilla, semilla_encriptada);

    // Guardar la semilla encriptada en el archivo
    char ruta[512];
    snprintf(ruta, sizeof(ruta), "%s/%s", dir_home, ARCHIVO_SEMILLA);

    FILE *archivo = fopen(ruta, "wb");
    if (archivo == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo de semilla de autenticación");
        closelog();
        return PAM_AUTH_ERR;
    }

    if (fwrite(semilla_encriptada, 1, SEED_SIZE, archivo) != SEED_SIZE) {
        syslog(LOG_ERR, "Error al escribir la semilla de autenticación");
        fclose(archivo);
        closelog();
        return PAM_AUTH_ERR; // Error al escribir la semilla de autenticación
    }

    // Cerrar el archivo
    fclose(archivo);

    syslog(LOG_INFO, "Semilla encriptada y guardada con éxito");

    closelog();
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}