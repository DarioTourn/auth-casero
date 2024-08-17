#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <cotp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);