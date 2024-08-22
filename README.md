Instrucciones para la instalacion del modulo pam de autenticacion ssh en 2 pasos:

Modificar el archivo "/etc/pam.d/sshd" agregando la siguiente linea:

"auth	required	pam_auth_casero.so"

justo debajo de las lineas:
# Standard Un*x authentication.
@include common-auth

Modificar el archivo "/etc/ssh/sshd_config", en particular asegurarse de que las configuraciones:

-UsePAM
-ChallengeResponseAuthentication

esten descomentadas y seteadas en "yes", y la configuracion

-PasswordAuthentication

este descomentada y seteada en "no".

En una consola ingresar los siguientes comandos:
1. git clone https://github.com/DarioTourn/auth-casero.git
2. cd auth-casero
3. sudo make

Para que los cambios tomen efecto se debe reiniciar el equipo o reiniciar el proceso ssh del sistema con el siguiente comando:

"sudo systemctl restart ssh"

INSTRUCCIONES DE USO

para generar o leer una seed se debera ejecutar el comando:

"generador-seed"

en una consola, esta aplicacion ofrece al usuario la opcion de crear o leer su seed,
en caso de no estar seteada la seed no se podra hacer ssh al usuario.

Una vez seteada la seed, la aplicacion le mostrara al usuario esta seed y el usuario debera ingresarla en su aplicacion de
google authenticator, una vez hecho esto el sistema de authenticacion estara configurado para futuras conexiones ssh a ese usuario.
