<?php 
/**
 * Clase para el manejo de tokens CSRF.
 */
class Token {
    /**
     * Método para verificar y/o iniciar sesión si no existe.
     */
    private static function checkSession() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Método para crear un token CSRF seguro.
     * 
     * @param string $name Nombre asignado al token
     * @return mixed Token creado o false si ya existe un token con ese nombre
     */
    public static function create($name) {
        self::checkSession();
        if (isset($_SESSION[$name])) {
            return false;
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION[$name] = $token;
        $_SESSION[$name . '_time'] = time();
        return $token;
    }

    /**
     * Método para eliminar un token existente.
     * 
     * @param string $name Nombre del token a eliminar
     * @return bool True si se eliminó, false si el token no existe
     */
    public static function delete($name) {
        self::checkSession();
        if (!isset($_SESSION[$name])) {
            return false;
        }

        unset($_SESSION[$name]);
        unset($_SESSION[$name . '_time']);
        return true;
    }

    /**
     * Método para procesar y validar un token enviado.
     * 
     * @param string $token Token enviado para validación
     * @param string $name Nombre del token a validar
     * @return bool True si los tokens coinciden, false en caso contrario
     */
    public static function process($token, $name) {
        self::checkSession();
        if (!isset($_SESSION[$name]) || $token !== $_SESSION[$name]) {
            return false;
        }

        self::delete($name);
        return true;
    }

    /**
     * Método para procesar y validar un token enviado con tiempo límite.
     * 
     * @param string $token Token enviado para validación
     * @param string $name Nombre del token a validar
     * @param int $time Tiempo en segundos desde la creación del token
     * @return bool True si los tokens coinciden y el tiempo no ha expirado, false en caso contrario
     */
    public static function processTime($token, $name, $time) {
        self::checkSession();
        if (!isset($_SESSION[$name]) || $token !== $_SESSION[$name]) {
            return false;
        }

        if ((time() - $_SESSION[$name . '_time']) > $time) {
            return false;
        }

        self::delete($name);
        return true;
    }
}
?>