<?php 
/**
 * Class for CSRF token handling.
 */
class Token {
    /**
     * Method to verify and/or start a session if it does not exist.
     */
    private static function checkSession() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Method to create a secure CSRF token.
     * 
     * @param string $name Name assigned to the token
     * @return mixed Created token or false if a token with that name already exists
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
     * Method to remove an existing token.
     * 
     * @param string $name Name of the token to remove
     * @return bool True if removed, false if token does not exist
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
     * Method to process and validate a sent token.
     * 
     * @param string $token Token sent for validation
     * @param string $name Name of the token to validate
     * @return bool True if tokens match, false otherwise
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
     * Method to process and validate a sent token with time limit.
     * 
     * @param string $token Token sent for validation
     * @param string $name Name of the token to validate
     * @param int $time Time in seconds since the token was created
     * @return bool True if tokens match and time has not expired, false otherwise
     */
    public static function processTime($token, $name, $time) {
        self::checkSession();
        if (!isset($_SESSION[$name]) || $token !== $_SESSION[$name]) {
            return false;
        }

        if ((time() - $_SESSION[$name . '_time']) < $time) {
            return false;
        }   

        self::delete($name);
        return true;
    }
}
?>