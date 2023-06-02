<?php

namespace Security;

/**
 * Class for database handling.
 */
class Database {
    private $host; // It contains the name of the database host.
    private $db_name; // It contains the name of the database.
    private $username; // It contains the username for the database connection.
    private $password; // It contains the password for the database connection.
    public $conn; // It contains the \PDO connection object.
    public $exception; // It contains the exception in case of an error.

    /**
    * Class constructor.
    *
    * @param string $host Database host
    * @param string $db_name Database name
    * @param string $username Database username
    * @param string $password Database password
    * @return bool Connection result 
    */
    public function __construct($host, $db_name, $username, $password) {
        $this->host = $host;
        $this->db_name = $db_name;
        $this->username = $username;
        $this->password = $password;
        return $this->connect();
    }

    /**
    * Method to connect to the database.
    *
    * @return bool Connection result
    */
    private function connect() {
        $this->conn = null;
        try {
            $this->conn = new \PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            return true;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

    /**
     * Method to execute an SQL query with optional parameters.
     * 
     * @param string $sql SQL query
     * @param array $params Optional parameters
     * @return mixed Query result or false in case of error
     */
    public function query($sql, $params = array()) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            return $result;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

    /**
     * Alternative method to execute an SQL query and return a single result.
     * 
     * @param string $sql SQL query
     * @param array $params Optional parameters
     * @return mixed Query result or false in case of error
     */
    public function querySingle($sql, $params = array()) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            return $result;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

    /**
     * Alternative method to execute an SQL query and return results as objects.
     * 
     * @param string $sql SQL query
     * @param array $params Optional parameters
     * @return mixed Query result or false in case of error
     */
    public function queryFetchObject($sql, $params = array()) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetchAll(\PDO::FETCH_OBJ);
            return $result;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

    /**
     * Alternative method to execute an SQL query and return results as a numbered array.
     * 
     * @param string $sql SQL query
     * @param array $params Optional parameters
     * @return mixed Query result or false in case of error
     */
    public function queryFetchNum($sql, $params = array()) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetchAll(\PDO::FETCH_NUM);
            return $result;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

    /**
     * Alternative method to execute an SQL query and return results as both an associative and numbered array.
     * 
     * @param string $sql SQL query
     * @param array $params Optional parameters
     * @return mixed Query result or false in case of error
     */
    public function queryFetchBoth($sql, $params = array()) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetchAll(\PDO::FETCH_BOTH);
            return $result;
        } catch (\PDOException $e) {
            $this->exception = $e;
            return false;
        }
    }

}


/**
 * Class for data handling and verification.
 */
class Sanitize {
    // Constants for verification indicators.
    const PHONE = 'phone';
    const EMAIL = 'email';
    const PASSWORD_STRONG = 'password_strong';
    const IP = 'ip';
    const ADDRESS = 'address';

    /**
     * Method to process an array of data and prevent XSS attacks.
     * 
     * @param array $data Array of data to process
     * @return array Processed array of data
     */
    public static function scope($data) {
        $sanitizedData = [];
        foreach ($data as $key => $value) {
            $sanitizedData[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
        return $sanitizedData;
    }

    /**
     * Method to remove special characters from a variable.
     * Supports all alphabets from all languages.
     * 
     * @param string $value Variable to sanitize
     * @return string Sanitized variable
     */
    public static function sanitize($value) {
        $input = trim($value);
        $input = preg_replace('/[^\p{L}\p{N}\p{M}\p{Zs}]/u', '', $input);
        $input = preg_replace('/[\p{Zs}]/u', ' ', $input);
        return $input;
    }

    /**
     * Method to verify a value according to a specific indicator.
     * 
     * @param string $value Value to verify
     * @param string $indicator Indicator to specify what is being verified
     * @return bool True if valid, false otherwise
     */
    public static function check($value, $indicator) {
        switch ($indicator) {
            case self::PHONE:
                return self::validatePhone($value);

            case self::EMAIL:
                return self::validateEmail($value);

            case self::PASSWORD_STRONG:
                return self::validatePasswordStrength($value);

            case self::IP:
                return self::validateIP($value);

            case self::ADDRESS:
                return self::validateAddress($value);

            default:
                return false;
        }
    }

    // Validation functions for each indicator.

    private static function validatePhone($value) {
        return preg_match('/^\+?\d{9,15}$/', $value);
    }

    private static function validateEmail($value) {
        return filter_var($value, FILTER_VALIDATE_EMAIL);
    }

    private static function validatePasswordStrength($value) {
        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $value);
    }

    private static function validateIP($value) {
        return filter_var($value, FILTER_VALIDATE_IP);
    }

    private static function validateAddress($value) {
        return preg_match('/^[a-zA-Z0-9\s\.,]+$/u', $value);
    }
}


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
     * 
     * Method to get a CSRF token value
     * 
     * @param string $name Name assigned to the token
     * @return mixed Token value or false if the token doesn't exist
     */
    public static function get($name){
        self::checkSession();
        if (!isset($_SESSION[$name])) {
            return false;
        }
        return $_SESSION[$name];
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

        if(isset($_SESSION[$name . '_timer'])){
            unset($_SESSION[$name . '_timer']);
        }

        if(isset($_SESSION[$name . '_count'])){
            unset($_SESSION[$name . '_count']);
        }

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

    /**
     * Method to process and validate a sent token with time aument
     * 
     * @param string $token Token sent for validation
     * @param string $name Name of the token to validate
     * @param int $time Time in seconds since the token was created
     * @param int $nUp The number of times to add second to $time
     * @param int $threshold Seconds to reset aument
     * @return bool true if token is valid, false otherwise
     */
    public static function processLimited($token, $name, $time, $nUp, $threshold){
        self::checkSession();
        if (!isset($_SESSION[$name]) || $token !== $_SESSION[$name]) {
            return false;
        }

        if (!isset($_SESSION[$name . '_count']) || !isset($_SESSION[$name . '_timer'])){
            $_SESSION[$name . '_count'] = 0;
            $_SESSION[$name . '_timer'] = 0;
        }

        $_SESSION[$name . '_count']++;

        if($_SESSION[$name . '_count'] == $nUp){
            $_SESSION[$name . '_timer']++;
            $_SESSION[$name . '_count'] = 0;
        }

        if ((time() - $_SESSION[$name . '_time']) < ($time+$_SESSION[$name . '_timer'])) {
            return false;
        }

        if((time() - $_SESSION[$name . '_time']) > $threshold){
            $_SESSION[$name . '_count'] = 0;
            $_SESSION[$name . '_timer'] = 0;
        }

        return self::unsetToken($name);
        
    }

    /**
     * Method to solve processLimited new tokens
     * 
     * @param string $name token to reset
     * @return bool true if token was deleted
     */
    public static function unsetToken($name) {
        self::checkSession();
        if (!isset($_SESSION[$name])) {
            return false;
        }

        unset($_SESSION[$name]);
        unset($_SESSION[$name . '_time']);

        return true;
    }

}


/**
 * Class for handling Ajax requests.
 */
class Ajax {
    /**
     * Method to verify the query type and set the content type.
     * 
     * @param string $requestType Query type (GET or POST)
     * @param string $contentType Type of content to display
     * @return bool True if the query is valid and content type was set, false otherwise
     */
    public static function ajax_start($requestType, $contentType) {
        if ($_SERVER['REQUEST_METHOD'] !== strtoupper($requestType) || !self::is_same_origin()) {
            return false;
        }

        header('Content-Type: application/' . $contentType);
        return true;
    }

    /**
     * Method to verify if the query is being made from the same server.
     * 
     * @return bool True if the query is being made from the same server, false otherwise
     */
    private static function is_same_origin() {
        if (!isset($_SERVER['HTTP_REFERER'])) {
            // Si la petición no incluye un referer, entonces no se puede verificar si es del mismo origen
            return false;
        }
        
        // Se obtiene el origen de la petición
        $referer = parse_url($_SERVER['HTTP_REFERER']);
        $referer_origin = $referer['scheme'] . '://' . $referer['host'];
        
        // Se obtiene el origen del servidor que recibe la petición
        $server_origin = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://{$_SERVER['HTTP_HOST']}";
        
        // Se compara el origen de la petición con el origen del servidor que recibe la petición
        return ($referer_origin === $server_origin);
    }
    

    /**
     * Method to return a 400 error in the Ajax response.
     */
    public static function ajax_error() {
        http_response_code(400);
    }

    /**
     * Method to return a 200 success in the Ajax response.
     */
    public static function ajax_success() {
        http_response_code(200);
    }

    /**
     * Sends an HTTP 200 (success) or 400 (error) response based on the value of a boolean expression.
     *
     * @param bool $expression Boolean expression to determine the HTTP result.
     * @return void
     */
    public static function ajax_value($expression) {
        if ($expression) {
            self::ajax_success();
        } else {
            self::ajax_error();
        }
    }

    /**
     * Verifies the validity of a CSRF token sent in an HTTP request.
     *
     * @param string $token_name Name of the token to verify.
     * @param string $source HTTP request method where to look for the token (post, get, cookie, request). Default is 'post'.
     * @param int|null $time Time in seconds to check if it has passed since the creation of the token. Default is null.
     * @return bool Returns true if the token is valid, false otherwise.
     */
    public static function ajax_token($token_name, $source = 'post', $time = null) {

        switch (strtolower($source)) {
            case 'post':
                $token_value = isset($_POST[$token_name]) ? $_POST[$token_name] : null;
                break;
            case 'get':
                $token_value = isset($_GET[$token_name]) ? $_GET[$token_name] : null;
                break;
            case 'cookie':
                $token_value = isset($_COOKIE[$token_name]) ? $_COOKIE[$token_name] : null;
                break;
            case 'request':
                $token_value = isset($_REQUEST[$token_name]) ? $_REQUEST[$token_name] : null;
                break;
            default:
                return false;
        }

        if ($token_value === null) {
            return false;
        }

        if ($time !== null) {
            return Token::processTime($token_value, $token_name, $time);
        } else {
            return Token::process($token_value, $token_name);
        }
    }

}

/**
 * Clase para el manejo de cookies.
 */
class Cookie {

    /**
     * Crea una cookie.
     *
     * @param string $name Nombre de la cookie.
     * @param mixed $value Valor de la cookie.
     * @param string|null $expiration Fecha de expiración de la cookie, en formato Día/Mes/Año o Horas/Minutos/Segundos.
     * @param string|null $format Formato del parámetro de expiración, 'date' para Día/Mes/Año o 'time' para Horas/Minutos/Segundos.
     * @param bool $omit Omite la limpieza y escape de caracteres.
     * @param bool $secure Almacena un hash de la cookie en una variable de sesión.
     * @return bool Returns false if something went wrong
     */
    public static function create($name, $value, $secure = true, $expiration = null, $format = 'time', $omit = false) {
        $expires = 0;
    
        if ($expiration !== null) {
            if ($format === 'date') {
                $date = \DateTime::createFromFormat('d/m/Y', $expiration);
                if ($date === false) {
                    return false;
                }
                $expires = $date->getTimestamp();
            } elseif ($format === 'time') {
                $time = \DateTime::createFromFormat('H:i:s', $expiration);
                if ($time === false) {
                    return false;
                }
                $expires = time() + $time->getTimestamp() - $time->setTime(0, 0, 0)->getTimestamp();
            } else {
                return false;
            }
        }
    
        if (!$omit) {
            $name = Sanitize::sanitize(Sanitize::scope([$name]))[0];
            $value = Sanitize::sanitize(Sanitize::scope([$value]))[0];
        }
    
        if (!setcookie($name, $value, $expires)) {
            return false;
        }
    
        if ($secure) {
            if (!isset($_SESSION)) {
                session_start();
            }
            $_SESSION[$name . '_hash'] = hash('sha256', $value);
        }

        return true;

    }    

    /**
     * Obtiene el valor de una cookie.
     *
     * @param string $name Nombre de la cookie.
     * @return mixed Valor de la cookie, o null si no existe.
     */
    public static function get($name) {
        return isset($_COOKIE[$name]) ? $_COOKIE[$name] : null;
    }

    /**
     * Elimina una cookie.
     *
     * @param string $name Nombre de la cookie.
     * @param bool $secure Elimina el hash de la cookie en la variable de sesión.
     * @return bool True if cookie was deleted, false otherwise.
     */
    public static function delete($name, $secure = true) {
        if (isset($_COOKIE[$name])) {
            if (!setcookie($name, '', time() - 3600)) {
                return false;
            }
            if ($secure) {
                if (isset($_SESSION[$name . '_hash'])) {
                    unset($_SESSION[$name . '_hash']);
                }
            }
        } else {
            return false;
        }
    }
}

/**
 * Clase para el manejo de sesiones
 */
class loged {
    /**
     * Previene el acceso de usuarios no autorizados a zonas especificas
     * 
     * @param string $preventPage Zona de información
     * @return null
     */
    public static function prevent($preventPage){
        if(session_status() === PHP_SESSION_NONE){
            header('Location: '.$preventPage);
            exit();
        }
    }

    /**
     * Previene el acceso a usuarios no autorizados a zonas especificas.
     * Adicionalmente comprueba la existencia de una variable
     * 
     * @param string $preventPage Zona de información
     * @param string $name Nombre de la variable
     * @return null
     */
    public static function preventExist($preventPage, $name){
        self::prevent($preventPage);
        if(!isset($_SESSION[$name])){
            header('Location: '.$preventPage);
            exit();
        }
    }

    /**
     * Previene el acceso a usuarios no autorizados a zonas especificas.
     * Adicionalmente comprueba la existencia de algun dato.
     * 
     * @param string $preventPage Zona de información
     * @param string $name Nombre de la variable
     * @param string $value Valor esperado
     * @return null
     */
    public static function preventCheck($preventPage, $name, $value){
        self::preventExist($preventPage, $name);
        if($_SESSION[$name] != $value){
            header('Location: '.$preventPage);
            exit();
        }
    }

    /**
     * Previene el acceso a usuarios no autorizados a zonas especificas.
     * Adicionalmente comprueba la existencia de varios datos.
     * 
     * @param string $preventPage Zona de información
     * @param array $names Nombres de las variables
     * @return null
     */
    public static function preventExists($preventPage, $names){
        self::prevent($preventPage);
        foreach($names as $name){
            if(!isset($_SESSION[$name])){
                header('Location: '.$preventPage);
                exit();
            }
        }
    }
}

?>
