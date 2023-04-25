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
    public $conn; // It contains the PDO connection object.
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
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return true;
        } catch (PDOException $e) {
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
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOException $e) {
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
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOException $e) {
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
            $result = $stmt->fetchAll(PDO::FETCH_OBJ);
            return $result;
        } catch (PDOException $e) {
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
            $result = $stmt->fetchAll(PDO::FETCH_NUM);
            return $result;
        } catch (PDOException $e) {
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
            $result = $stmt->fetchAll(PDO::FETCH_BOTH);
            return $result;
        } catch (PDOException $e) {
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
        return filter_var($value, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);
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

        if ((time() - $_SESSION[$name . '_time']) > $time) {
            return false;
        }

        self::delete($name);
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
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : $_SERVER['HTTP_HOST'];
        return $origin === $_SERVER['HTTP_HOST'];
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
     * Method to verify an expected token in the Ajax query.
     * 
     * @return bool True if the token is valid, false otherwise or if the Token class is not available
     */
    public static function ajax_token() {
        if (!class_exists('Token')) {
            return false;
        }

        $tokenName = isset($_REQUEST['token_name']) ? $_REQUEST['token_name'] : null;
        $tokenValue = isset($_REQUEST['token_value']) ? $_REQUEST['token_value'] : null;
        $tokenTime = isset($_REQUEST['token_time']) ? intval($_REQUEST['token_time']) : null;

        if ($tokenName && $tokenValue) {
            if ($tokenTime !== null) {
                return Token::processTime($tokenValue, $tokenName, $tokenTime);
            } else {
                return Token::process($tokenValue, $tokenName);
            }
        }

        return false;
    }

}

// Class for generating error reports.
class Report {
    /**
     * Handles an exception, sends the user to a safe page, and generates an error report if necessary.
     *
     * @param Exception $exception The exception to handle
     * @param string $safePage The URL of the safe page to which the user will be sent
     * @param string $errorFolder The path of the folder where error reports will be saved
     */
    public static function handleException($exception, $safePage, $errorFolder) {
        $errorHash = md5($exception->getMessage() . $exception->getCode() . $exception->getFile() . $exception->getLine());

        if (!file_exists($errorFolder . '/' . $errorHash . '.json')) {
            $errorReport = [
                'message' => $exception->getMessage(),
                'code' => $exception->getCode(),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => $exception->getTrace(),
                'timestamp' => date('Y-m-d H:i:s')
            ];

            file_put_contents($errorFolder . '/' . $errorHash . '.json', json_encode($errorReport));
        }

        header('Location: ' . $safePage);
        exit();
    }
}

?>
