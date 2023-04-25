<?php

namespace Security;

/**
 * Clase para el manejo de la base de datos.
 */
class Database {
    private $host; // Contiene el nombre del host de la base de datos
    private $db_name; // Contiene el nombre de la base de datos
    private $username; // Contiene el nombre de usuario para la conexión a la base de datos
    private $password; // Contiene la contraseña para la conexión a la base de datos
    public $conn; // Contiene el objeto de conexión PDO
    public $exception; // Contiene la excepción en caso de error

    /**
     * Constructor de la clase.
     * 
     * @param string $host Host de la base de datos
     * @param string $db_name Nombre de la base de datos
     * @param string $username Nombre de usuario de la base de datos
     * @param string $password Contraseña de la base de datos
     * @return bool Resultado de la conexión
     */
    public function __construct($host, $db_name, $username, $password) {
        $this->host = $host;
        $this->db_name = $db_name;
        $this->username = $username;
        $this->password = $password;
        return $this->connect();
    }

    /**
     * Método para conectar a la base de datos.
     * 
     * @return bool Resultado de la conexión
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
     * Método para ejecutar una consulta SQL con parámetros opcionales.
     * 
     * @param string $sql Consulta SQL
     * @param array $params Parámetros opcionales
     * @return mixed Resultado de la consulta o false en caso de error
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
     * Método alternativo para ejecutar una consulta SQL y devolver un único resultado.
     * 
     * @param string $sql Consulta SQL
     * @param array $params Parámetros opcionales
     * @return mixed Resultado de la consulta o false en caso de error
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
     * Método alternativo para ejecutar una consulta SQL y devolver los resultados como objetos.
     * 
     * @param string $sql Consulta SQL
     * @param array $params Parámetros opcionales
     * @return mixed Resultado de la consulta o false en caso de error
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
     * Método alternativo para ejecutar una consulta SQL y devolver los resultados como una matriz numerada.
     * 
     * @param string $sql Consulta SQL
     * @param array $params Parámetros opcionales
     * @return mixed Resultado de la consulta o false en caso de error
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
     * Método alternativo para ejecutar una consulta SQL y devolver los resultados como una matriz tanto asociativa como numerada.
     * 
     * @param string $sql Consulta SQL
     * @param array $params Parámetros opcionales
     * @return mixed Resultado de la consulta o false en caso de error
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
 * Clase para el manejo y verificación de datos.
 */
class Sanitize {
    // Constantes para indicadores de verificación
    const PHONE = 'phone';
    const EMAIL = 'email';
    const PASSWORD_STRONG = 'password_strong';
    const IP = 'ip';
    const ADDRESS = 'address';

    /**
     * Método para procesar un arreglo de datos y evitar ataques XSS.
     * 
     * @param array $data Arreglo de datos a procesar
     * @return array Arreglo de datos procesados
     */
    public static function scope($data) {
        $sanitizedData = [];
        foreach ($data as $key => $value) {
            $sanitizedData[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
        return $sanitizedData;
    }

    /**
     * Método para eliminar caracteres especiales de una variable.
     * Admite todos los alfabetos de todos los idiomas.
     * 
     * @param string $value Variable a sanitizar
     * @return string Variable sanitizada
     */
    public static function sanitize($value) {
        return filter_var($value, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);
    }

    /**
     * Método para verificar un valor según un indicador específico.
     * 
     * @param string $value Valor a verificar
     * @param string $indicator Indicador para especificar qué se desea verificar
     * @return bool True si es válido, false en caso contrario
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

    // Funciones de validación para cada indicador

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


/**
 * Clase para el manejo de solicitudes Ajax.
 */
class Ajax {
    /**
     * Método para verificar el tipo de consulta y establecer el tipo de contenido.
     * 
     * @param string $requestType Tipo de consulta (GET o POST)
     * @param string $contentType Tipo de contenido a mostrar
     * @return bool True si la consulta es válida y se estableció el tipo de contenido, false en caso contrario
     */
    public static function ajax_start($requestType, $contentType) {
        if ($_SERVER['REQUEST_METHOD'] !== strtoupper($requestType) || !self::is_same_origin()) {
            return false;
        }

        header('Content-Type: application/' . $contentType);
        return true;
    }

    /**
     * Método para verificar si la consulta se realiza desde el mismo servidor.
     * 
     * @return bool True si la consulta se realiza desde el mismo servidor, false en caso contrario
     */
    private static function is_same_origin() {
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : $_SERVER['HTTP_HOST'];
        return $origin === $_SERVER['HTTP_HOST'];
    }

    /**
     * Método para devolver un error 400 en la respuesta Ajax.
     */
    public static function ajax_error() {
        http_response_code(400);
    }

    /**
     * Método para devolver un éxito 200 en la respuesta Ajax.
     */
    public static function ajax_success() {
        http_response_code(200);
    }

    /**
     * Método para verificar un token esperado en la consulta Ajax.
     * 
     * @return bool True si el token es válido, false en caso contrario o si la clase Token no está disponible
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

// Clase para la generación de reportes de errores
class Report {
    /**
     * Maneja una excepción, envía al usuario a una página segura y genera un reporte de error si es necesario.
     *
     * @param Exception $exception La excepción a manejar
     * @param string $safePage La URL de la página segura a la que se enviará al usuario
     * @param string $errorFolder La ruta de la carpeta donde se guardarán los reportes de error
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
