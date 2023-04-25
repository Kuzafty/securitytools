<?php
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
?>