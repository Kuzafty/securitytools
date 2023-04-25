<?php
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
?>