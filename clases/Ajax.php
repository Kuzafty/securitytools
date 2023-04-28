<?php
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
?>