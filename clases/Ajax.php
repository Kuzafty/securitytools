<?php
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
?>