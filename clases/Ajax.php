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
        $http_origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
        $https_origin = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on' ? 'https://' . $_SERVER['HTTP_HOST'] : '';
        $origin = $http_origin ?: $https_origin ?: $_SERVER['HTTP_HOST'];
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
?>