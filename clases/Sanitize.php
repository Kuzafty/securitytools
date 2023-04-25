<?php
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
?>