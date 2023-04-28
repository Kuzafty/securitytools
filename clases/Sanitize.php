<?php
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
?>