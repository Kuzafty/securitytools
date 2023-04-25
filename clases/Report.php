<?php
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