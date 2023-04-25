<?php
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