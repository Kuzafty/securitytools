# SECURITYTOOLS

Este proyecto contiene varias clases de utilidad para mejorar la seguridad en aplicaciones web PHP. Las clases incluidas son:

- Database
- Sanitize
- Token
- Ajax
- Report

## Clase Database

La clase `Database` proporciona una manera fácil de conectar y realizar consultas en bases de datos MySQL usando PDO. Gestiona la conexión, la preparación y la ejecución de consultas SQL.

### Ejemplo de uso

```php
require_once 'Database.php';

$db = new Database('localhost', 'my_database', 'username', 'password');
$results = $db->query('SELECT * FROM users WHERE id = :id', ['id' => 1]);
```

## Clase Sanitize

La clase Sanitize contiene métodos estáticos para limpiar y validar datos de entrada, como números de teléfono, direcciones de correo electrónico, contraseñas, direcciones IP y direcciones físicas.

### Ejemoplo de uso

```php
require_once 'Sanitize.php';

$sanitizedEmail = Sanitize::sanitize('example@example.com');
$isEmailValid = Sanitize::check('example@example.com', Sanitize::EMAIL);
```

## Clase Token

La clase Token proporciona métodos estáticos para la creación, eliminación y verificación de tokens CSRF.

### Ejemplo de uso

```php
require_once 'Token.php';

$tokenName = 'my_token';
$token = Token::create($tokenName);
$isValid = Token::process($_POST['token_value'], $tokenName);
$isValidOnTime = Token::processTime($_POST['token_value'], $tokenName, 2);
```

## Clase Ajax

La clase Ajax contiene métodos estáticos para facilitar el manejo de las solicitudes AJAX, verificación de tokens CSRF y el envío de respuestas de éxito o error.

### Ejemplo de uso

```php
require_once 'Token.php';
require_once 'Ajax.php';

Ajax::ajax_start('POST', 'json');
if (!Ajax::ajax_token($_POST['token_name'], $_POST['token_value'])) {
    Ajax::ajax_error();
} else {
    Ajax::ajax_success();
}
```

## Clase Report

La clase Report maneja las excepciones y envía al usuario a una página segura, generando un reporte de error en formato JSON si es necesario.

### Ejemplo de uso

```php
require_once 'Report.php';

try {
    // Código que puede lanzar excepciones
} catch (Exception $e) {
    Report::handleException($e, 'safe_page.php', 'error_reports');
}

```