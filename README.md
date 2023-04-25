# SECURITYTOOLS

This project contains several utility classes to improve security in PHP web applications. The included classes are:

- Database
- Sanitize
- Token
- Ajax
- Report

## Class Database

The Database class provides an easy way to connect to and query MySQL databases using PDO. It handles the connection, preparation, and execution of SQL queries.

### Example

```php
require_once 'Database.php';

$db = new Database('localhost', 'my_database', 'username', 'password');
$results = $db->query('SELECT * FROM users WHERE id = :id', ['id' => 1]);
```

## Class Sanitize

The Sanitize class contains static methods for cleaning and validating input data such as phone numbers, email addresses, passwords, IP addresses, and physical addresses.

### Example

```php
require_once 'Sanitize.php';

$sanitizedEmail = Sanitize::sanitize('Text that should not contain special characters.');
$isEmailValid = Sanitize::check('example@example.com', Sanitize::EMAIL);
```

## Class Token

The Token class provides static methods for creating, deleting, and verifying CSRF tokens.

### Example

```php
require_once 'Token.php';

$tokenName = 'my_token';
$token = Token::create($tokenName);
$isValid = Token::process($_POST['token_value'], $tokenName);
$isValidOnTime = Token::processTime($_POST['token_value'], $tokenName, 2);
```

## Class Ajax

The Ajax class contains static methods to facilitate handling AJAX requests, verifying CSRF tokens, and sending success or error responses.

### Example

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

## Class Report

The Report class handles exceptions and sends the user to a secure page, generating an error report in JSON format if necessary.

### Example

```php
require_once 'Report.php';

try {
    // Code that can throw exceptions.
} catch (Exception $e) {
    Report::handleException($e, 'safe_page.php', 'error_reports');
}

```