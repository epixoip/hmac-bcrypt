<?php

include "../src/HMAC_Bcrypt.php";

$failure  = false;
$pepper   = 'test-pepper';
$expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ';

if (isset($_POST['password'])) {
    if (hmac_bcrypt_verify($_POST['password'], $expected, $pepper)) {
        print "<h2>Authenticated!</h2>";
        exit;
    } else {
        $failure = true;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>hmac-bcrypt test</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.css" />
    <style>
        body {
            background-color: #ECF0F1;
        }
        .page-login {
            margin-top: 25px;
        }
    </style>
</head>
<body>
<div class="page-login">
    <div class="ui centered grid container">
        <div class="nine wide column">
            <?php if ($failure): ?>
                <div class="ui icon warning message">
                    <i class="lock icon"></i>
                    <div class="content">
                        <div class="header"> Login failed </div>
                        <p>Invalid password!</p>
                    </div>
                </div>
            <?php endif; ?>
            <div class="ui fluid card">
                <div class="content">
                    <form class="ui form" method="POST">
                        <div class="field">
                            <label for="password">Password</label>
                            <input type="password" name="password" value="test-pass">
                        </div>
                        <button class="ui primary labeled icon button" type="submit">
                            <i class="unlock alternate icon"></i> Login </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.js"></script>
</body>
</html>
