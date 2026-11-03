<?php
function hashPassword($p) { return md5($p); }
function encrypt($data, $key) { return openssl_encrypt($data, 'aes-128-ecb', $key); }
