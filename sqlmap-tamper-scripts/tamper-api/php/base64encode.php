#!/usr/bin/env php
<?php
#
# Author:       KING SABRI | @KINGSABRI
# Description:  Base64 encoding all characters in a given payload
# Requirements: None
#
$json    = json_decode($argv[1], true);
$payload = $json['payload'];
$kwargs  = $json['kwargs'];

$json['payload'] = base64_encode($payload);

echo json_encode($json);
?>
