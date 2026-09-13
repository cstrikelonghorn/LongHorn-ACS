<?php
// Reports are only ever read by the server and displayed through index.php. Refuse direct access.
http_response_code(403);
header('Content-Type: text/plain; charset=utf-8');
echo "Access denied.\n";
