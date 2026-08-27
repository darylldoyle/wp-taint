<?php

/**
 * Reflected XSS through a heredoc, which lowers the same way as interpolation.
 */

$title = $_POST['title'];

$markup = <<<HTML
<section>
    <h1>{$title}</h1>
</section>
HTML;

echo $markup; // wp-taint-expect wp.xss.unescaped-output html
