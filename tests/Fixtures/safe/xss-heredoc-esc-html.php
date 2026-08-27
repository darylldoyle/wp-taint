<?php

/**
 * Heredoc with an escaped value.
 */

$title = esc_html($_POST['title']);

echo <<<HTML
<section>
    <h1>{$title}</h1>
</section>
HTML;
