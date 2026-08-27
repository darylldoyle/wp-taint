<?php

/**
 * esc_textarea() is the correct escaper inside a textarea.
 */

echo '<textarea>' . esc_textarea($_POST['body']) . '</textarea>';
