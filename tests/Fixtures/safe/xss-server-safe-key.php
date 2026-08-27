<?php

/**
 * Most $_SERVER keys are set by the web server, not the client. Treating the
 * whole superglobal as tainted makes the false positive rate unmanageable.
 */

echo '<p>Served by ' . $_SERVER['SERVER_NAME'] . '</p>';

echo '<p>Script: ' . $_SERVER['SCRIPT_FILENAME'] . '</p>';
