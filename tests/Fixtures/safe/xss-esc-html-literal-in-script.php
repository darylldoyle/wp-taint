<?php

/**
 * A hardcoded literal passed to esc_html__() is developer-authored text, not
 * attacker input, and carries no character that could break out of a <script>
 * block. The wrong-context rule reports attacker-controlled breakouts, so it
 * must leave this alone.
 */

printf('<script>var label = "%s";</script>', esc_html__('Open Date Picker', 'acme'));
