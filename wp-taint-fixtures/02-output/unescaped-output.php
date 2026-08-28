<?php
/**
 * Fixture: tainted values reaching an output sink with no escaping.
 * Every annotated line is VULNERABLE (CWE-79 reflected/stored XSS at sink).
 * $value / $url are assumed tainted (option, meta, query var).
 */

function fx_render_bad( $value, $url ) {
	// ruleid: wp.output.unescaped
	echo $value;

	// ruleid: wp.output.unescaped
	print( $value );

	// ruleid: wp.output.unescaped
	printf( '<span>%s</span>', $value );

	// ruleid: wp.output.unescaped
	echo "<div class='{$value}'>x</div>";

	// ruleid: wp.output.unescaped
	?><a href="<?php echo $url; ?>">go</a><?php

	// ruleid: wp.output.unescaped
	echo '<p>' . $value . '</p>';

	// printf with the taint in the FORMAT string, not an arg — classic miss.
	// ruleid: wp.output.unescaped
	printf( $value );

	// Heredoc interpolation.
	// ruleid: wp.output.unescaped
	echo <<<HTML
<section>$value</section>
HTML;
}
