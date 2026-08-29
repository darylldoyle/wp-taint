<?php

/**
 * The apostrophe has to come first. `$1'` puts it *after* the `=`, which
 * neutralises nothing: the cell still begins with the formula character.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_export_badly(): void {
	$out = fopen( 'php://output', 'w' );

	$name = preg_replace( '/^([=+\-@])/', "$1'", (string) get_option( 'acme_name' ) );

	fputcsv( $out, array( $name ) ); // wp-taint-expect wp.output.csv-injection csv
	fclose( $out );
}
