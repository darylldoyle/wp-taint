<?php

/**
 * A spreadsheet treats a cell beginning `=`, `+`, `-` or `@` as a formula.
 * Prefixing one with an apostrophe stops that, and it is exactly what
 * `wp.output.csv-injection` tells people to do.
 *
 * Asking for something and then not crediting it when it is done is the same
 * defect as advice that cannot be followed.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_export_safely(): void {
	$out = fopen( 'php://output', 'w' );

	$name = preg_replace( '/^([=+\-@])/', "'$1", (string) get_option( 'acme_name' ) );

	fputcsv( $out, array( $name ) );
	fclose( $out );
}
