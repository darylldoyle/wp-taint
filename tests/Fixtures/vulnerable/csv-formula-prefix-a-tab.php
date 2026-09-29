<?php

/**
 * A tab in front of the formula is not credited. trim() removes it, and so do
 * readers that strip a cell's leading whitespace.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_export_with_a_tab(): void {
	$out = fopen( 'php://output', 'w' );

	$name = preg_replace( '/^([=+\-@])/', "\t$1", (string) get_option( 'acme_name' ) );

	fputcsv( $out, array( $name ), ',', '"', '' ); // wp-taint-expect wp.output.csv-injection csv
	fclose( $out );
}
