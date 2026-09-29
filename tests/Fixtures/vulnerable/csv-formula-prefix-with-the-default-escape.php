<?php

/**
 * The apostrophe covers the cell's first character only. fputcsv()'s default
 * escape character is a backslash, and it does not double a quote that follows
 * one. A spreadsheet reads that quote as the end of the cell:
 *
 *     x\",=HYPERLINK("http://example.com")
 *
 * becomes two cells, and the second one is a formula.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_export_escapably(): void {
	$out = fopen( 'php://output', 'w' );

	$name = preg_replace( '/^([=+\-@])/', "'$1", (string) get_option( 'acme_name' ) );

	fputcsv( $out, array( $name ) ); // wp-taint-expect wp.output.csv-injection csv_prefixed
	fclose( $out );
}
