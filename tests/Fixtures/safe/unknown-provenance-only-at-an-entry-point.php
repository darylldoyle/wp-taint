<?php

// wp-taint-options unknown-provenance

/**
 * `--unknown-provenance` marks a parameter as unvouched-for. It used to mark
 * every parameter, including ones the scan can answer for itself:
 *
 *     acme_render( esc_html( $title ) );
 *
 * The caller settles that, and it is right there. Marking it anyway put 926
 * findings on the corpus, of which 784 were this — a value the engine had
 * already read the provenance of, reported for having none.
 *
 * A function nothing in the scan calls is the real case, and it has its own
 * fixture next to this one.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_render( string $title ): void {
	echo $title;
}

function acme_page(): void {
	acme_render( esc_html( get_bloginfo( 'name' ) ) );
}
