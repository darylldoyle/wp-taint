<?php
/**
 * Inside a namespace, add_action() compiles to the namespaced call form even
 * though it resolves to the global function at runtime. Matching only the plain
 * form silently missed every registration in namespaced code — 747 of
 * Elementor's 757.
 */

namespace Acme\Plugin;

add_filter( 'acme_ns_title', __NAMESPACE__ . '\\acme_ns_inject' );

function acme_ns_inject( $value ) {
	return $_GET['title'];
}

function acme_ns_render() {
	echo apply_filters( 'acme_ns_title', 'A safe default' ); // wp-taint-expect wp.xss.unescaped-output html
}
