<?php
/**
 * Fixture: correct late-escaping at the sink. Every case is SAFE.
 * A finding on any annotated line is a false positive.
 * Note: $value is treated as already-tainted (came from DB / meta / option).
 */

function fx_render( $value, $url, $attr ) {
	// ok: wp.output.unescaped
	echo esc_html( $value );

	// ok: wp.output.unescaped
	printf( '<a href="%s">link</a>', esc_url( $url ) );

	// ok: wp.output.unescaped
	printf( '<div data-x="%s"></div>', esc_attr( $attr ) );

	// ok: wp.output.unescaped
	echo wp_kses_post( $value );

	// ok: wp.output.unescaped
	echo esc_textarea( $value );

	// ok: wp.output.unescaped
	?><input type="text" value="<?php echo esc_attr( $value ); ?>" /><?php

	// ok: wp.output.unescaped
	echo esc_html__( 'Static translatable string', 'fx' );

	// ok: wp.output.unescaped
	echo absint( $value ); // cast to int is a valid numeric escape

	// ok: wp.output.unescaped
	wp_kses( $value, array( 'strong' => array(), 'em' => array() ) );
}
