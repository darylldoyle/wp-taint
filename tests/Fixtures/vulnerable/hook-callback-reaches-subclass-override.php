<?php
/**
 * A base class registers `array( $this, 'render' )`, and a subclass overrides
 * render(). `$this` is the subclass when the subclass is constructed, so the
 * override is what the action runs. The base's escaping body says nothing
 * about it.
 */

class Acme_Base_Widget {
	public function __construct() {
		add_action( 'acme_widget_render', array( $this, 'render' ) );
	}

	public function render( $value ) {
		echo esc_html( $value );
	}
}

class Acme_Title_Widget extends Acme_Base_Widget {
	public function render( $value ) {
		echo $value; // wp-taint-expect wp.xss.unescaped-output html
	}
}

new Acme_Title_Widget();

function acme_render_widgets() {
	do_action( 'acme_widget_render', $_GET['title'] );
}
