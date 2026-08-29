<?php

/**
 * The same shape with a fixed prefix on the name. `'acme_' . …` pens the
 * attacker into a namespace the plugin owns whatever the suffix is, so the
 * anchor carried from the constructor argument keeps the write silent.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Setting_Safe {
	private $name;

	public function __construct( $name ) {
		$this->name = $name;
	}

	public function save( $value ): void {
		update_option( $this->name, $value );
	}
}

function acme_store_ok(): void {
	$setting = new Acme_Setting_Safe( 'acme_' . sanitize_key( wp_unslash( $_POST['which'] ) ) );
	$setting->save( 1 );
}
