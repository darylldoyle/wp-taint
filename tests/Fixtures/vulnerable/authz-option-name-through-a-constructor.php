<?php

/**
 * The option name is chosen by the request, laundered through a constructor
 * that stores it on a property and a method that writes it. Anchoring is the
 * caller's to settle — inside the constructor the value is a parameter, which
 * reads as anchored — so the caller's argument decides, carried onto the
 * property and surviving the interprocedural merge.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Setting {
	private $name;

	public function __construct( $name ) {
		$this->name = $name;
	}

	public function save( $value ): void {
		update_option( $this->name, $value ); // wp-taint-expect wp.authz.arbitrary-option-write identifier
	}
}

function acme_store_bad(): void {
	$setting = new Acme_Setting( wp_unslash( $_POST['which'] ) );
	$setting->save( 1 );
}
