<?php

/**
 * Boilerplate registers hooks through a loader, and the component here lives on
 * a typed property rather than in a local variable. Before property types were
 * read, the callback could not be resolved to a body and the missing check was
 * invisible.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Loader {
	public array $actions = array();

	public function add_action( string $hook, object $component, string $callback ): void {
		$this->actions[] = array( $hook, $component, $callback );
	}
}

class Acme_Admin_Component {
	public function handle(): void {
		update_option( 'acme_from_loader', 1 );
	}
}

class Acme_Loader_Plugin {
	protected Acme_Admin_Component $admin;

	protected Acme_Loader $loader;

	public function __construct( Acme_Admin_Component $admin ) {
		$this->admin  = $admin;
		$this->loader = new Acme_Loader();

		$this->loader->add_action( 'wp_ajax_acme_loader_save', $this->admin, 'handle' ); // wp-taint-expect wp.authz.ajax-missing-check authz
	}
}
