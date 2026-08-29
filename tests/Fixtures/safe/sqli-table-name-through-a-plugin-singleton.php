<?php

/**
 * The shape every substantial plugin is made of, and the one that produced most
 * of the corpus's unprepared-query findings.
 *
 * Every link is provable and the value is a table name the plugin built out of
 * `$wpdb->prefix` and a class constant. What was missing was the receiver: the
 * engine tracked parameter types and `new Foo()` within one body, so it could
 * not get from `acme()` to `Acme_Plugin`, or from there to `$db`.
 *
 * `wpforms()->form->`, `aioseo()->core->db->` and `WC()->countries->` are the
 * same three steps.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Store {
	private string $table = '';

	public function __construct() {
		global $wpdb;

		$this->table = $wpdb->prefix . 'acme_things';
	}

	public function table_name(): string {
		return $this->table;
	}
}

class Acme_Plugin {
	public $store;

	public function __construct() {
		$this->store = new Acme_Store();
	}
}

function acme(): Acme_Plugin {
	static $plugin = null;

	return $plugin ??= new Acme_Plugin();
}

function acme_all(): array {
	global $wpdb;

	$table = acme()->store->table_name();

	return (array) $wpdb->get_results( "SELECT * FROM $table" );
}
