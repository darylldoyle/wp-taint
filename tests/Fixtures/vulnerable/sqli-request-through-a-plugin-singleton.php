<?php

/**
 * The same three steps carrying the request instead of a table name. Following
 * the chain has to find this, or following it is just a way to go quiet.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Query {
	public function order_by(): string {
		return $_GET['orderby'];
	}
}

class Acme_App {
	public $query;

	public function __construct() {
		$this->query = new Acme_Query();
	}
}

function acme_app(): Acme_App {
	static $app = null;

	return $app ??= new Acme_App();
}

function acme_listing(): array {
	global $wpdb;

	$order = acme_app()->query->order_by();

	return (array) $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $order" ); // wp-taint-expect wp.sqli.wpdb-query sql
}
