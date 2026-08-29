<?php

/**
 * `$wpdb` and `$this->db` are the near-universal names for the database handle,
 * and the resolver treats them as such because a global has no declaration to
 * read. A declared type does, and it has to win.
 *
 * Reading `$db` here as the handle resolved `$db->table_name()` to
 * `wpdb::table_name()`, which nothing defines. The call then failed to resolve,
 * its origin was "unaccounted for", and the table name it returns was reported
 * as an unprepared query.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Store {
	public function table_name(): string {
		global $wpdb;

		return $wpdb->prefix . 'acme_things';
	}
}

function acme_all( Acme_Store $db ): array {
	global $wpdb;

	$table = $db->table_name();

	return (array) $wpdb->get_results( "SELECT * FROM $table" );
}
