<?php
/**
 * Stripping everything outside an allowlist is a real sanitizer, and a common
 * one: 146 sites in the corpus. WP Super Cache writes it with a comment saying
 * exactly why, right after a filter whose callbacks read the user agent.
 */

function acme_render_slug() {
	$slug = preg_replace( '/[^a-zA-Z0-9_-]/', '', $_GET['slug'] );

	echo $slug;
}

function acme_read_by_id() {
	$id = preg_replace( '/[^0-9]/', '', $_GET['id'] );

	include '/var/www/reports/' . $id . '.php';
}
