<?php
/**
 * The captures can only carry what the subject carried. A literal subject
 * produces literal captures.
 */

function acme_render_version() {
	preg_match( '/(\d+)\.(\d+)/', '6.4.2', $matches );

	echo $matches[1];
}
