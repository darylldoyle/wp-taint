<?php

/**
 * The other half of the same array. `name` is the filename the client sent, and
 * nothing stops it being `../../../wp-config.php`.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_store_upload(): void {
	$target = WP_CONTENT_DIR . '/uploads/' . $_FILES['import']['name'];

	copy( $_FILES['import']['tmp_name'], $target ); // wp-taint-expect wp.path.file-write path
}
