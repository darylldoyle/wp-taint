<?php

/**
 * PHP writes `tmp_name`, `size` and `error` itself. `tmp_name` is a path under
 * `upload_tmp_dir` that the client never chose, and reading it is the only way
 * to read an upload at all.
 *
 * Ten plugins in the corpus were told this line was path traversal.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_import_settings(): string {
	if ( ! isset( $_FILES['import']['tmp_name'] ) ) {
		return '';
	}

	return (string) file_get_contents( $_FILES['import']['tmp_name'] );
}

/**
 * The same read spread over two statements, which is how the first real client
 * codebase this was pointed at spelled it.
 */
function acme_import_via_variable(): string {
	$upload = $_FILES['import'];

	return (string) file_get_contents( $upload['tmp_name'] );
}
