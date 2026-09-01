<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * What passing a capability check proves about the object being operated on.
 *
 * WordPress capabilities come in three grains, and the difference is the whole
 * of the object-level authorization question:
 *
 * - **Object** (a meta capability): `edit_post`, `delete_user` — meaningful
 *   only with the object's id as the second argument, because `map_meta_cap()`
 *   resolves it against that specific row. With the id it is exactly the check
 *   an IDOR is missing; without it it checks nothing about any row.
 * - **Site**: `manage_options`, `edit_users` — a site-wide administrative
 *   grant. A caller holding one is entitled to cross-object operations, so a
 *   dominating check discharges the question for any id.
 * - **Role**: `edit_posts`, `upload_files` — proves the caller has a role, and
 *   nothing about whose row a request-supplied id names. The classic broken
 *   pattern is exactly a role check standing guard over an object operation.
 *
 * A capability not in the catalogue is treated as {@see self::Site}: plugins
 * mint their own capabilities and typically grant them to administrators, and
 * the documented false negative beats guessing a stranger's capability model.
 */
enum CapabilityScope: string
{
    case Object = 'object';
    case Site = 'site';
    case Role = 'role';
}
