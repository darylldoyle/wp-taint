<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Registry\CapabilityScope;
use Enshrined\WpTaint\Registry\Registry;

/**
 * Every admin page the scan registers, by the function that renders it.
 *
 * WordPress runs a page's callback only for a user who holds the capability
 * the page was registered with. `add_submenu_page( 'acme', 'Settings',
 * 'Settings', 'manage_options', 'acme-settings', 'acme_settings_page' )` hands
 * `acme_settings_page()` to administrators alone, so a settings form the page
 * saves is one only they can submit.
 *
 * A callback registered for several pages answers to all of them, and the
 * least favourable capability wins.
 */
final class AdminPageTable
{
    /**
     * Callback function key => the capabilities its pages are registered
     * with, one list per registration. An empty list is a capability the
     * scan could not fold to a string.
     *
     * @var array<string, list<list<string>>>
     */
    private array $byCallback = [];

    /**
     * @param list<string> $capabilities every string the capability argument can be, or none when it is
     *                                   computed
     */
    public function add(string $callbackKey, array $capabilities): void
    {
        $this->byCallback[strtolower($callbackKey)][] = $capabilities;
    }

    /**
     * @return list<string>
     */
    public function callbackKeys(): array
    {
        return array_keys($this->byCallback);
    }

    /**
     * The capabilities of every page this callback renders.
     *
     * @return list<list<string>>
     */
    public function capabilitiesFor(string $callbackKey): array
    {
        return $this->byCallback[strtolower($callbackKey)] ?? [];
    }

    /**
     * The callbacks every one of whose pages asks for a site-wide grant.
     *
     * A capability the catalogue does not know counts, as it does for
     * {@see \Enshrined\WpTaint\Taint\CapabilityGuard}, and so does one the
     * scan could not fold. Redirection registers its page with
     * `apply_filters( 'redirection_role', 'manage_options' )`, which is an
     * administrator's grant unless a site filters it.
     *
     * @return array<string, true>
     */
    public function administratorOnly(Registry $registry): array
    {
        $only = [];

        foreach ($this->byCallback as $key => $registrations) {
            foreach ($registrations as $capabilities) {
                foreach ($capabilities as $capability) {
                    $scope = $registry->capabilityScope($capability);

                    if ($scope !== null && $scope !== CapabilityScope::Site) {
                        continue 3;
                    }
                }
            }

            $only[$key] = true;
        }

        return $only;
    }
}
