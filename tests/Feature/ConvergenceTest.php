<?php

declare(strict_types=1);

/**
 * Shapes that made the fixed point oscillate forever.
 *
 * Every one of these was found by running the corpus, not by writing a fixture.
 * Non-convergence is worse than a wrong answer: the engine gives up mid-flight
 * and reports "results may be incomplete", so anything downstream of the loop
 * is unreliable.
 *
 * The rule they all come back to: **every transfer function must be monotone.**
 * Two ops writing the same operand with different answers is the way that
 * breaks, and SSA does not give array elements or assertion targets their own
 * operands.
 */

/**
 * @return list<string> `file function` for each function that did not converge
 */
function convergenceWarnings(string $code): array
{
    return array_map(
        static fn (object $warning): string => trim($warning->file . ' ' . $warning->functionName),
        scanCode($code)->warnings,
    );
}

it('converges when an array is built empty and filled in a loop', function (): void {
    // `$out = array()` and `$out[$k] = …` write the same SSA operand, because
    // SSA does not re-version an array for an element write. Sharing one taint
    // slot made the two fight: assignment sets it empty, element write sets it
    // tainted, forever.
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        $out = array();

        foreach ((array) $_GET['items'] as $key => $item) {
            $out[$key] = $item;
        }

        echo implode(', ', $out);
        PHP);

    expect($warnings)->toBe([]);
});

it('still reports the taint written into that array', function (): void {
    // Fixing the oscillation must not fix it by losing the flow.
    $result = scanCode(<<<'PHP'
        <?php
        $out = array();

        foreach ((array) $_GET['items'] as $key => $item) {
            $out[$key] = $item;
        }

        echo $out['first'];
        PHP);

    expect($result->findings)->toHaveCount(1);
    expect($result->findings->all()[0]->ruleId)->toBe('wp.xss.unescaped-output');
});

it('converges when a tainted array element is overwritten in a loop', function (): void {
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        $plugins = get_option('active_plugins');

        foreach ($plugins as $i => $plugin) {
            if ($plugin === 'x') {
                $plugins[$i] = false;
            }
        }

        update_option('active_plugins', array_filter($plugins));
        PHP);

    expect($warnings)->toBe([]);
});

it('converges through isset and empty guards', function (): void {
    // php-cfg gives Op\Expr\Assertion an operand that is *already written* by
    // the op producing the value, rather than a fresh temporary. Treating the
    // assertion as producing a clean value made the two writers alternate.
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        if (empty($_POST['_wpnonce']) || ! is_string($_POST['_wpnonce'])) {
            return;
        }

        if (isset($_GET['tab']) && isset($_GET['section'])) {
            echo esc_html($_GET['tab']);
        }
        PHP);

    expect($warnings)->toBe([]);
});

it('does not let an isset guard launder taint', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        if (isset($_GET['q'])) {
            echo $_GET['q'];
        }
        PHP);

    expect($result->findings)->toHaveCount(1);
});

it('converges on a nested loop that appends to a string', function (): void {
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        $where = '';

        foreach (array('a', 'b') as $column) {
            foreach ((array) $_GET['terms'] as $term) {
                $where .= $column . $term;
            }
        }

        echo $where;
        PHP);

    expect($warnings)->toBe([]);
});

it('converges when a property is written and read in the same body', function (): void {
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        class Acme
        {
            private $value;

            public function run()
            {
                $this->value = $_GET['v'];

                for ($i = 0; $i < 3; $i++) {
                    $this->value = $this->value . $i;
                }

                echo esc_html($this->value);
            }
        }
        PHP);

    expect($warnings)->toBe([]);
});

it('converges when a static property is written and read', function (): void {
    $warnings = convergenceWarnings(<<<'PHP'
        <?php
        class Acme
        {
            private static $option;

            public static function getOption($cache = true)
            {
                if (self::$option && $cache) {
                    return self::$option;
                }

                $option = get_option('acme', array());

                self::$option = array(
                    'feed' => !empty($option['feed']) ? (array) $option['feed'] : array(),
                );

                return self::$option;
            }
        }
        PHP);

    expect($warnings)->toBe([]);
});

it('follows taint through a static property', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme
        {
            private static $label;

            public static function store()
            {
                self::$label = $_GET['label'];
            }

            public static function render()
            {
                echo self::$label;
            }
        }
        PHP);

    expect($result->findings)->toHaveCount(1);
    expect($result->findings->all()[0]->ruleId)->toBe('wp.xss.unescaped-output');
});

it('traces a property flow back to its source across method boundaries', function (): void {
    // A trace that begins "read from property $x" and stops there tells a
    // reviewer nothing, and a finding they cannot judge is one they learn to
    // ignore. On the corpus roughly a fifth of findings entered through a
    // property read, so this is not a corner case.
    $result = scanCode(<<<'PHP'
        <?php
        class Acme
        {
            private $label;

            public function capture()
            {
                $this->label = $_GET['label'];
            }

            public function render()
            {
                echo $this->label;
            }
        }
        PHP);

    expect($result->findings)->toHaveCount(1);

    $trace = $result->findings->all()[0]->trace;
    $verbs = array_map(static fn (object $step): string => $step->verb->value, $trace);

    expect($verbs[0])->toBe('source');
    expect($verbs[count($verbs) - 1])->toBe('sink');

    $descriptions = implode("\n", array_map(static fn (object $step): string => $step->description, $trace));

    expect($descriptions)->toContain('superglobal $_GET');
    expect($descriptions)->toContain('Written to property $label');
    expect($descriptions)->toContain('Read from property $label');
});

it('traces a static property flow back to its source', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme
        {
            private static $label;

            public static function capture()
            {
                self::$label = $_POST['label'];
            }

            public static function render()
            {
                echo self::$label;
            }
        }
        PHP);

    expect($result->findings)->toHaveCount(1);
    expect($result->findings->all()[0]->trace[0]->verb->value)->toBe('source');
});

it('does not treat array values as if they were array keys', function (): void {
    // WooCommerce interpolates array_keys() of a data array into fourteen
    // prepared queries. The values are user data; the keys are column names.
    // Conflating them made every one of those a critical finding.
    $result = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $data = array('hook' => $_POST['hook'], 'args' => $_POST['args']);
        $columns = '`' . implode('`, `', array_keys($data)) . '`';
        $wpdb->query($wpdb->prepare("INSERT INTO wp_acme ({$columns}) VALUES (%s, %s)", array_values($data)));
        PHP);

    expect($result->findings)->toHaveCount(0);
});

it('still reports array values reaching a sink', function (): void {
    // The key/value split must not lose the flow it was carved out of.
    $result = scanCode(<<<'PHP'
        <?php
        $args = array($_GET['first'], $_GET['second']);
        vprintf('<p>%s %s</p>', $args);
        PHP);

    expect($result->findings)->toHaveCount(1);
});

it('still treats the keys of a superglobal as attacker-controlled', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        foreach ($_GET as $key => $value) {
            echo $key;
        }
        PHP);

    expect($result->findings)->toHaveCount(1);
});
