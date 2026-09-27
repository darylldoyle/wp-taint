<?php

declare(strict_types=1);

// Two findings on one echo are one defect only when they tell one story. A
// request value that reaches the echo raw and an escaped value a filter hands
// back are two flows, and showing only the medium for the filter hid the high.

it('reports a raw flow and a voided flow that reach one echo', function (): void {
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_render( $c ) {
            $raw = $_GET['title'];
            $voided = apply_filters( 'acme_title', esc_html( $_GET['name'] ) );
            echo $c ? $raw : $voided;
        }
        PHP)))->toEqualCanonicalizing(['wp.xss.unescaped-output@5', 'wp.xss.escape-voided@5']);
});

it('tells two flows apart when both start on the echo line', function (): void {
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_render( $c ) {
            echo $c ? $_GET['title'] : apply_filters( 'acme_title', esc_html( $_GET['name'] ) );
        }
        PHP)))->toEqualCanonicalizing(['wp.xss.unescaped-output@3', 'wp.xss.escape-voided@3']);
});

it('still reports a voided escape once', function (): void {
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_render() {
            echo apply_filters( 'acme_title', esc_html( $_GET['name'] ) );
        }
        PHP)))->toBe(['wp.xss.escape-voided@3']);
});

it('reports a value that is both raw and voided once, at its raw severity', function (): void {
    // One flow: the function's return is raw on one path and voided on the
    // other, so the caller's echo gets both kinds from one step.
    $findings = scanCode(<<<'PHP'
        <?php
        function acme_title( $c ) {
            return $c ? $_GET['title'] : apply_filters( 'acme_title', esc_html( $_GET['name'] ) );
        }
        function acme_render() {
            echo acme_title( true );
        }
        PHP)->findings->all();

    expect(array_map(static fn ($f): string => $f->ruleId . '@' . $f->line . ' ' . $f->severity->value, $findings))
        ->toBe(['wp.xss.escape-voided@6 high']);
});

it('names the voided escape when a filter callback appends raw input', function (): void {
    $findings = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_banner', function ( $banner ) {
            return $banner . wp_unslash( $_GET['suffix'] );
        } );
        function acme_banner() {
            return apply_filters( 'acme_banner', esc_html( get_option( 'acme_banner', 'Hello' ) ) );
        }
        function acme_render() {
            echo '<div class="banner">' . acme_banner() . '</div>';
        }
        PHP)->findings->all();

    expect(array_map(static fn ($f): string => $f->ruleId . '@' . $f->line . ' ' . $f->severity->value, $findings))
        ->toBe(['wp.xss.escape-voided@9 high']);
});
