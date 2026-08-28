<?php

final class Fixture_F07_Label {
    public function read() {
        // @wp-taint-source F07
        return isset( $_GET['label'] ) ? sanitize_text_field( wp_unslash( $_GET['label'] ) ) : '';
    }
    public function normalize( $value ) { return strtolower( trim( $value ) ); }
    public function render() {
        $label = $this->normalize( $this->read() );
        // @wp-taint-sink F07 expect=clean
        echo '<span>' . esc_html( $label ) . '</span>';
    }
}
