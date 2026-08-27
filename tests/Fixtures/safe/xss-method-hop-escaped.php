<?php

/**
 * Method boundary with escaping inside the callee.
 */

class ReportRenderer
{
    public function render()
    {
        echo $this->build_header($_GET['report_filter']);
    }

    private function build_header($label)
    {
        return '<h2>' . esc_html($label) . '</h2>';
    }
}
