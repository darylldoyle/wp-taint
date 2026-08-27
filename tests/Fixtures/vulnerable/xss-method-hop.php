<?php

/**
 * Reflected XSS crossing a method boundary on $this.
 */

class ReportRenderer
{
    public function render()
    {
        $filter = $_GET['report_filter'];

        echo $this->build_header($filter); // wp-taint-expect wp.xss.unescaped-output html
    }

    private function build_header($label)
    {
        return '<h2>' . $label . '</h2>';
    }
}
