<?php
// The same class in three places, the way several plugins each bundle their
// own copy of one library. Every method has three bodies in three files.
class Acme_Bundled {
    public function m1( $x ) { return $x . '1'; }
    public function m2( $x ) { return $x . '2'; }
    public function m3( $x ) { return $x . '3'; }
    public function m4( $x ) { return $x . '4'; }
    public function show() { echo $this->m1( $_GET['q'] ); }
}
