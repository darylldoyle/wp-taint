<?php
/**
 * Template part rendering the banner option. Sink for the stored cross-component
 * flow: source is plugin-a's $_POST, storage is the option, sink is here.
 */
$banner = fx_theme_get_banner();
?>
<div class="site-banner">
	<?php
	// ruleid: wp.xcomp.sink-from-option
	echo $banner;
	?>
</div>
<?php
// Escaped variant for contrast. SAFE.
?>
<div class="site-banner-safe">
	<?php
	// ok: wp.xcomp.sink-from-option
	echo esc_html( $banner );
	?>
</div>
