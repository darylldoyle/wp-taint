<?php
/**
 * Template Name: Acme Report
 *
 * Shapes that appear constantly in WordPress themes and nowhere else.
 */

if (! defined('ABSPATH')) {
    exit;
}

get_header();

if (have_posts()) :
    while (have_posts()) :
        the_post();
        ?>
        <article <?php post_class(); ?> id="post-<?php the_ID(); ?>">
            <h1><?php the_title(); ?></h1>
            <?php the_content(); ?>
        </article>
        <?php
    endwhile;
endif;

get_sidebar();
get_footer();
