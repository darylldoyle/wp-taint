<?php
/** Alternative control structure syntax, ubiquitous in WordPress templates. */
$items = [1, 2, 3];
?>
<?php if (! empty($items)) : ?>
    <ul>
    <?php foreach ($items as $i => $item) : ?>
        <li><?php echo esc_html((string) $item); ?></li>
    <?php endforeach; ?>
    </ul>
<?php elseif (is_admin()) : ?>
    <p>No items.</p>
<?php else : ?>
    <p>Nothing here.</p>
<?php endif; ?>
<?php
while (false) :
    break;
endwhile;

for ($i = 0; $i < 0; $i++) :
endfor;

switch (1) :
    case 1:
        break;
    default:
        break;
endswitch;
