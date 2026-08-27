Leading output before the open tag.
<?php $x = 1; ?>
<div class="wrap">
    <?= 'short echo tag' ?>
    <?php if ($x) { ?>
        <span>inline</span>
    <?php } ?>
</div>
<?php
echo 'trailing';
