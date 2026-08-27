<?php

/**
 * eval() on a literal is not a taint finding. It is bad practice, but this
 * tool is not a linter.
 */

eval('return 1 + 1;');
