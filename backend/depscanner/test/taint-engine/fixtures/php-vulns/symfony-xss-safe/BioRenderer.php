<?php

namespace App\View;

class BioRenderer
{
    public static function render($safeBio)
    {
        return "<div class='bio'>" . $safeBio . "</div>";
    }
}
