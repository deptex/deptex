<?php

namespace App\View;

class BioRenderer
{
    public static function render($rawBio)
    {
        return "<div class='bio'>" . $rawBio . "</div>";
    }
}
