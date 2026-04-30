<?php

namespace App\Repository;

class UserRepository
{
    public static function findByName($name)
    {
        $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
        return static::$connection->executeQuery($sql);
    }
}
