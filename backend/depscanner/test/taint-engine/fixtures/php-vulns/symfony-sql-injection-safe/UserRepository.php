<?php

namespace App\Repository;

class UserRepository
{
    public static function findByNameSafe($name)
    {
        $sql = "SELECT * FROM users WHERE name = ?";
        return static::$connection->executeQuery($sql, [$name]);
    }
}
