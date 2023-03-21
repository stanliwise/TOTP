<?php

namespace OTP;

class Utils
{
    public static function dd($value)
    {
        var_dump($value);
        die;
    }

    public static function debug($value)
    {
        var_dump($value);
        ob_flush();
    }

    public static function logger($index)
    {
        file_put_contents('totp.log', file_get_contents('totp.log') . "\n" . $index);
    }
}
