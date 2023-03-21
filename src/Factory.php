<?php

namespace OTP;

use OTP\Contract\TimeBasedOTP;

class Factory
{
    public static function userHOTP(TimeBasedOTP $user)
    {
        return new TOTP(
            $user->totpSecretKey(),
            $user->totpWindowSize(),
            $user->totpSupportTolerance(),
            $user->totpLength()
        );
    }

    /**
     * This help to create a user totp that does not comply with the 30 seconds interval placed by TOTP
     */
    public static function nonRFCCompliantUserHOTP(TimeBasedOTP $user, int $interval)
    {
        $hotp = (self::userHOTP($user));

        $hotp->customizeInterval($interval);
        return $hotp;
    }
}
