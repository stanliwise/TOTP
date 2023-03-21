<?php

namespace OTP\Contract;

interface TimeBasedOTP
{
    public function totpSecretKey(): string;

    public function totpWindowSize(): int;

    public function totpSupportTolerance(): bool;

    public function totpLength(): int;
}
