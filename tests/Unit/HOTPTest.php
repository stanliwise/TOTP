<?php

namespace Test\Unit;

use OTP\Base32;
use OTP\TOTP;
use OTP\Utils;
use PHPUnit\Framework\TestCase;

class HOTPTest extends TestCase
{
    /**
     * @var \OTP\TOTP
     */
    protected $hotp;

    /**
     * @var string
     */
    protected $secret;

    public function setUp(): void
    {
        parent::setUp();
        $this->hotp = new TOTP("12345678901234567890", 3, true);
    }

    public function test_token_and_tokenAt()
    {
        $first_otp = $this->hotp->token();
        $second_otp = $this->hotp->tokenAt(time() - 30, 1);
        return $this->assertEquals($first_otp, $second_otp);
    }

    public function test_token_support_delay_tolerance()
    {
        $now = time();
        $token_1 = $this->hotp->tokenAt($now - 30); //remove 30 seconds 
        $token_2 = $this->hotp->tokenAt($now + 20); //add 20 seconds
        $this->assertTrue($this->hotp->verify($token_1));
        $this->assertTrue($this->hotp->verify($token_2));
    }

    public function testBase32Encoding()
    {
        $this->assertEquals(Base32::encode("12345678901234567890"), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $this->assertEquals(Base32::decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), "12345678901234567890");
    }

    public function test_verify_token_by_windows()
    {
        $this->assertTrue($this->hotp->validateByWindow(
            $this->hotp->token(2), 0
        ));
        #Utils::debug('hi');
        $this->assertTrue($this->hotp->verify($this->hotp->token(-29)));
    }
}
