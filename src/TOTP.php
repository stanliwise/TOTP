<?php

namespace OTP;

use Exception;

class TOTP
{
    /**
     * @var string The secret HOTP operate with
     * 
     */
    protected $secret;

    /**
     * @var int How long should be tolerate the time difference
     */
    protected $tolerance;

    /**
     * @var int The interval, i.e window size
     */
    protected $interval;

    /**
     * @var int The length of the token
     */
    protected $length;


    /**
     * @var int specify the size of tokens a window can contain, if interval is for example 30 seconds
     * and window size is 2 then it implicitly mean a window last for one minute. 
     * 
     * The Justification for introducing windowSize is for those who want to be compliant with for example
     * RFC standard of 30 seconds but wants to extend validation space of for example 1 minute, it means if
     * a user generates a token within a minutes and for example tolerance is false, then such is valid and would
     * comply with any OTP the user provides from his/her Google authenticator. This is because comparison would
     * happen with more than one token.
     */
    protected $windowSize;

    /**
     * @throws Exception
     */
    public function __construct(string $secret, $windowSize = 1, $tolerance = true, int $length = 6)
    {
        $this->secret = $secret;
        $this->interval = 30; #must be a multiple of 30
        $this->tolerance = $tolerance;
        $this->windowSize = $windowSize;
        $this->length = $length;

        if ($length < 4 || ($length > 8))
            throw new Exception('Token must not be lesser than four or greater than 8');
    }

    public function verify($token): bool
    {
        return !$this->tolerance ?
            $this->validateByWindow($token) #this window
            : ($this->validateByWindow($token) || #this window
                $this->validateByWindow($token, -1) || #previus windows
                $this->validateByWindow($token, 1) #next windows
            );
    }

    public function validateByWindow($token, int $windowSteps = 0)
    {
        foreach ($this->getWindowTokens($windowSteps) as $per_token) {
            if ($token == $per_token)
                return true;
        }

        return false;
    }


    public function getWindowTokens(int $windowSteps = 0)
    {
        #get the start time of the window
        $timestamp = $this->truncateTimestamp(time()) + ($windowSteps * $this->interval * $this->windowSize);

        #the amoount of steps per window
        for ($i = 0; $i < $this->windowSize; $i++) {
            yield $this->tokenAt($timestamp);

            $timestamp = $timestamp + $this->interval;
        }
    }

    /**
     * Get current TOTP token
     * 
     * @param int $steps How many steps from the current interval
     */
    public function token(int $steps = 0)
    {
        return $this->generateHOTPToken($this->getTimeFactor(time()) + $steps);
    }

    /**
     * Get token at a particular timestamp
     */
    public function tokenAt(float $timestamp, int $steps = 0)
    {
        return $this->generateHOTPToken($this->getTimeFactor($timestamp) + $steps);
    }

    protected function getTimeFactor(float $timestamp): int
    {
        date_default_timezone_set('UTC');
        return  $this->truncateTimestamp($timestamp) / $this->interval;
    }

    protected function truncateTimestamp($timestamp)
    {
        return floor($timestamp - ($timestamp % $this->interval));
    }

    /**
     * Get an HOTP token
     */
    public function generateHOTPToken(string $moving_factor)
    {
        $hexa = hash_hmac('sha1', $this->intToByteString($moving_factor), $this->secret, true);

        $splited_hexa = unpack('C*', $hexa);

        #TODO: truncation now will be dynamic
        $index = ($splited_hexa[20] & 0xf) + 1; #this is because unpack starts at index 1 instead of 0;

        $hex_token = ((($splited_hexa[$index]) & 0x7f) << 24) |
            ((($splited_hexa[$index + 1]) & 0xff) << 16) |
            ((($splited_hexa[$index + 2]) & 0xff) << 8) |
            (($splited_hexa[$index + 3]) & 0xff);

        return str_pad($hex_token % (pow(10, $this->length)), $this->length, 0, STR_PAD_LEFT);
    }

    private function hexPad(string $hex_string)
    {
        $st_l = strlen($hex_string);
        return str_pad($hex_string, $st_l + ($st_l % 2), '0', STR_PAD_LEFT);
    }

    protected function intToByteString(int $int): string
    {
        $hexEncode = hex2bin( #transform to binary(raw bytes)
            $this->hexPad( #pad hexadecimal evenly(with zeros on the left if necessary)
                dechex($int) #get hexadecimal string form of integer
            )
        );

        return str_pad($hexEncode, 8, "\000", STR_PAD_LEFT); #pad to a byte(8 bit)
    }

    protected function intToByteStringAlternate(int $int): string
    {

        //verbose explanation of the code above, more like an alternate
        $result = [];
        while ($int !== 0) {
            $result[] = chr($int & 0xFF); #take hexa at the extreme and push to array e.g in abc, bc is push to array
            $int >>= 8; #truncate the numbers taken i.e bc is truncated off to remain a
        }

        return str_pad(implode('', array_reverse($result)), 8, "\000", STR_PAD_LEFT);
    }

    public function customizeInterval(int $interval)
    {
        $this->interval  = $interval;
    }
}
