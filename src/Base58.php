<?php

declare(strict_types=1);

namespace MoneroIntegrations\MoneroCrypto;

use \Exception;

class Base58
{
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const ALPHABET_SIZE = "58";
    const BLOCK_SIZE = 8;
    const ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    const FULL_ENCODED_BLOCK_SIZE = 11;

    /**
     * Converts an array of unsigned 8-bit big-endian integers to a 64-bit unsigned integer.
     */
    private static function uint8beTo64(array $data): string
    {
        $res = '0';
        $size = count($data);

        for ($i = 0; $i < $size; $i++) {
            $res = bcmul($res, '256');
            $res = bcadd($res, (string)ord($data[$i]));
        }

        return $res;
    }

    /**
     * Converts a decimal string to a hexadecimal string.
     */
    private static function decToHex(string $dec): string
    {
        $res = '';
        while (bccomp($dec, '0') > 0) {
            $remainder = bcmod($dec, '16');
            $dec = bcdiv($dec, '16');
            $res = dechex((int)$remainder) . $res;
        }

        return $res;
    }

    /**
     * Encodes a block of data into Monero's Base58.
     */
    private static function encodeBlock(array $data, array $res, int $res_offset): array
    {
        $length = count($data);

        if ($length < 1 || $length > self::FULL_ENCODED_BLOCK_SIZE) {
            throw new Exception("Invalid block length: " . $length);
        }

        $num = self::uint8beTo64($data);
        $i = self::ENCODED_BLOCK_SIZES[$length] - 1;

        while ($num > 0) {
            $remainder = bcmod($num, self::ALPHABET_SIZE);
            $num = bcdiv($num, self::ALPHABET_SIZE);
            $res[$res_offset + $i] = self::ALPHABET[$remainder];
            $i--;
        }

        return $res;
    }

    /**
     * Encodes a hexadecimal string into Monero's Base58.
     */
    public static function encode(string $hex): string
    {
        $data = str_split(hex2bin($hex));
        $length = count($data);

        if ($length === 0) {
            return '';
        }

        $full_block_count = (int)floor($length / self::BLOCK_SIZE);
        $last_block_size = $length % self::BLOCK_SIZE;
        $res_size = $full_block_count * self::FULL_ENCODED_BLOCK_SIZE + self::ENCODED_BLOCK_SIZES[$last_block_size];

        $res = array_fill(0, $res_size, self::ALPHABET[0]);

        for ($i = 0; $i < $full_block_count; $i++) {
            $res = self::encodeBlock(array_slice($data, $i * self::BLOCK_SIZE, self::BLOCK_SIZE), $res, $i * self::FULL_ENCODED_BLOCK_SIZE);
        }

        if ($last_block_size > 0) {
            $res = self::encodeBlock(array_slice($data, $full_block_count * self::BLOCK_SIZE, $last_block_size), $res, $full_block_count * self::FULL_ENCODED_BLOCK_SIZE);
        }

        return implode('', $res);
    }

    /**
     * Decodes a block of data from Monero's Base58.
     */
    private static function decodeBlock(array $data, array $res, int $res_offset): array
    {
        $length = count($data);

        if ($length < 1 || $length > self::FULL_ENCODED_BLOCK_SIZE) {
            throw new Exception("Invalid block length: " . $length);
        }

        $num = '0';

        for ($i = 0; $i < $length; $i++) {
            $char = $data[$i];
            $char_value = strpos(self::ALPHABET, $char);

            if ($char_value === false) {
                throw new Exception("Invalid character: " . $char);
            }

            $num = bcmul($num, self::ALPHABET_SIZE);
            $num = bcadd($num, (string)$char_value);
        }

        $res = array_merge($res, str_split(pack('H*', self::decToHex($num))));
        return $res;
    }

    /**
     * Decodes a Monero's Base58 string into a hexadecimal string.
     */
    public static function decode(string $base58): string
    {
        $data = str_split($base58);
        $length = count($data);

        if ($length === 0) {
            return '';
        }

        $full_block_count = (int)floor($length / self::FULL_ENCODED_BLOCK_SIZE);
        $last_block_size = $length % self::FULL_ENCODED_BLOCK_SIZE;

        $res = [];
        for ($i = 0; $i < $full_block_count; $i++) {
            $res = self::decodeBlock(array_slice($data, $i * self::FULL_ENCODED_BLOCK_SIZE, self::FULL_ENCODED_BLOCK_SIZE), $res, $i * self::BLOCK_SIZE);
        }

        if ($last_block_size > 0) {
            $res = self::decodeBlock(array_slice($data, $full_block_count * self::FULL_ENCODED_BLOCK_SIZE, $last_block_size), $res, $full_block_count * self::BLOCK_SIZE);
        }

        return bin2hex(implode('', $res));
    }
}
