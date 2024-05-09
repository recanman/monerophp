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

    // todo: implement decode
}
