<?php
/* https://pdapps.org/kanbani/web | License: MIT */
namespace Kanbani;

class SyncFileException extends \Exception {}
class MissingSyncFileSecret extends SyncFileException {}
class InvalidSyncFileVersionException extends SyncFileException {}
class InvalidSyncFileHashException extends SyncFileException {}
class InvalidSyncDataVersionException extends SyncFileException {}

class SyncFile {
    // Version numbers ($version).
    const PLAIN = 0;
    const ENCRYPTED = 1;

    // Must be set before unserialize().
    public $ignoreBadHash = false;

    // For encrypted files, must be set before serialize() and unserialize()
    // if $version is ENCRYPTED.
    public $secret;
    public $boardID;

    // These are set by unserialize() or must be set before calling serialize().
    public $version;    // an integer.
    public $hashAlgorithm = "SHA-256";      // in Java format.
    public $hash;       // binary form.
    public $isBadHash;  // set by unserialize().
    // In Java format. Ignored if PLAIN.
    public $encryptAlgorithm = "AES/CTR/PKCS5Padding";
    public $iv;         // ignored if PLAIN.
    public $data;       // string (un/compressed by un/serialize()).

    protected $preview;

    // Provide $secret and $boardID if reading an encrypted file.
    //
    // $sync = (new SyncFile)->unserializeFile("123.kanbani");
    // $object = json_decode($sync->data);
    function unserializeFile($path, $secret = null, $boardID = null) {
        $this->secret = $secret;
        $this->boardID = $boardID;
        return $this->unserialize(file_get_contents($path));
    }

    // Provide $secret and $boardID if writing an encrypted file.
    //
    // $data = json_encode($object);
    // (new SyncFile)->serializeFile("123.kanbani", $data);
    function serializeFile($path, $data, $secret = null, $boardID = null) {
        $this->data = $data;
        $this->version = strlen($secret) ? static::ENCRYPTED : static::PLAIN;
        $this->secret = $secret;
        $this->boardID = $boardID;
        file_put_contents($path, $this->serialize(), LOCK_EX);
        return $this;
    }

    function serialize() {
        $str = gzcompress($this->data);
        $func = "serialize_$this->version";
        if (!method_exists($this, $func)) {
            throw new InvalidSyncFileVersionException("Invalid version for serializing: $this->version.");
        }
        return chr($this->version)."$this->hashAlgorithm\n".$this->$func($str);
    }

    protected function serialize_0($str) {
        return $str.hash($this->phpHashAlgorithm(), $str, true);
    }

    protected function serialize_1($str) {
        list($encAlgo, $padding, $isAEAD) = $this->phpEncryptAlgorithm();
        $this->iv = openssl_random_pseudo_bytes($this->ivLength());
        list($authKey, $encKey) = $this->deriveKeys();
        if (version_compare(PHP_VERSION, "7.1.0", "<") || !$isAEAD) {
            $data = openssl_encrypt($str, $encAlgo, $encKey, OPENSSL_RAW_DATA | $padding, $this->iv);
            $tag = "";
        } else {
            $data = openssl_encrypt($str, $encAlgo, $encKey, OPENSSL_RAW_DATA | $padding, $this->iv, $tag);
        }
        $data = "$this->encryptAlgorithm\n$this->iv$data$tag";
        return $data.hash_hmac($this->phpHashAlgorithm(), $data, $authKey, true);
    }

    // Faster version of unserialize() that only fills some fields and sets
    // $data to raw string, compressed and/or encrypted. This can be
    // used to validate file signature/hash. $secret/$boardID are not used.
    function unserializeHeader($str) {
        $this->preview = true;
        try {
            return $this->unserialize($str);
        } finally {
            $this->preview = false;
        }
    }

    function unserialize($str) {
        $this->version = ord($str[0]);
        $func = "unserialize_$this->version";
        if (!method_exists($this, $func)) {
            throw new InvalidSyncFileVersionException("Invalid version for unserializing: $this->version.");
        }
        $this->data = $this->$func(substr($str, 1));
        if (!$this->preview) {
            $this->data = gzuncompress($this->data);
        }
        return $this;
    }

    protected function unserialize_0($str) {
        list($this->hashAlgorithm, $data) = explode("\n", $str, 2);
        $length = $this->hashLength();
        $this->hash = substr($data, -$length);
        $data = substr($data, 0, -$length);
        if (!$this->preview) {
            $this->isBadHash = !hash_equals(hash($this->phpHashAlgorithm(), $data, true), $this->hash);
            if ($this->isBadHash && !$this->ignoreBadHash) {
                throw new InvalidSyncFileHashException("Bad data hash.");
            }
        }
        return $data;
    }

    protected function unserialize_1($str) {
        list($this->hashAlgorithm, $data) = explode("\n", $str, 2);
        $length = $this->hashLength();
        $this->hash = substr($data, -$length);
        $authenticated = substr($data, 0, -$length);
        list($this->encryptAlgorithm, $data) = explode("\n", $authenticated, 2);
        $this->iv = substr($data, 0, $this->ivLength());
        $encrypted = substr($data, strlen($this->iv));
        if ($this->preview) {
            return $encrypted;
        }
        list($authKey, $encKey) = $this->deriveKeys();
        $this->isBadHash = !hash_equals(hash_hmac($this->phpHashAlgorithm(), $authenticated, $authKey, true), $this->hash);
        if ($this->isBadHash && !$this->ignoreBadHash) {
            throw new InvalidSyncFileHashException("Bad data HMAC.");
        }
        list($encAlgo, $padding, $isAEAD) = $this->phpEncryptAlgorithm();
        if (version_compare(PHP_VERSION, "7.1.0", "<") || !$isAEAD) {
            return openssl_decrypt($encrypted, $encAlgo, $encKey, OPENSSL_RAW_DATA | $padding, $this->iv);
        } else {
            // PHP 7.1 added support for GCM ciphers which need $tag (length is 16)
            // stored separately, alike to $iv.
            return openssl_decrypt(substr($encrypted, 0, -16), $encAlgo, $encKey, OPENSSL_RAW_DATA | $padding, $this->iv, substr($encrypted, -16));
        }
    }

    // SHA-256 -> sha256
    // HmacSHA256 -> sha256
    function phpHashAlgorithm() {
        return preg_replace('/^hmac|[-]/', "", strtolower($this->hashAlgorithm));
    }

    // Returns standard PHP algorithm name + "/padding" or "/nopadding".
    // AES/CTR/PKCS5Padding -> aes-128-ctr, 0
    // AES_256/GCM/NoPadding -> aes-256-gcm, OPENSSL_ZERO_PADDING
    function phpEncryptAlgorithm() {
        $regexp = '!^aes(_(128|192|168))?/(cbc|ctr|gcm)/(pkcs5padding|nopadding)$!';
        if (preg_match($regexp, strtolower($this->encryptAlgorithm), $match)) {
            return [
                "aes-".($match[2] ?: 128)."-$match[3]",
                $match[4][0] === "n" ? OPENSSL_ZERO_PADDING : 0,
                $match[3] === "gcm",
            ];
        }
    }

    function deriveKeys() {
        if (!strlen($this->secret) || !strlen($this->boardID)) {
            throw new MissingSyncFileSecret("The sync file is encrypted but no secret and/or board ID were supplied.");
        }
        $info = $this->encryptAlgorithm.$this->iv;
        $masterKey = hash_pbkdf2("sha1", $this->secret, $this->boardID, 10000, 0, true);
        return [
            hash_hkdf("sha256", $masterKey, 0, "auth".$info, $this->boardID),
            hash_hkdf("sha256", $masterKey, 0, "enc".$info, $this->boardID),
            hash_hkdf("sha256", $masterKey, 0, "filename1", $this->boardID),
        ];
    }

    // Returns a name without extension for a file that Kanbani would produce
    // when syncing an encrypted profile using a network transport (i.e. other
    // than Local File or Android Share).
    // This method alone uses only $secret and $boardID properties.
    function encryptedFileName() {
        return hash_hmac("sha256", $this->boardID, $this->deriveKeys()[2]);
    }

    function hashLength() {
        return strlen(hash($this->phpHashAlgorithm(), "", true));
    }

    function ivLength() {
        return openssl_cipher_iv_length($this->phpEncryptAlgorithm($this->encryptAlgorithm)[0]);
    }

    function isEncrypted() {
        return $this->version === static::ENCRYPTED;
    }
}

class SyncData implements \JsonSerializable {
    const SYNC_VERSION = 1;
    const CLIENT_VERSION = 1;

    const UTF8_BOM = "\xEF\xBB\xBF";

    public $boards;

    function __construct(array $boards = []) {
        $this->boards = $boards;
    }

    function jsonSerialize() {
        return [
            "sync_version"      => static::SYNC_VERSION,
            "client_version"    => static::CLIENT_VERSION,
            "boards"            => $this->boards,
        ];
    }

    function unserializeFile($path, $secret = null, $boardID = null) {
        return $this->unserializeFileUsing(new SyncFile, $path, $secret, $boardID);
    }

    function unserializeFileUsing(SyncFile $file, $path, $secret = null, $boardID = null) {
        $file = $file->unserializeFile($path, $secret, $boardID);
        $data = json_decode($file->data);
        static::verifyUnserialized($data, $secret, $boardID);
        $this->boards = $data->boards;
        return $this;
    }

    static function verifyUnserialized($data, $secret = null, $boardID = null) {
        if (!is_object($data) ||
                +$data->sync_version !== static::SYNC_VERSION ||
                +$data->client_version !== static::CLIENT_VERSION ||
                !$data->boards) {
            throw new InvalidSyncDataVersionException(sprintf(
                "Invalid sync_version (%s) or client_version (%s). Expected: sync %s/client %s.",
                $data->sync_version, $data->client_version,
                static::SYNC_VERSION, static::CLIENT_VERSION));
        }
        if (strlen($secret) && ($id = $data->boards[0]->id) !== $boardID) {
            throw new SyncFileException("Encrypted data of another board: $id. Expected: $boardID.");
        }
    }

    function serializeFile($path, $secret = null) {
        return $this->serializeFileUsing(new SyncFile, $path, $secret);
    }

    // If editing an existing sync file, provide $file to preserve existing
    // serialization options ($hashAlgorithm and others):
    //
    // $file = new SyncFile;
    // $data = (new SyncData)->unserializeFileUsing($file, "123.kanbani");
    // ...edit $data->boards...
    // $data->serializeFileUsing($file, "123.kanbani");
    function serializeFileUsing(SyncFile $file, $path, $secret = null) {
        if (!$this->boards) {
            throw new SyncFileException("No boards set for serialization.");
        }
        if (strlen($secret) && !$this->isSingleBoard()) {
            throw new SyncFileException("Encrypting a multi-board sync file is not supported yet.");
        }
        $file->serializeFile($path, $this->serializeToJSON(), $secret, $this->boards[0]->id);
        return $this;
    }

    function serializeToJSON($flags = 0) {
        return json_encode($this, $flags | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    function serializeToExcelCSV() {
        return static::UTF8_BOM.$this->serializeToCSV(";", "\r\n");
    }

    function serializeToCSV($separator = ",", $eol = "\n") {
        $lines = [];

        $push = function (array $values) use (&$lines, $separator) {
            $quoter = function ($v) {
                return '"'.preg_replace('/"/u', '""', $v).'"';
            };
            $lines[] = join($separator, array_map($quoter, $values));
        };

        $encodeCustom = function ($data) {
            return $data === null ? "" : json_encode($data);
        };

        foreach ($this->boards as $board) {
            $push([
                "board",
                $board->id,
                $board->create_time,
                $board->title,
                $encodeCustom($board->custom),
            ]);
            foreach ($board->lists as $list) {
                if (!isset($list->cards)) { continue; }     // skip deleted.
                $push([
                    "list",
                    $list->id,
                    $list->create_time,
                    $list->title,
                    $encodeCustom($list->custom),
                    $board->id,
                ]);
                foreach ($list->cards as $card) {
                    if (!isset($card->title)) { continue; }     // skip deleted.
                    $push([
                        "card",
                        $card->id,
                        $card->create_time,
                        $card->title,
                        $encodeCustom($card->custom),
                        $list->id,
                        $card->create_user,
                        $card->change_time,
                        $card->related_name,
                        $card->color,
                        $card->description,
                        $card->due_time ?: "",
                        !!$card->archived,
                    ]);
                }
            }
        }

        return join($eol, $lines);
    }

    function boardCount() {
        return count($this->boards);
    }

    function isSingleBoard() {
        return $this->boardCount() === 1;
    }

    function filterCards(callable $func) {
        $cards = [];
        foreach ($this->boards as $board) {
            foreach ($board->lists as $list) {
                foreach ($list->cards as $card) {
                    if ($func($card, $list, $board)) {
                        $cards[] = [$card, $list, $board];
                    }
                }
            }
        }
        return $cards;
    }

    function findCard($id, &$list = null, &$board = null) {
        $found = $this->filterCards(function ($card) use ($id) {
            return $card->id === $id;
        });
        if (!$found) {
            throw new \OutOfRangeException("Unknown card $id.");
        }
        list($card, $list, $board) = $found[0];
        return $card;
    }
}

if (PHP_SAPI === "cli" && count(get_included_files()) === 1) {
    list(, $path, $secret, $boardID) = $argv + ["", "", "", ""];
    if (!is_file($path)) {
        echo "$path does not exist", PHP_EOL;
        exit(1);
    }
    $file = new SyncFile;
    $file->ignoreBadHash = true;
    $data = (new SyncData)->unserializeFileUsing($file, $path, $secret, $boardID);
    var_dump($data);
    fwrite(STDERR, "version: $file->version boards: ".$data->boardCount().PHP_EOL);
    fwrite(STDERR, "hash: ".bin2hex($file->hash)." $file->hashAlgorithm".PHP_EOL);
    fwrite(STDERR, "bad: ".($file->isBadHash ? "yes" : "no").PHP_EOL);
    if ($file->isEncrypted()) {
        fwrite(STDERR, "encrypt: $file->encryptAlgorithm iv: ".bin2hex($file->iv).PHP_EOL);
    }
}
