<?php
/* https://pdapps.org/kanbani/web | License: MIT */
namespace Kanbani;

class QrCodeException extends \Exception {}

abstract class QrCodeTransport implements \JsonSerializable {
    static function unserialize(\stdClass $obj) {
        foreach ([QrCodeFTP::class, QrCodeSFTP::class, QrCodeWebDAV::class] as $class) {
            if ($obj->t === $class::TYPE) {
                return new $class($obj->bU, QrCodeAuth::unserialize($obj));
            }
        }
        if ($obj->t === QRCodeLocalFile::TYPE) {
            return new QRCodeLocalFile($obj->lFP);
        }
        throw new QrCodeException("Invalid transport type $obj->t.");
    }
}

abstract class QrCodeWebTransport extends QrCodeTransport implements \JsonSerializable {
    public $baseURL;
    public $auth;

    function __construct($baseURL, QrCodeAuth $auth = null) {
        $this->baseURL = $baseURL;
        $this->auth = $auth;
    }

    function __clone() {
        if ($this->auth) {
            $this->auth = clone $this->auth;
        }
    }

    function jsonSerialize() {
        return [
            "t"     => static::TYPE,
            "bU"    => $this->baseURL,
        ] + ($this->auth ? $this->auth : new QrCodePassword("", ""))->jsonSerialize();
    }
}

class QrCodeFTP extends QrCodeWebTransport {
    const TYPE = "FTP";

    function testConnection() {
        if ($this->auth && !($this->auth instanceof QrCodePassword)) {
            return ["auth", "invalid auth method for FTP: ".get_class($this->auth)];
        }
        $url = parse_url($this->baseURL) + ["port" => 21, "path" => "."];
        try {
            $sock = fsockopen($url["host"], $url["port"], $errno, $errstr);
        } catch (\Throwable $e) {
            $errstr = $errstr ?: $e->getMessage();
        }
        if (empty($sock)) {
            return ["connect", $errstr];
        }
        try {
            $chat = [
                $this->auth ? "USER ".$this->auth->username : "USER anonymous",
                $this->auth ? "PASS ".$this->auth->password : "",
                "STAT $url[path]",
                "QUIT",
            ];
            fwrite($sock, join("\r\n", $chat)."\r\n");
            $response = stream_get_contents($sock);
        } catch (\Throwable $e) {
            return ["chat", $e->getMessage()];
        } finally {
            fclose($sock);
        }
        if (!preg_match('/^\s*drwx.+\.\s*$/m', $response)) {
            if (preg_match('/^213-Status/m', $response)) {
                return ["path", "base directory $url[path] does not exist"];
            }
            // Other error, such as incorrect username/password (530).
            $lines = explode("\n", $response);
            // Skip banner(s).
            while (!strncmp($lines[0] ?? "", "220", 3)) {
                array_shift($lines);
            }
            return ["chat", array_shift($lines)];
        }
    }
}

class QrCodeSFTP extends QrCodeWebTransport {
    const TYPE = "SFTP";

    // No testConnection() for SFTP since it requires calling an external tool
    // like `sftp` but not only that, it needs `sshpass` or other tools not
    // installed by default to test password-based auth (which is most common
    // in Kanbani).
}

class QrCodeWebDAV extends QrCodeWebTransport {
    const TYPE = "WebDAV";

    function testConnection(array $sslOptions = []) {
        if ($this->auth && !($this->auth instanceof QrCodePassword)) {
            return ["auth", "invalid auth method for WebDAV: ".get_class($this->auth)];
        }
        $headers = ["Depth: 0"];
        if ($this->auth) {
            $encoded = base64_encode($this->auth->username.":".$this->auth->password);
            $headers[] = "Authorization: Basic $encoded";
        }
        $context = stream_context_create([
            "http" => [
                "method" => "PROPFIND",
                "header" => $headers,
                "protocol_version" => 1.1,
            ],
            // verify_peer, etc.
            "ssl" => $sslOptions,
        ]);
        try {
            $xml = file_get_contents("$this->baseURL/", false, $context);
            // <lp1:resourcetype><D:collection/></lp1:resourcetype>
            if (!preg_match('!:resourcetype\b.+:collection\s*/>!u', $xml)) {
                return ["chat", "invalid response: ".preg_replace('/\s+/u', " ", strip_tags($xml))];
            }
        } catch (\Throwable $e) {
            return ["connect", $e->getMessage()];
        }
    }
}

class QrCodeLocalFile extends QrCodeTransport {
    const TYPE = "LocalFile";

    public $path;

    function __construct($path) {
        $this->path = $path;
    }

    function jsonSerialize() {
        return [
            "t"     => static::TYPE,
            "lFP"   => $this->path,
        ];
    }
}

abstract class QrCodeAuth implements \JsonSerializable {
    static function unserialize(\stdClass $obj) {
        $aM = isset($obj->aM) ? $obj->aM : null;
        switch ($aM) {
            default:
                throw new QrCodeException("Invalid auth type $aM.");
            case QrCodeSshKey::TYPE:
                return new QrCodeSshKey($obj->u, $obj->sPK);
            case QrCodePassword::TYPE:
                if (strlen($obj->u.$obj->p)) {
                    return new QrCodePassword($obj->u, $obj->p);
                }
            case null:
        }
    }
}

class QrCodePassword extends QrCodeAuth {
    const TYPE = "pass";

    public $username;
    public $password;

    function __construct($username, $password) {
        $this->username = $username;
        $this->password = $password;
    }

    function jsonSerialize() {
        return [
            "aM"    => static::TYPE,
            "u"     => $this->username,
            "p"     => $this->password,
        ];
    }
}

class QrCodeSshKey extends QrCodeAuth {
    const TYPE = "key";

    public $username;
    public $path;

    function __construct($username, $path) {
        $this->username = $username;
        $this->path = $path;
    }

    function jsonSerialize() {
        return [
            "aM"    => static::TYPE,
            "u"     => $this->username,
            "sPK"   => $this->path,
        ];
    }
}

class QrCodeBoard implements \JsonSerializable {
    public $id;
    public $title;

    // $obj is an object from QR code encoded data.
    static function unserialize(\stdClass $obj) {
        return new static($obj->i, $obj->n);
    }

    // $obj is an object in Kanbani sync format (not shared QR code).
    static function from(\stdClass $obj) {
        return new static($obj->id, $obj->title);
    }

    function __construct($id, $title) {
        $this->id = $id;
        $this->title = $title;
    }

    function jsonSerialize() {
        return [
            "i"     => $this->id,
            "n"     => $this->title,
        ];
    }
}

class QrCodeData implements \JsonSerializable {
    const VERSION = 1;

    // For $mode.
    const SYNC = "SYNC";
    const EXPORT = "BACKUP";
    const IMPORT = "COPY";

    // For $corruptedMode, $conflictMode.
    const MODE_CANCEL = "CANCEL";
    const MODE_ASK = "ASK";

    public $version = self::VERSION;
    public $id;             // profile ID.
    public $title = "Unnamed profile";
    public $mode = self::SYNC;
    public $corruptedMode = self::MODE_ASK;
    public $conflictMode = self::MODE_ASK;
    public $transport;
    public $boards = [];
    public $secret;
    public $hashAlgorithm = "SHA-256";
    public $encryptAlgorithm = "AES/CTR/PKCS5Padding";

    static function randomIdentifier($length = 32) {
        $func = function_exists("random_bytes") ? "random_bytes" : "openssl_random_pseudo_bytes";
        $s = base64_encode($func($length + 5));
        return substr(strtr($s, "/+", "Ka"), 0, $length);
    }

    function __construct() {
        $this->id = static::randomIdentifier();
    }

    function __clone() {
        if ($this->transport) {
            $this->transport = clone $this->transport;
        }
        $this->boards = array_map(function ($b) { return clone $b; }, $this->boards);
    }

    function jsonSerialize() {
        return [
            "kJV"       => $this->version,
            "i"         => $this->id,
            "n"         => $this->title,
            "m"         => $this->mode,
            "cM"        => $this->conflictMode,
            "crM"       => $this->corruptedMode,
            "tP"        => $this->transport,
            "b"         => $this->boards,
            "iE"        => strlen($this->secret) > 0,
            "s"         => (string) $this->secret,
            "hA"        => $this->hashAlgorithm,
            "eA"        => $this->encryptAlgorithm,
            // "Add new boards" flag.
            "aNB"       => false,
            // If 0, disable automatic sync. If 1, is sync interval in minutes.
            "sT"        => 15,
            // Sync by file change.
            "cBF"       => "",
        ];
    }

    function serialize($flags = 0) {
        return json_encode($this, $flags | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    function unserialize(\stdClass $obj) {
        $this->version = $obj->kJV;
        $this->id = $obj->i;
        $this->title = $obj->n;
        $this->mode = $obj->m;
        $this->conflictMode = $obj->cM;
        $this->corruptedMode = $obj->crM;
        $this->transport = QrCodeTransport::unserialize($obj->tP);
        $this->boards = array_map([QrCodeBoard::class, "unserialize"], $obj->b);
        $this->secret = $obj->iE ? $obj->s : null;
        $this->hashAlgorithm = $obj->hA;
        $this->encryptAlgorithm = $obj->eA;
        return $this;
    }
}
