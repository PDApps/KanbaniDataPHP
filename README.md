# Kanbani data parsers for PHP

These scripts enable interop with [Kanbani](https://pdapps.org/kanbani) - a free task manager for Android. In particular, they are used in [Kanbani Web Viewer](https://pdapps.org/kanbani/web) - a simple Trello-like Kanbani board browser.

```
composer require pdapps/kanbani-data
```

## Requirements

- PHP 5.6 or 7.x
- `openssl` (if working with encrypted profiles)

## What's inside

Scripts are independent. You can include only those that you need.

### `sync.php` - sync data manipulation

Provides set of classes that allow reading and writing (unserializing and serializing) data produced by the Kanbani when doing sync (using any transport such as local file or WebDAV).

If the `openssl` PHP module is available, you can manipulate encrypted sync data as well as plain.

```PHP
// Creating a sync file from scratch:
$syncData = new Kanbani\SyncData;
$syncData->boards = [$board1, $board2, ...];
$syncData->serializeFile('foobar.kanbani');
// Or, encrypted:
$syncData->serializeFile('foobar.kanbani', "TheSecretString");

// Reading an existing sync file:
$syncData = new Kanbani\SyncData;
$syncData->unserializeFile('foobar.kanbani');
// Or, if encrypted:
$syncData->unserializeFile('foobar.kanbani', "TheSecretString", "sOmOzK...");
echo count($syncData->boards);

// Can also chain like so:
$syncData = (new Kanbani\SyncData($boards))
    ->serializeFile(...);

$syncData = (new Kanbani\SyncData)
    ->unserializeFile(...);
```

Under the hood, `SyncData` is using `SyncFile` - a class that doesn't know what exactly it is serializing, only that it is some string. You can use the two separately:

```PHP
// Get plain text JSON:
// {"sync_version": 1, "client_version": 1, "boards": [...]}
echo json_encode($syncData);

// Get CSV (to read back CSV use Kanbani Web Viewer's import plugin):
// board;agEi...P4F7;1577836800000;"Welcome Board";
echo $syncData->serializeToCSV();
```

Assuming that `$object` is in the format described [here](https://pdapps.org/kanbani/?lang=en#sync.html#json):
```PHP
// Creating a sync file from scratch:
$data = json_encode($object);
(new Kanbani\SyncFile)->serializeFile("foobar.kanbani", $data);

// Reading an existing sync file:
$sync = (new Kanbani\SyncFile)->unserializeFile("foobar.kanbani");
$object = json_decode($sync->data);

// Reading file info only (faster, doesn't parse the data):
$syncFile = (new Kanbani\SyncFile)->unserializeHeader(file_get_contents(...));
echo $syncFile->isEncrypted() ? "Encrypted data" : "Plain text";
```

#### Helper methods

`SyncFile` can generate Kanbani-compatible files names for encrypted boards:

```PHP
$syncFile = new Kanbani\SyncFile;
$syncFile->secret = "TheSecretString";
$syncFile->boardID = "sOmOzK...";
echo $syncFile->encryptedFileName(), ".kanbani";
```

`SyncData` can serialize (export) data in several other formats (it can't import them, see [Kanbani Web Viewer's import plugin for that](https://github.com/PDApps/KanbaniWebViewer/blob/master/plugins/import.php)):

```PHP
$syncData->serializeToJSON();       // plain text JSON
$syncData->serializeToCSV();        // CSV format similar to Trello
$syncData->serializeToExcelCSV();   // CSV compatible with MS Excel
```

#### Command line usage

Call `sync.php` directly from the command line to unserialize and dump a file (useful for debugging):

```
php sync.php Board.kanbani [secret board-id]
```

### `qrcode.php` - QR code data manipulation

Provides set of classes that represent Kanbani's sync profile data when encoded as a QR code for sharing with other devices. It identifies the transport, server location, encryption settings and so on.

Note: a QR code holds JSON data; these classes work on such data but they do not scan or generate QR code images - use libraries like [phpqrcode](https://github.com/t0k4rt/phpqrcode) for that.

Generating QR code data from scratch:
```PHP
$qrCode = new Kanbani\QrCodeData;
$qrCode->title = "Generated sync profile";

$baseURL = "https://deep.secret/kanbani/";
$auth = new Kanbani\QrCodePassword("PDApps", "4Ever!");
$qrCode->transport = new Kanbani\QrCodeSFTP($baseURL, $auth);

$data = json_encode($qrCode);

// $data can now be encoded as an image:
require_once "phpqrcode.php";
QRcode::png($data);
```

Parsing QR code data:
```PHP
$qrCode = new Kanbani\QrCodeData;
$qrCode->unserialize(json_decode($data));
echo $qrCode->title;
echo get_class($qrCode->transport);
```

#### Helper methods

Some `QrCodeWebTransport`s have `testConnection()` method that returns `null` on success or array `["id", "msg"]` (error identifier and human readable message) - useful for checking user input.

```PHP
$dav = new QrCodeWebDAV("https://dav.user.pdapps.org", null /*no auth*/);
$error = $dav->testConnection();
if ($error) {
    echo "Problem '$error[0]': $error[1]";
} else {
    echo "Connection test OK!";
}
```
