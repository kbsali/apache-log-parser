# Web server access Log Parser

[![Build Status](https://travis-ci.org/kassner/apache-log-parser.png?branch=master)](https://travis-ci.org/kassner/apache-log-parser)

## Install

Using composer:

```
php composer.phar require kassner/apache-log-parser:dev-master
```

## Usage

Simply instantiate the class :

```php
$parser = new \Kassner\ApacheLogParser\ApacheLogParser();
```

And then parse the lines of your access log file :

```php
$lines = file('/var/log/apache2/access.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
foreach ($lines as $line) {
    $entry = $parser->parse($line);
}
```

Where `$entry` object will hold all data parsed.

```php
stdClass Object
(
    [host] => 193.191.216.76
    [logname] => -
    [user] => www-data
    [stamp] => 1390794676
    [time] => 27/Jan/2014:04:51:16 +0100
    [request] => GET /wp-content/uploads/2013/11/whatever.jpg HTTP/1.1
    [status] => 200
    [responseBytes] => 58678
)
```

You may customize the log format (by default it matches the [Apache common log format](https://httpd.apache.org/docs/2.2/en/logs.html#common))

```php
# default Nginx format :
$parser->setFormat('%h %l %u %t "%r" %>s %O "%{Referer}i" \"%{User-Agent}i"');
```

## Supported format strings

Here is the full list of [log format strings](https://httpd.apache.org/docs/2.2/en/mod/mod_log_config.html#formats) supported by Apache, and whether they are supported by the library :

| Supported? | Format String | Property name | Description |
|:----------:|:-------------:|---------------|-------------|
| Y | %% | percent |The percent sign |
| Y | %A | localIp |Local IP-address |
| Y | %a | remoteIp |Remote IP-address |
| Y | %B | responseBytes |Size of response in bytes, excluding HTTP headers. |
| Y | %b | responseBytes |Size of response in bytes, excluding HTTP headers. In CLF format, i.e. a '-' rather than a 0 when no bytes are sent. |
| Y | %D | responseTime | The time taken to serve the request, in microseconds. |
| Y | %f | filename | Filename |
| Y | %h | host |Remote host |
| N | %H | protocol |The request protocol |
| Y | %I | receivedBytes | Bytes received, including request and headers, cannot be zero. You need to enable mod_logio to use this. |
| Y | %k | keepAliveRequests | Number of keepalive requests handled on this connection. Interesting if KeepAlive is being used, so that, for example, a '1' means the first keepalive request after the initial one, '2' the second, etc...; otherwise this is always 0 (Y indicating the initial request). Available in versions 2.2.11 and later. |
| Y | %l | logname | Remote logname (from identd, if supplied). This will return a dash unless mod_ident is present and IdentityCheck is set On. |
| Y | %m | requestMethod | The request method |
| Y | %O | sentBytes | Bytes sent, including headers, cannot be zero. You need to enable mod_logio to use this. |
| Y | %p | port | The canonical port of the server serving the request |
| Y | %P | PID | The process ID of the child that serviced the request. |
| N | %q | queryString | The query string (prepended with a ? if a query string exists, otherwise an empty string) |
| Y | %r | request | First line of request |
| N | %R | handler | The handler generating the response (if any). |
| Y | %s | originalStatus | Status. For requests that got internally redirected, this is the status of the *original* request --- %>s for the last. |
| Y | %>s | status |status |
| Y | %T | timeRequestServed | The time taken to serve the request, in seconds. |
| Y | %t | time | Time the request was received (standard english format) |
| Y | %u | user | Remote user (from auth; may be bogus if return status (%s) is 401) |
| Y | %U | URL | The URL path requested, not including any query string. |
| Y | %v | serverName | The canonical ServerName of the server serving the request. |
| Y | %V | canonicalServerName | The server name according to the UseCanonicalName setting. |
| Y | %X | connectionStatus | Connection status when response is completed: X = connection aborted before the response completed. + = connection may be kept alive after the response is sent. - = connection will be closed after the response is sent. |
| Y | %{Foobar}C | *Cookie | The contents of cookie Foobar in the request sent to the server. Only version 0 cookies are fully supported. |
| Y | %{FOOBAR}e | *Env | The contents of the environment variable FOOBAR |
| Y | %{Foobar}i | *Header | The contents of Foobar: header line(s) in the request sent to the server. Changes made by other modules (e.g. mod_headers) affect this. If you're interested in what the request header was prior to when most modules would have modified it, use mod_setenvif to copy the header into an internal environment variable and log that value with the %{VARNAME}e described above. |
| N | %{Foobar}n | *Note | The contents of note Foobar from another module. |
| N | %{Foobar}o | *Headers | The contents of Foobar: header line(s) in the reply. |
| N | %{format}p | *Port | The canonical port of the server serving the request or the server's actual port or the client's actual port. Valid formats are canonical, local, or remote. |
| N | %{format}P | *PID | The process ID or thread id of the child that serviced the request. Valid formats are pid, tid, and hextid. hextid requires APR 1.2.0 or higher. |
| N | %{format}t | *Time | The time, in the form given by format, which should be in strftime(3) format. (potentially localized) (This directive was %c in late versions of Apache 1.3, but this conflicted with the historical ssl %{var}c syntax.) |

## Exceptions

If a line does not match with the defined format, an `\Kassner\ApacheLogParser\FormatException` will be thrown.
