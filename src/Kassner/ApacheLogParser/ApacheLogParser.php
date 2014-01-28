<?php

namespace Kassner\ApacheLogParser;

class ApacheLogParser
{
    private $pcreFormat, $patterns = array(
        '%%'  => '(?P<percent>\%)',
        '%A'  => '(?P<localIp>(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
        '%a'  => '(?P<remoteIp>(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
        '%B'  => '(?P<responseBytes>(\d+))',
        '%b'  => '(?P<responseBytes>(\d+|-))',
        '%D'  => '(?P<responseTime>(\d+))',
        '%f'  => '(?P<filename>[a-zA-Z0-9\-\._:]+)',
        '%h'  => '(?P<host>[a-zA-Z0-9\-\._:]+)',
        // '%H'  => '(?P<protocol>[a-zA-Z0-9\-\._:]+)',
        '%I'  => '(?P<receivedBytes>(\d+))',
        '%k'  => '(?P<keepAliveRequests>[a-zA-Z0-9]+)',
        '%l'  => '(?P<logname>(?:-|[\w-]+))',
        '%m'  => '(?P<requestMethod>OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)',
        '%O'  => '(?P<sentBytes>(\d+))',
        '%p'  => '(?P<port>\d+)',
        '%P'  => '(?P<PID>\d+)',
        // '%q'  => '(?P<queryString>(?:-|[\w-]+))',
        '%r'  => '(?P<request>(?:(?:[A-Z]+) .+? HTTP/1.(?:0|1))|-|)',
        // '%R'  => '(?P<handler>(?:-|[\w-]+))',
        '%s'  => '(?P<originalStatus>\d{3}|-)',
        '%>s' => '(?P<status>\d{3}|-)', // last status
        '%t'  => '\[(?P<time>\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} (?:-|\+)\d{4})\]',
        '%T'  => '(?P<timeRequestServed>(\d+))',
        '%U'  => '(?P<URL>.+?)',
        '%u'  => '(?P<user>(?:-|[\w-]+))',
        '%V'  => '(?P<canonicalServerName>([a-zA-Z0-9]+)([a-z0-9.-]*))',
        '%v'  => '(?P<serverName>([a-zA-Z0-9]+)([a-z0-9.-]*))',
        '%X'  => '(?P<connectionStatus>(X|+|-)',
        '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}C' => '(?P<Cookie\\1\\3>.*?)',
        '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}e' => '(?P<Env\\1\\3>.*?)',
        '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}i' => '(?P<Header\\1\\3>.*?)',
        // '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}n' => '(?P<Note\\1\\3>.*?)',
        // '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}o' => '(?P<Headers\\1\\3>.*?)',
        // '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}p' => '(?P<Port\\1\\3>.*?)',
        // '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}P' => '(?P<PID\\1\\3>.*?)',
        // '\%\{(?P<name>[a-zA-Z]+)(?P<name2>[-]?)(?P<name3>[a-zA-Z]+)\}t' => '(?P<Time\\1\\3>.*?)',
    );

    public function __construct($format = '%h %l %u %t "%r" %>s %b')
    {
        $this->setFormat($format);
    }

    public function setFormat($format)
    {
        // strtr won't work for "complex" header patterns
        // $this->pcreFormat = strtr("#^{$format}$#", $this->patterns);
        $this->pcreFormat = "#^{$format}$#";
        foreach ($this->patterns as $pattern => $replace) {
            $this->pcreFormat = preg_replace("/{$pattern}/", $replace, $this->pcreFormat);
        }
    }

    public function parse($line)
    {
        if (!preg_match($this->pcreFormat, $line, $matches)) {
            throw new FormatException($line);
        }
        $entry = new \stdClass();
        foreach (array_filter(array_keys($matches), 'is_string') as $key) {
            $entry->{$key} = $matches[$key];
            if ('time' === $key && true !== $stamp = strtotime($matches[$key])) {
                $entry->stamp = $stamp;
            }
            if ('request' === $key) {
                list($entry->method, $entry->path, $entry->protocol) = explode(' ', $entry->request);
            }
        }

        return $entry;
    }

    public function getPCRE()
    {
        return (string) $this->pcreFormat;
    }
}
