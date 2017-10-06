<?php

class SSHAgent
{
    const SSH_AGENT_FAILURE                         = 5;
    const SSH_AGENT_SUCCESS                         = 6;
    const SSH_AGENT_IDENTITIES_ANSWER               = 12;
    const SSH_AGENT_SIGN_RESPONSE                   = 14;
    const SSH_AGENT_EXTENSION_FAILURE               = 28;

    const SSH_AGENTC_REQUEST_IDENTITIES             = 11;
    const SSH_AGENTC_SIGN_REQUEST                   = 13;
    const SSH_AGENTC_ADD_IDENTITY                   = 17;
    const SSH_AGENTC_REMOVE_IDENTITY                = 18;
    const SSH_AGENTC_REMOVE_ALL_IDENTITIES          = 19;
    const SSH_AGENTC_ADD_SMARTCARD_KEY              = 20;
    const SSH_AGENTC_REMOVE_SMARTCARD_KEY           = 21;
    const SSH_AGENTC_LOCK                           = 22;
    const SSH_AGENTC_UNLOCK                         = 23;
    const SSH_AGENTC_ADD_ID_CONSTRAINED             = 25;
    const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED  = 26;
    const SSH_AGENTC_EXTENSION                      = 27;

    protected $socket;
    protected $identities = [];

    public function __construct($socket)
    {
        $this->socket = $socket;
    }

    public function addIdentity($comment, $pem)
    {
        $this->identities[$comment] = $pem;
    }

    protected function failure()
    {
        return pack('C', self::SSH_AGENT_FAILURE);
    }

    protected function success()
    {
        return pack('C', self::SSH_AGENT_SUCCESS);
    }

    protected function pack($string)
    {
        return pack('N', strlen($string)) . $string;
    }

    protected function identities()
    {
        echo "Identities requested, we have " . count($this->identities) . "\n";

        $ret = pack('CN', self::SSH_AGENT_IDENTITIES_ANSWER, count($this->identities));

        foreach ($this->identities as $comment => $pem) {
            $privateKey = openssl_pkey_get_private($pem);
            $publicKey = openssl_pkey_get_public(openssl_pkey_get_details($privateKey)['key']);
            $rsa = openssl_pkey_get_details($publicKey)['rsa'];

            $keyType = 'ssh-rsa';

            $ret .= $this->pack(
                        $this->pack($keyType)
                        . $this->pack($rsa['e'])
                        . $this->pack("\0" . $rsa['n'])
                    )
                    . $this->pack($comment);
        }

        return $ret;
    }

    protected function sign($raw)
    {
        echo "Sign requested\n";

        $keyLength = unpack('N', substr($raw, 1))[1];
        $key = substr($raw, 1 + 4, $keyLength);
        $dataLength = unpack('N', substr($raw, 1 + 4 + $keyLength))[1];
        $data = substr($raw, 1 + 4 + $keyLength + 4, $dataLength);
        $flags = unpack('N', substr($raw, 1 + 4 + $keyLength + 4 + $dataLength))[1];

        foreach ($this->identities as $comment => $pem) {
            $privateKey = openssl_pkey_get_private($pem);
            $publicKey = openssl_pkey_get_public(openssl_pkey_get_details($privateKey)['key']);
            $rsa = openssl_pkey_get_details($publicKey)['rsa'];

            $cmp = $this->pack('ssh-rsa') . $this->pack($rsa['e']) . $this->pack("\0" . $rsa['n']);

            if ($key !== $cmp)
                continue;

            $signature = null;
            openssl_sign($data, $signature, $privateKey);

            return pack('C', self::SSH_AGENT_SIGN_RESPONSE) . $this->pack($this->pack('ssh-rsa') . $this->pack($signature));
        }

        return pack('C', self::SSH_AGENT_FAILURE);
    }

    protected function read()
    {
        $data = socket_read($this->socket, 4);
        if ($data === false || strlen($data) === 0)
            return false;

        $length = unpack('N', $data)[1];
        return socket_read($this->socket, $length);
    }

    protected function write($message)
    {
        socket_write($this->socket, pack('N', strlen($message)) . $message);
    }

    public function handle()
    {
        while (($data = $this->read()) !== false)
        {
            $type = unpack('C', $data)[1];

            switch ($type)
            {
                // undocumented protocol 1 identities
                case 1:
                    $this->write(pack('CN', 2, 0));
                    break;

                case self::SSH_AGENTC_REQUEST_IDENTITIES:
                    $this->write($this->identities());
                    break;

                case self::SSH_AGENTC_SIGN_REQUEST:
                    $this->write($this->sign($data));
                    break;

                default:
                    printf("Unknown request type $type\n");
                    $this->write($this->failure());
            }
        }

        socket_close($this->socket);
    }
}

class KeePassHTTP
{
    protected $key;
    protected $id = false;

    public function __construct()
    {
        $this->key = str_repeat('A', 32); // FIXME: static testing key
        $this->id = 'keepassxc-agent'; // FIXME: static test id
    }

    protected function request($data)
    {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));

        foreach ($data as $k => $v) {
            if (in_array($k, ['RequestType', 'SortSelection', 'TriggerUnlock', 'Id', 'Key']))
                continue;

            $data[$k] = base64_encode(openssl_encrypt($v, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv));
        }

        $data['Nonce'] = base64_encode($iv);
        $data['Verifier'] = base64_encode(openssl_encrypt($data['Nonce'], 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv));

        if ($this->id)
            $data['Id'] = $this->id;

        $ctx = stream_context_create([
            'http' => [
                'method'    => 'POST',
                'header'    => 'Content-Type: application/json',
                'content'   => json_encode($data),
            ]
        ]);

        $raw = @file_get_contents('http://localhost:19455', false, $ctx);

        if ($raw !== false)
            return json_decode($raw, true);

        return false;
    }

    public function testAssociate()
    {
        $ret = $this->request([
            'RequestType'   => 'test-associate',
            'TriggerUnlock' => 'false',
        ]);

        return !empty($ret['Success']);
    }

    public function associate()
    {
        $ret = $this->request([
            'RequestType' => 'associate',
            'Key' => base64_encode($this->key),
        ]);

        return !empty($ret['Success']);
    }

    protected function decrypt($data, $nonce)
    {
        return openssl_decrypt(base64_decode($data), 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, base64_decode($nonce));
    }

    public function getLogins()
    {
        $ret = $this->request([
            'RequestType'   => 'get-logins',
            'SortSelection' => 'false',
            'TriggerUnlock' => 'true',
            'Url'           => 'https://ssh-private-key',
        ]);

        $ids = [];

        if (empty($ret['Entries']))
            return $ids;

        foreach ($ret['Entries'] as $entry) {
            $name = $this->decrypt($entry['Name'], $ret['Nonce']);
            foreach ($entry['StringFields'] as $field) {
                $key = $this->decrypt($field['Key'], $ret['Nonce']);
                if ($key == 'KPH: id_rsa') {
                    $value = $this->decrypt($field['Value'], $ret['Nonce']);
                    $ids[$name] = $value;
                }
            }
        }

        return $ids;
    }
}

@unlink('/tmp/agent.sock');
$listen = socket_create(AF_UNIX, SOCK_STREAM, 0);
socket_bind($listen, '/tmp/agent.sock');
socket_listen($listen);

while (true) {
    $socket = socket_accept($listen);

    echo "Connected.\n";

    $agent = new SSHAgent($socket);

    $kph = new KeePassHTTP;

    if (!$kph->testAssociate()) {
        $kph->associate();
    }

    foreach ($kph->getLogins() as $comment => $pem) {
        $agent->addIdentity($comment, $pem);
    }

    $agent->handle();

    echo "Connection closed.\n";
}

socket_close($listen);
@unlink('/tmp/agent.sock');
