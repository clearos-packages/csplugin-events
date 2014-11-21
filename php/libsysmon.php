<?php

define('csSMOC_NULL', 0);
define('csSMOC_VERSION', 1);
define('csSMOC_ALERT_INSERT', 2);
define('csSMOC_RESULT', 3);

define('csSMPR_OK', 0);
define('csSMPR_VERSION_MISMATCH', 1);

define('csAF_NULL', 0);
define('csAF_LVL_NORM', 0x00000001);
define('csAF_LVL_WARN', 0x00000002);
define('csAF_LVL_CRIT', 0x00000004);
define('csAF_FLG_PERSIST', 0x00000100);
define('csAF_FLG_READ', 0x00000200);
define('csAF_MAX', 0xffffffff);

define('csAT_NULL', 0);

define('csSYSMON_PROTOVER', 0x20141112);

class libSysMonAlert
{
    protected $id;
    protected $stamp;
    protected $flags;
    protected $type;
    protected $user;
    protected $groups;
    protected $uuid;
    protected $icon;
    protected $description;

    public function __construct()
    {
        $this->reset();
    }

    public function reset()
    {
        $this->id = 0;
        $this->stamp = time();
        $this->flags = csAF_NULL;
        $this->type = csAT_NULL;
        $this->user = posix_getuid();
        $this->groups = array();
        $this->uuid = null;
        $this->icon = null;
        $this->desc = null;
    }

    public function get_id()
    {
        return $this->id;
    }

    public function get_stamp()
    {
        return $this->stamp;
    }

    public function get_flags()
    {
        return $this->flags;
    }

    public function get_type()
    {
        return $this->type;
    }

    public function get_user()
    {
        return $this->user;
    }

    public function get_groups()
    {
        return $this->groups;
    }

    public function get_uuid()
    {
        return $this->uuid;
    }

    public function get_icon()
    {
        return $this->icon;
    }

    public function get_description()
    {
        return $this->desc;
    }

    public function set_id($id)
    {
        $this->id = $id;
    }

    public function set_stamp($stamp = null)
    {
        if ($stamp === null)
            $this->stamp = time();
        else
            $this->stamp = $stamp;
    }

    public function set_flags($flags)
    {
        $this->flags = $flags;
    }

    public function set_flag($flag)
    {
        $this->flags |= $flag;
    }

    public function clear_flag($flag)
    {
        $this->flag &= ~$flag;
    }

    public function set_type($type)
    {
        $this->type = $type;
    }

    public function set_user($user)
    {
        if (is_string($user)) {
            $pwent = posix_getpwnam($user);
            if ($pwent !== null)
                $this->user = $pwent['uid'];
        }
        else $this->user = $user;
    }

    public function add_group($group)
    {
        if (is_string($group)) {
            $grent = posix_getgrnam($group);
            if ($grent !== null)
                $this->groups[] = $grent['gid'];
        }
        else $this->groups[] = $group;
    }

    public function clear_groups()
    {
        $this->groups = array();
    }

    public function set_uuid($uuid)
    {
        $this->uuid = $uuid;
    }

    public function set_icon($icon)
    {
        $this->icon = $icon;
    }

    public function set_description($desc)
    {
        $this->desc = $desc;
    }
}

class libSysMonitor
{
    const PATH_SOCKET = '/tmp/sysmonctl.socket';

    protected $sd;
    protected $socket_path;
    protected $header;
    protected $payload;
    protected $payload_index;

    public function __construct($socket_path = self::PATH_SOCKET)
    {
        $this->sd = socket_create(AF_UNIX, SOCK_STREAM, 0);
        if (! is_resource($this->sd))
            throw new Exception(socket_strerror(socket_last_error()));
        $this->socket_path = $socket_path;

        $this->reset_packet();
    }

    public function __destruct()
    {
        if (is_resource($this->sd)) socket_close($this->sd);
    }

    public function connect()
    {
        if (socket_connect($this->sd, $this->socket_path) === false)
            throw new Exception(socket_strerror(socket_last_error($this->sd)));
        $this->version_exchange();
    }

    public function send_alert($alert)
    {
        $this->reset_packet();
        $this->write_packet_alert($alert);
        $this->write_packet(csSMOC_ALERT_INSERT);
    }

    protected function version_exchange()
    {
        $this->reset_packet();
        $this->write_packet_var(csSYSMON_PROTOVER, 'L', 4);
        $this->write_packet(csSMOC_VERSION);

        if ($this->read_result() != csSMPR_OK) {
            throw new Exception(
                'Unexpected result code: ' + $this->header['opcode']
            );
        }
    }

    protected function reset_packet()
    {
        $this->header = array('opcode' => csSMOC_NULL, 'payload_length' => 0);
        $this->payload = null;
        $this->payload_index = 0;
    }

    protected function read_packet_var(&$v, $format, $length)
    {
        $u = unpack(
            $format,
            substr($this->payload, $this->payload_index, $length)
        );
        $v = $u[1];
        $this->payload_index += $length;
    }

    protected function read_packet_string(&$v)
    {
        $u = unpack(
            'L',
            substr($this->payload, $this->payload_index, 4)
        );
        $length = $u[1];
        $this->payload_index += 4;
        if ($length == 0) $v = '';
        else {
            $v = substr($this->payload, $this->payload_index, $length);
            $this->payload_index += $length;
        }
    }

    protected function read_packet_alert(&$v)
    {
        $v->reset();

        $u = unpack(
            'N2',
            substr($this->payload, $this->payload_index, 8)
        );
        $v->set_id($u[1] << 32 | $u[2]);
        $this->payload_index += 8;

        $this->read_packet_var($u, 'L', 4);
        $v->set_stamp($u);

        $this->read_packet_var($u, 'L', 4);
        $v->set_flags($u);

        $this->read_packet_var($u, 'L', 4);
        $v->set_type($u);

        $this->read_packet_var($u, 'L', 4);
        $v->set_user($u);

        $this->read_packet_var($u, 'L', 4);

        for ($i = 0; $i < $u; $i++) {
            $g = null;
            $this->read_packet_var($g, 'L', 4);
            $v->add_group($g);
        }

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_uuid($u);

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_icon($u);

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_description($u);
    }

    protected function write_packet_var($v, $format, $length)
    {
        $this->payload .= pack($format, $v);
        $this->payload_length += $length;
        $this->header['payload_length'] += $length;
    }

    protected function write_packet_string($v)
    {
        $this->payload .= pack('L', strlen($v));
        $this->header['payload_length'] += 4;
        if (strlen($v) > 0) {
            $this->payload .= $v;
            $this->header['payload_length'] += strlen($v);
        }
    }

    protected function write_packet_alert($v)
    {
        $hi = ($v->get_id() & 0xffffffff00000000) >> 32;
        $lo =  $v->get_id() & 0x00000000ffffffff;

        $this->payload .= pack('NN', $hi, $lo);
        $this->header['payload_length'] += 8;

        $this->write_packet_var($v->get_stamp(), 'L', 4);
        $this->write_packet_var($v->get_flags(), 'L', 4);
        $this->write_packet_var($v->get_type(), 'L', 4);
        $this->write_packet_var($v->get_user(), 'L', 4);

        $groups = $v->get_groups();
        $this->write_packet_var(count($groups), 'L', 4);
        foreach ($groups as $group)
            $this->write_packet_var($group, 'L', 4);

        $this->write_packet_string($v->get_uuid());
        $this->write_packet_string($v->get_icon());
        $this->write_packet_string($v->get_description());
    }

    protected function read_packet()
    {
        $this->reset_packet();
        $buffer = socket_read($this->sd, 5);

        $u = unpack('C', substr($buffer, 0, 1));
        $this->header['opcode'] = $u[1];

        $u = unpack('L', substr($buffer, 1, 4));
        $this->header['payload_length'] = $u[1];

        if ($this->header['payload_length'] == 0)
            $this->payload = null;
        else {
            $this->payload = socket_read(
                $this->sd,
                $this->header['payload_length']
            );
        }

        return $this->header['opcode'];
    }

    protected function write_packet($opcode)
    {
        $this->header['opcode'] = $opcode;
        $buffer = pack('C', $this->header['opcode']);
        $buffer .= pack('L', $this->header['payload_length']);
        if ($this->header['payload_length'] > 0)
            $buffer .= $this->payload;

        socket_write($this->sd, $buffer);
    }

    protected function read_result()
    {
        $this->read_packet();
        if ($this->header['opcode'] != csSMOC_RESULT)
            throw new Exception('Unexpected protocol op-code');
        if ($this->header['payload_length'] != 4)
            throw new Exception('Unexpected payload length');
        $u = unpack('L', substr($this->payload, 0, 4));
        return $u[1];
    }

    protected function write_result($result)
    {
        $this->reset_packet();
        $this->write_packet_var($result, 'L', 4);
        $this->write_packet(csSMOC_RESULT);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
