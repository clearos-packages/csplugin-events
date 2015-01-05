<?php

define('csSMOC_NULL', 0);
define('csSMOC_VERSION', 1);
define('csSMOC_ALERT_INSERT', 2);
define('csSMOC_ALERT_SELECT', 3);
define('csSMOC_ALERT_MARK_AS_READ', 4);
define('csSMOC_ALERT_RECORD', 5);
define('csSMOC_RESULT', 0xFF);

define('csSMPR_OK', 0);
define('csSMPR_VERSION_MISMATCH', 1);
define('csSMPR_ALERT_MATCHES', 2);

define('csAF_NULL', 0);
define('csAF_LVL_NORM', 0x00000001);
define('csAF_LVL_WARN', 0x00000002);
define('csAF_LVL_CRIT', 0x00000004);
define('csAF_FLG_PERSIST', 0x00000100);
define('csAF_FLG_READ', 0x00000200);
define('csAF_MAX', 0xFFFFFFFF);

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
    protected $desc;

    protected static $field_sizes;

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

    public static function init_field_sizes()
    {
        self::$field_sizes = array(
            'id' => array('format' => 'LL', 'size' => 8),
            'stamp' => array('format' => 'L', 'size' => 4),
            'flags' => array('format' => 'L', 'size' => 4),
            'type' => array('format' => 'L', 'size' => 4),
            'user' => array('format' => 'L', 'size' => 4),
            'group' => array('format' => 'L', 'size' => 4),
            'groups' => array('format' => 'C', 'size' => 1),
            'string' => array('format' => 'C', 'size' => 1),
            'version' => array('format' => 'L', 'size' => 4),
            'result' => array('format' => 'C', 'size' => 1),
            'matches' => array('format' => 'L', 'size' => 4),
        );
    }

    public static function get_field_format($field)
    {
        if (! array_key_exists($field, self::$field_sizes))
            throw new Exception("Unknown field name: $field");
        return self::$field_sizes[$field]['format'];
    }

    public static function get_field_length($field)
    {
        if (! array_key_exists($field, self::$field_sizes))
            throw new Exception("Unknown field name: $field");
        return self::$field_sizes[$field]['size'];
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

libSysMonAlert::init_field_sizes();

class libSysMonitor
{
    const PATH_SOCKET = '/tmp/sysmonctl.socket';
    const FILE_CONFIG = '/etc/clearsync.d/csplugin-sysmon.conf';

    protected $sd;
    protected $socket_path;
    protected $header;
    protected $header_field_sizes;
    protected $payload;
    protected $payload_index;
    protected $alert_type_map;

    public function __construct($socket_path = self::PATH_SOCKET)
    {
        $this->header_field_sizes = array(
            'opcode' => array('format' => 'C', 'size' => 1),
            'payload_length' => array('format' => 'L', 'size' => 4),
            'result' => array('format' => 'C', 'size' => 1),
        );

        $this->sd = socket_create(AF_UNIX, SOCK_STREAM, 0);
        if (! is_resource($this->sd))
            throw new Exception(socket_strerror(socket_last_error()));
        $this->socket_path = $socket_path;

        $this->reset_packet();

        $xml_source = file_get_contents(self::FILE_CONFIG);
        if ($xml_source === false)
            throw new Exception('Configuration not found: ' . self::FILE_CONFIG);

        $xml_config = simplexml_load_string($xml_source);
        if ($xml_config === false)
            throw new Exception('Error parsing configuration: ' . self::FILE_CONFIG);

        $this->alert_type_map = array();
        foreach ($xml_config->types->type as $i => $type) {
            $id = $type['id'][0];
            $name = $type['type'][0];
            $this->alert_type_map["$id"] = sprintf('%s', $name);
        }
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

    public function get_type_id($name)
    {
        return array_search($name, $this->alert_type_map);
    }

    public function get_type_name($id)
    {
        if (! array_key_exists($id, $this->alert_type_map)) return false;
        return $this->alert_type_map[$id];
    }

    public function send_alert($alert)
    {
        $this->reset_packet();
        $this->write_packet_alert($alert);
        $this->write_packet(csSMOC_ALERT_INSERT);
    }

    public function get_alerts($where = 'ORDER BY stamp')
    {
        $this->reset_packet();
        $this->write_packet_string($where);
        $this->write_packet(csSMOC_ALERT_SELECT);

        if ($this->read_result() != csSMPR_ALERT_MATCHES) {
            throw new Exception(
                'Unexpected result code: ' . $this->header['opcode']
            );
        }

        $alerts = array();
        $this->read_packet_var($matches, 'matches');

        for ($i = 0; $i < $matches; $i++) {
            if ($this->read_packet() != csSMOC_ALERT_RECORD) {
                throw new Exception(
                    'Unexpected op-code: ' . $this->header['opcode']
                );
            }
            $alert = new libSysMonAlert();
            $this->read_packet_alert($alert);
            $alerts[] = $alert;
        }

        return $alerts;
    }

    public function mark_as_read($id)
    {
        $this->reset_packet();
        $this->write_packet_var($id, 'id');
        $this->write_packet(csSMOC_ALERT_MARK_AS_READ);
    }

    protected function get_header_length($field)
    {
        if (! array_key_exists($field, $this->header_field_sizes))
            throw new Exception("Unknown header field: $field");
        return $this->header_field_sizes[$field]['size'];
    }

    protected function get_header_format($field)
    {
        if (! array_key_exists($field, $this->header_field_sizes))
            throw new Exception("Unknown header field: $field");
        return $this->header_field_sizes[$field]['format'];
    }

    protected function version_exchange()
    {
        $this->reset_packet();
        $this->write_packet_var(csSYSMON_PROTOVER, 'version');
        $this->write_packet(csSMOC_VERSION);

        if ($this->read_result() != csSMPR_OK) {
            throw new Exception(
                'Unexpected result code: ' . $this->header['opcode']
            );
        }
    }

    protected function reset_packet()
    {
        $this->header = array('opcode' => csSMOC_NULL, 'payload_length' => 0);
        $this->payload = null;
        $this->payload_index = 0;
    }

    protected function read_packet_var(&$v, $field)
    {
        $format = libSysMonAlert::get_field_format($field);
        $length = libSysMonAlert::get_field_length($field);

        $u = unpack(
            $format,
            substr($this->payload, $this->payload_index, $length)
        );
        $v = $u[1];
        $this->payload_index += $length;
    }

    protected function read_packet_string(&$v)
    {
        $format = libSysMonAlert::get_field_format('string');
        $length = libSysMonAlert::get_field_length('string');

        $u = unpack(
            $format,
            substr($this->payload, $this->payload_index, $length)
        );
        $this->payload_index += $length;

        $length = $u[1];
        if ($length == 0) $v = '';
        else {
            $v = substr($this->payload, $this->payload_index, $length);
            $this->payload_index += $length;
        }
    }

    protected function read_packet_alert(&$v)
    {
        $v->reset();

        $format = libSysMonAlert::get_field_format('id');
        $length = libSysMonAlert::get_field_length('id');

        $u = unpack(
            'L2',
            substr($this->payload, $this->payload_index, $length)
        );
        //$v->set_id($u[1] << 32 | $u[2]);
        $v->set_id($u[1] | $u[2]);
        $this->payload_index += $length;

        $this->read_packet_var($u, 'stamp');
        $v->set_stamp($u);

        $this->read_packet_var($u, 'flags');
        $v->set_flags($u);

        $this->read_packet_var($u, 'type');
        $v->set_type($u);

        $this->read_packet_var($u, 'user');
        $v->set_user($u);

        $this->read_packet_var($u, 'groups');

        for ($i = 0; $i < $u; $i++) {
            $g = null;
            $this->read_packet_var($g, 'group');
            $v->add_group($g);
        }

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_uuid($u);

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_icon($u);

        $this->read_packet_string($u);
        if (strlen($u)) $v->set_description($u);
    }

    protected function write_packet_var($v, $field)
    {
        $format = libSysMonAlert::get_field_format($field);
        $length = libSysMonAlert::get_field_length($field);

        if ($length == 8) {
            $hi =  $v & 0x00000000ffffffff;
            $lo = ($v & 0xffffffff00000000) >> 32;
            //$hi = ($v & 0xffffffff00000000) >> 32;
            //$lo =  $v & 0x00000000ffffffff;
        
            $this->payload .= pack($format, $hi, $lo);
        }
        else
            $this->payload .= pack($format, $v);

        $this->payload_length += $length;
        $this->header['payload_length'] += $length;
    }

    protected function write_packet_string($v)
    {
        $format = libSysMonAlert::get_field_format('string');
        $length = libSysMonAlert::get_field_length('string');

        $this->payload .= pack($format, strlen($v));
        $this->header['payload_length'] += $length;
        if (strlen($v) > 0) {
            $this->payload .= $v;
            $this->header['payload_length'] += strlen($v);
        }
    }

    protected function write_packet_alert($v)
    {
        $this->write_packet_var($v->get_id(), 'id');
        $this->write_packet_var($v->get_stamp(), 'stamp');
        $this->write_packet_var($v->get_flags(), 'flags');
        $this->write_packet_var($v->get_type(), 'type');
        $this->write_packet_var($v->get_user(), 'user');

        $groups = $v->get_groups();
        $this->write_packet_var(count($groups), 'groups');
        foreach ($groups as $group)
            $this->write_packet_var($group, 'group');

        $this->write_packet_string($v->get_uuid());
        $this->write_packet_string($v->get_icon());
        $this->write_packet_string($v->get_description());
    }

    protected function read_packet()
    {
        $this->reset_packet();
        $buffer = socket_read($this->sd, 5);

        $offset = 0;
        $format = $this->get_header_format('opcode');
        $length = $this->get_header_length('opcode');

        $u = unpack($format, substr($buffer, $offset, $length));
        $this->header['opcode'] = $u[1];
        $offset += $length;

        $format = $this->get_header_format('payload_length');
        $length = $this->get_header_length('payload_length');

        $u = unpack($format, substr($buffer, $offset, $length));
        $this->header['payload_length'] = $u[1];
        $offset += $length;

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
        $format = $this->get_header_format('opcode');
        $buffer = pack($format, $this->header['opcode']);
        $format = $this->get_header_format('payload_length');
        $buffer .= pack($format, $this->header['payload_length']);
        if ($this->header['payload_length'] > 0)
            $buffer .= $this->payload;

        socket_write($this->sd, $buffer);
    }

    protected function read_result()
    {
        $this->read_packet();
        if ($this->header['opcode'] != csSMOC_RESULT)
            throw new Exception('Unexpected protocol op-code');

        $format = libSysMonAlert::get_field_format('result');
        $length = libSysMonAlert::get_field_length('result');
        if ($this->header['payload_length'] < $length)
            throw new Exception('Unexpected payload length');

        $u = unpack($format, substr($this->payload, 0, $length));
        $this->payload_index += $length;
        return $u[1];
    }

    protected function write_result($result)
    {
        $this->reset_packet();
        $this->write_packet_var($result, 'result');
        $this->write_packet(csSMOC_RESULT);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
