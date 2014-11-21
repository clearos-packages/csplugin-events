#!/usr/clearos/sandbox/usr/bin/php -q
<?php
include_once('libsysmon.php');

$sysmon = new libSysMonitor();
$sysmon->connect();

$alert = new libSysMonAlert();

$alert->set_flag(csAF_LVL_WARN);
$alert->set_flag(csAF_FLG_PERSIST);
$alert->set_user('dsokoloski');
$alert->add_group('dsokoloski');
$alert->set_uuid('0a:00:27:00:00:00');
$alert->set_icon('firewall_incoming');
$alert->set_description('This is an example alert description!');

$sysmon->send_alert($alert);

