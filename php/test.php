#!/usr/clearos/sandbox/usr/bin/php -q
<?php
// Example System Monitor usage for PHP
include_once('libevents.php');

date_default_timezone_set('America/New_York');

// Connect to System Monitor
$sysmon = new libSysMonitor();
$sysmon->connect();

// Create and send a new alert
$alert = new libSysMonAlert();
$alert->set_flag(csAF_LVL_WARN);
$alert->set_flag(csAF_FLG_PERSIST);
$alert->set_type($sysmon->get_type_id('USER_LOGIN'));
$alert->set_user('dsokoloski');
$alert->add_group('dsokoloski');
$alert->set_uuid('0a:00:27:00:00:00');
$alert->set_icon('firewall_incoming');
$alert->set_description('This is an example alert description!');

$sysmon->send_alert($alert);

// Mark an alert as read
//$sysmon->mark_as_read(7);

// Get array of alerts, format and display them
$alerts = $sysmon->get_alerts();

if (! count($alerts)) {
    echo "No alerts in database\n";
    return 0;
}

foreach ($alerts as $alert) {
    $alert_prio = '';
    if ($alert->get_flags() & csAF_LVL_WARN)
        $alert_prio = 'WARNING';
    else if ($alert->get_flags() & csAF_LVL_WARN)
        $alert_prio = 'CRITICAL';

    $alert_flags = ($alert->get_flags() & csAF_FLG_PERSIST) ? 'p' : '-';
    $alert_flags .= ($alert->get_flags() & csAF_FLG_READ) ? 'r' : '-';

    printf("#%-10lu%-30s%s%s%s [%s]\n",
        $alert->get_id(), strftime('%c', $alert->get_stamp()),
        $alert_prio, (strlen($alert_prio)) ? ': ' : ' ',
        $sysmon->get_type_name($alert->get_type()), $alert_flags);
    echo $alert->get_description() . "\n\n";
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
