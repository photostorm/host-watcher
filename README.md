# host-watcher
Collect system information with SSH

```
+--------------------+------------------+-----------+------------+--------------+------------+-------------+-------------+--------------------------------+
|        HOST        |     OS NAME      | OS VENDOR | OS VERSION | PROCESS USER | PROCESS ID | PROCESS CPU | PROCESS MEM |        PROCESS COMMAND         |
+--------------------+------------------+-----------+------------+--------------+------------+-------------+-------------+--------------------------------+
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |          1 |         0.0 |         0.9 | /sbin/init                     |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        237 |         0.0 |         0.9 | /lib/systemd/systemd-journald  |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        258 |         0.0 |         0.4 | /lib/systemd/systemd-udevd     |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | systemd+     |        280 |         0.0 |         0.6 | /lib/systemd/systemd-timesyncd |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        330 |         0.0 |         0.7 | /usr/sbin/haveged              |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        431 |         0.0 |         0.2 | /usr/sbin/cron                 |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | message+     |        432 |         0.0 |         0.4 | /usr/bin/dbus-daemon           |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        433 |         0.0 |         0.7 | /lib/systemd/systemd-logind    |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        435 |         0.0 |         0.4 | /usr/sbin/rsyslogd             |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        442 |         0.0 |         0.3 | /bin/login                     |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        443 |         0.0 |         0.3 | /bin/login                     |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        444 |         0.0 |         0.6 | /usr/sbin/sshd                 |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        494 |         0.0 |         0.8 | /lib/systemd/systemd           |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        495 |         0.0 |         0.2 | (sd-pam)                       |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |        499 |         0.0 |         0.4 | -bash                          |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |       1646 |         0.0 |         0.4 | -bash                          |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |      27661 |         0.0 |         0.8 | sshd:                          |
| 192.168.159.131:22 | Debian GNU/Linux | debian    |         10 | root         |      27668 |         0.0 |         0.3 | ps                             |
+--------------------+------------------+-----------+------------+--------------+------------+-------------+-------------+--------------------------------+

```