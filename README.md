# SpamAssassin Policy Daemon (for Amavis/Maia and Postfix)

This simple spamassassin policy daemon watches your Postfix maillog for obvious spammers and temporarily bans their IP's with 450 (defer) responses via Postfix.   This tool will SIGNIFICANLY reduce stress and increase stability on your spam filtering nodes by reducing the needless scanning of obvious spam mail.

Even more, sa-policy is an excellent replacement for greylisting.   Achieve similar results WITHOUT delaying legitimate mail (and upsetting your customers!).

  - Blacklist is temporary (450 DEFER) - you configure the length of time
  - Blacklist and host stats are stored in MySQL
  - Old MySQL records auto-purged to keep table sizes small
  - Very little overhead (daemon takes 8MB RAM and almost zero CPU time)
  - Also works on MX clusters with a common DB
  - Ban repeat abusers temporarily via iptables (optional)

The installation and files should be self-explanitory.

##### sa-policy.sql
Create your tables by executing `mysql <dbname> < sa-policy.sql`

##### sa-policy.logrotate
Keep your logs rotated by copying this to `/etc/logrotate.d`.

##### sa-policy.cron
Copy this to `/etc/cron.d` to keep the daemon running (in case the DB goes down, reboot, ect).

##### mysql-sa-policy.cf
Edit the DB parameters and place this in `/etc/postfix`.   You also need to place the following just under `smtpd_recipient_restrictions` (top of the list) in your `main.cf`:

`check_client_access mysql:/etc/postfix/mysql-sa-policy.cf,`

##### sa-policy.pl
Place this into `/opt/sa-policy` and edit the top section to your liking.   The primary parameters (other than the DB credentials) are `spam_score` and `max_spam_per_interval`.   You should set `spam_score` to the minimum level which you feel is definately spam to prevent false positives.   `max_spam_per_interval` is the number of messages with a score higher than `spam_score` during the `spam_interval` which will trigger a temporary blacklisting.

##### regex.custom.pm (optional)
Some spammers react poorly to the 450 defers and will hammer your server excessively (up to 1000/min per host in some cases).  If you are using CSF firewall, you can drop this into `/etc/csf/` to temporarily block this hammering in IPTABLES and keep the postfix logs from filling up with excessive 450's.

NOTE: You also need to edit `/etc/csf/csf.conf` towards the end and set `CUSTOM1_LOG` to `/var/log/maillog`.
