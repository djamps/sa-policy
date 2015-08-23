# SpamAssassin Policy Daemon (for Amavis/Maia and Postfix)

This simple spamassassin policy daemon watches your Postfix maillog for obvious spammers and temporarily bans their IP's with 450 (defer) responses via Postfix.   This tool will SIGNIFICANLY reduce stress and increase stability on your spam filtering nodes by preventing needless scanning of obvious spam mail.

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
