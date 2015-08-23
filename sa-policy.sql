CREATE TABLE IF NOT EXISTS `sa_policy_blacklist` (
  `ip` varchar(46) NOT NULL,
  `spam_count` int(11) NOT NULL DEFAULT '0',
  `updates` int(11) NOT NULL DEFAULT '0',
  `expires` datetime NOT NULL,
  PRIMARY KEY (`ip`),
  KEY `expires` (`expires`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;



CREATE TABLE IF NOT EXISTS `sa_policy_log` (
  `ip` varchar(46) NOT NULL,
  `hits` decimal(6,3) NOT NULL,
  `time` datetime NOT NULL,
  KEY `time` (`time`),
  KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;



CREATE TABLE IF NOT EXISTS `sa_policy_stats` (
  `ip` varchar(46) NOT NULL,
  `spam_count` int(11) NOT NULL DEFAULT '0',
  `ham_count` int(11) NOT NULL DEFAULT '0',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  UNIQUE KEY `ip` (`ip`),
  KEY `spam_count` (`spam_count`,`ham_count`,`first_seen`,`last_seen`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

