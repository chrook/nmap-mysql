DROP TABLE IF EXISTS `hosts`;

CREATE TABLE `hosts` (
  `id` bigint(20) PRIMARY KEY AUTO_INCREMENT,
  `ip_address` varchar(20) DEFAULT NULL,
  `mac_address` varchar(24) DEFAULT NULL,
  `hostname` varchar(64) DEFAULT NULL,
  `os` varchar(64) DEFAULT NULL,
  `scan_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` int(1) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `host_ports`;

CREATE TABLE `host_ports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) DEFAULT NULL,
  `port_number` char(5) DEFAULT NULL,
  `protocol` varchar(20) DEFAULT NULL,
  `state` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
