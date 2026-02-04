----
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--      http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
----

-----------------------------------------------------------------------------------------------------
-- Name: create_db.sql
--
-- Ver           Date            Author          Comment
-- =======       ===========     ===========     ==========================================
-- V1.0.00       2018-12-12      DW              Create databases for SMS, and put in essential data.
-- V1.0.01       2019-05-24      DW              Define indexes for all database tables.
-- V1.0.02       2020-06-19      DW              Make all databases using utf8mb4 character set which   
--                                               let them fully support UTF-8 data storage.
-- V1.0.03       2020-07-16      DW              Use 'longtext' for message related fields on table
--                                               'message'.
-- V1.0.04       2022-07-26      DW              Change 'msg_id' data type on tables 'message' and 
--                                               'msg_tx' from BIGINT to BINARY(16), in order to handle
--                                               huge number of message records. In addition, 'log_id'
--                                               for tables 'sys_error_log' and 'unhappy_login_history'
--                                               are also changed from BIGINT to BINARY(16).
-- V1.0.05       2022-09-10      DW              Add new table 'rsa_keypair' to store generated RSA key
--                                               pairs. 
-- V1.0.06       2023-02-27      DW              Add new table 'sms_version' to store SMS versioning 
--                                               details.
-- V1.0.07       2023-10-10      DW              Amend schema of table 'rsa_keypair' and 'login_token_queue'. 
-- V1.0.08       2024-01-19      DW              Amend schema of table 'message' to add a new field 'iv'.
-- V1.0.09       2024-03-20      DW              Add new table 'kyber_keypair' to store generated Crystals
--                                               Kyber key pairs. 
-- V1.0.10       2024-10-22      DW              Update happy password and unhappy password hash strings for
--                                               user 'smsadmin' on table 'user_list', since the library used 
--                                               for user password encryption and verification is changed.
-- V1.0.11       2025-06-12      DW              Add three more system settings. They are 'use_email_gateway',
--                                               'email_gateway' and 'master_passwd'.  
-- V1.0.12       2025-12-04      DW              - Add a new field 'rolling_key varchar(128)' to tables 
--                                                 'login_token_queue' and 'web_session'.
--                                               - Create a new table 'sess_roll_key'. 
--
-- Remark: It is part of SMS installation program.
-----------------------------------------------------------------------------------------------------

DROP DATABASE IF EXISTS msgdb;

CREATE DATABASE msgdb
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

GRANT ALL ON msgdb.* TO 'msgadmin'@localhost IDENTIFIED BY 'cPx634BzAr1338Ux';

USE msgdb;

CREATE OR REPLACE TABLE user_list
(
  user_id bigint unsigned not null auto_increment,
  user_name varchar(64),
  user_alias varchar(256),
  name varchar(256),
  happy_passwd varchar(256),
  unhappy_passwd varchar(256),
  login_failed_cnt int,
  user_role int,
  email varchar(256),
  tg_id varchar(128),
  refer_by bigint,
  join_date date,
  status varchar(6),
  cracked int,
  cracked_date datetime,
  inform_new_msg int,
  PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_name ON user_list(user_name);
CREATE INDEX idx_usr_role_status ON user_list(user_role, status);

LOCK TABLES `user_list` WRITE;
ALTER TABLE `user_list` DISABLE KEYS;
INSERT INTO `user_list` VALUES (1,'smsadmin','SA','','$argon2id$v=19$m=512,t=256,p=1$j1LImLNIVbQBKTw/rvYxpg$ESlT/C0vTuLK7fNpgl70wmycNZ4NF+XROgEYDkdYcQ4','$argon2id$v=19$m=512,t=256,p=1$JX7EABK+eZI1DpIRcUi1SA$5sPeVhCSJkSU4vTF4J9k+ztD/3/SHdg66Z4YUOaVTVM',0,2,'your_email_address','',0,current_date(),'A',0,null,1);
ALTER TABLE `user_list` ENABLE KEYS;
UNLOCK TABLES;

CREATE OR REPLACE TABLE tg_bot_profile
(
  bot_name varchar(128),
  bot_username varchar(128),
  http_api_token varchar(256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE applicant
(
  apply_id bigint unsigned not null auto_increment,
  name varchar(256),
  email varchar(256),
  refer_email varchar(256),
  remark varchar(1024),
  apply_date datetime,
  status varchar(6),
  seed varchar(256),
  algorithm varchar(15),
  token_iv varchar(512),
  token varchar(512),  
  PRIMARY KEY (apply_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Note: 'token' in UTF-8 is too long to be used as primary key.
CREATE OR REPLACE TABLE login_token_queue
(
  token varchar(512) not null,
  token_addtime datetime,
  token_usetime datetime,
  algorithm varchar(15),
  token_iv varchar(512),
  token_seed varchar(256),
  aes_key varchar(128),
  rolling_key varchar(128),
  status varchar(6),
  user_id bigint
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_token ON login_token_queue(token);

CREATE OR REPLACE TABLE web_session
(
  sess_code varchar(128),
  user_id bigint,
  sess_until datetime,
  ip_address varchar(256),
  http_user_agent varchar(384),
  secure_key varchar(128),
  rolling_key varchar(128),
  status varchar(2),
  PRIMARY KEY (sess_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id ON web_session(user_id);

CREATE TABLE sess_roll_key
(
  sess_code varchar(128),
  rolling_key varchar(128),
  counter int
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_sess_roll_key ON sess_roll_key(sess_code, rolling_key);

CREATE OR REPLACE TABLE hack_history
(
  ipv4_addr varchar(20),
  user_id bigint,
  first_hack_time datetime,
  last_hack_time datetime,
  hack_cnt int,
  ip_blocked int 
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id_ipv4 ON hack_history(user_id, ipv4_addr); 

CREATE OR REPLACE TABLE msg_group
(
  group_id bigint unsigned not null auto_increment,
  group_name varchar(256),
  group_type int,
  msg_auto_delete int,
  delete_after_read int,
  algorithm varchar(15),
  encrypt_key varchar(256),
  status varchar(6),
  refresh_token varchar(16),
  PRIMARY KEY (group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE group_member
(
  group_id bigint unsigned,
  user_id bigint,
  group_role varchar(1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE INDEX idx_grp_id_usr_id ON group_member(group_id, user_id);
CREATE INDEX idx_grp_id ON group_member(group_id);

-- 'add_marker' is an unique identifier which is used during record creation. It is a randomly generated alphanumeric string.
-- After the message record has been created and the newly generated msg_id has been obtained, the value of 'add_marker' 
-- should be cleared to avoid possible interference later.    
CREATE OR REPLACE TABLE message
(
  msg_id binary(16) not null default (unhex(replace(uuid(), '-', ''))),
  add_marker varchar(16) not null,
  group_id bigint unsigned not null,
  sender_id bigint unsigned not null,
  send_time datetime not null default (current_timestamp()),  
  send_status varchar(6) not null,  
  iv text not null,
  msg longtext not null,
  fileloc varchar(512) not null default (''),
  op_flag varchar(1),
  op_user_id bigint,
  op_msg longtext,  
  op_iv text,
  PRIMARY KEY (msg_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_grp_id_msg_id ON message(group_id, msg_id);

CREATE OR REPLACE TABLE msg_tx
(
  msg_id binary(16) not null,
  receiver_id bigint not null,
  read_status varchar(6),
  read_time datetime,
  PRIMARY KEY (msg_id, receiver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_msg_id ON msg_tx(msg_id);
CREATE INDEX idx_rev_id_msg_id ON msg_tx(receiver_id, msg_id);

CREATE OR REPLACE TABLE new_msg_inform
(
  user_id bigint unsigned,
  period datetime,
  status varchar(2),
  try_cnt int
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id_status ON new_msg_inform(user_id, status); 

CREATE OR REPLACE TABLE unhappy_login_history
(
  log_id binary(16) not null default (unhex(replace(uuid(), '-', ''))),
  user_id bigint unsigned,
  login_time datetime,
  loc_longitude numeric(13,6),
  loc_latitude numeric(13,6),
  browser_signature varchar(512),
  PRIMARY KEY (log_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id ON unhappy_login_history(user_id);

CREATE OR REPLACE TABLE decoy_sites
(
  site_url varchar(512),
  key_words varchar(512)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `decoy_sites` WRITE;
INSERT INTO `decoy_sites` VALUES ('https://nexter.org','News'),('https://techcrunch.com','Tech News'),('https://thenextweb.com','Tech News'),('https://www.wired.com','Tech News'),('https://www.firstpost.com/tech','Tech News'),('https://gizmodo.com','Tech News'),('https://mashable.com','Tech News'),('https://www.theverge.com','Tech News'),('https://www.digitaltrends.com','Tech News'),('https://www.techradar.com','Tech News'),('https://www.macrumors.com','Tech News'),('https://www.codeproject.com','Programming Forum'),('https://stackoverflow.com','Programming Forum'),('https://forum.xda-developers.com','Programming Forum'),('https://bytes.com','Programming Forum'),('https://www.webhostingtalk.com','Forum'),('https://thehackernews.com','IT security news'),('https://www.infosecurity-magazine.com','IT security news'),('https://www.csoonline.com','IT security news'),('https://www.tripwire.com/state-of-security','IT security news'),('https://www.troyhunt.com','IT security blog'),('https://www.lastwatchdog.com','IT security watch'),('https://www.schneier.com','IT security watch'),('https://blogs.akamai.com','IT security blog'),('https://krebsonsecurity.com','IT security news'),('https://taosecurity.blogspot.com/?m=1','IT security blog'),('https://www.pcworld.com','IT news'),('https://www.welivesecurity.com','IT security news'),('https://www.afcea.org/content','IT security news'),('https://threatpost.com','IT security news'),('https://www.computerworld.com/category/emerging-technology','IT news'),('https://www.grahamcluley.com','IT security news'),('https://www.itsecurityguru.org','IT security news');
UNLOCK TABLES;

CREATE OR REPLACE TABLE sys_error_log
(
  log_id binary(16) not null default (unhex(replace(uuid(), '-', ''))),
  user_id bigint unsigned,
  brief_err_msg varchar(256),
  detail_err_msg varchar(1024),
  log_time datetime,
  browser_signature varchar(512),
  PRIMARY KEY (log_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE sys_email_sender
(
  ms_id bigint not null auto_increment,
  email varchar(128),
  m_user varchar(64),
  m_pass varchar(64),
  smtp_server varchar(128),
  port int,
  status varchar(1),
  PRIMARY KEY (ms_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE sites
(
  site_type varchar(10),
  site_dns varchar(128),
  status varchar(1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `sites` WRITE;
INSERT INTO `sites` VALUES ('DECOY','https://decoy.site.com','A'),('MESSAGE','https://messaging.site.net','A');
UNLOCK TABLES;

CREATE OR REPLACE TABLE file_type
(
  ftype_id bigint not null auto_increment,
  file_ext varchar(16),
  file_type varchar(64),
  PRIMARY KEY (ftype_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `file_type` WRITE;
ALTER TABLE `file_type` DISABLE KEYS;
INSERT INTO `file_type` VALUES (1,'jpg','image'),(2,'jpeg','image'),(3,'png','image'),(4,'gif','image'),(5,'bmp','image'),(6,'tif','image'),(7,'tiff','image'),(8,'mp3','audio/mpeg'),(9,'ogg','audio/ogg'),(10,'wav','audio/wav'),(11,'mp4','video/mp4'),(12,'webm','video/webm'),(13,'amr','aud_convertable'),(14,'3gpp','aud_convertable');
ALTER TABLE `file_type` ENABLE KEYS;
UNLOCK TABLES;

CREATE OR REPLACE TABLE sys_settings
(
  sys_key varchar(64) not null,
  sys_value varchar(512),
  PRIMARY KEY (sys_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `sys_settings` WRITE;
INSERT INTO `sys_settings` VALUES ('audio_converter',"/usr/bin/ffmpeg -i '{input_file}' '{output_file}'"),('connection_mode','0'),('decoy_company_name','PDA Tools'),('msg_block_size','30'),('session_period','02:00:00'),('old_msg_delete_days','14'),('use_email_gateway','FALSE'),('email_gateway',''),('master_passwd','');
UNLOCK TABLES;

CREATE OR REPLACE TABLE rsa_keypair
(
  key_id varchar(16) not null,
  public_key longtext not null,
  private_key longtext not null,
  algorithm longtext not null,
  add_datetime datetime not null,
  PRIMARY KEY (key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE kyber_keypair
(
  key_id varchar(64) not null,
  public_key longtext not null,
  private_key longtext not null,
  add_datetime datetime not null,
  PRIMARY KEY (key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE sms_version
(
  ver_no varchar(30) not null,
  ver_major varchar(30),
  ver_minor varchar(30),
  build_no varchar(30),
  build_time datetime
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `sms_version` WRITE;
INSERT INTO `sms_version` VALUES ("2.0.19", "2.0", "19", "20260130", "2026-01-30 23:59:59");
UNLOCK TABLES;

--=========================================================================================================================================================--


DROP DATABASE IF EXISTS pdadb;

CREATE DATABASE pdadb
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

GRANT ALL ON pdadb.* TO 'pdadmin'@localhost IDENTIFIED BY 'Yt83344Keqpkgw34';

USE pdadb;

CREATE OR REPLACE TABLE web_session
(
  sess_code varchar(128),
  user_id bigint,
  sess_until datetime,
  ip_address varchar(256),
  http_user_agent varchar(384),
  secure_key varchar(128),
  rolling_key varchar(128),
  status varchar(2),
  PRIMARY KEY (sess_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id ON web_session(user_id);

CREATE OR REPLACE TABLE feature_store
(
  feature_id bigint unsigned not null auto_increment,
  feature_url varchar(512),
  feature_icon varchar(256),
  PRIMARY KEY (feature_id)  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `feature_store` WRITE;
ALTER TABLE `feature_store` DISABLE KEYS;
INSERT INTO `feature_store` VALUES (1,'/tools/notes','/images/notes.png'),(2,'/tools/scheduler','/images/scheduler.png');
ALTER TABLE `feature_store` ENABLE KEYS;
UNLOCK TABLES;

CREATE OR REPLACE TABLE feature_list
(
  feature_id bigint,
  list_order int
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `feature_list` WRITE;
INSERT INTO `feature_list` VALUES (1,1),(2,2);
UNLOCK TABLES;

CREATE OR REPLACE TABLE schedule_event
(
  event_id bigint unsigned not null auto_increment,
  user_id bigint,
  event_title varchar(256),
  event_detail text,
  ev_start datetime,
  ev_end datetime,
  PRIMARY KEY (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_usr_id_ev_start ON schedule_event(user_id, ev_start); 

CREATE OR REPLACE TABLE schedule_reminder
(
  reminder_id bigint unsigned not null auto_increment,
  event_id bigint,
  remind_before varchar(32),
  remind_unit varchar(16),
  has_informed int,
  PRIMARY KEY (reminder_id) 
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE OR REPLACE TABLE notes
(
  notes_id bigint unsigned not null auto_increment,
  user_id bigint unsigned,
  notes_title varchar(256),
  notes_content text,
  create_date datetime,
  update_date datetime,  
  PRIMARY KEY (notes_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



