#!/usr/bin/node

//###
//# Licensed under the Apache License, Version 2.0 (the "License");
//# you may not use this file except in compliance with the License.
//# You may obtain a copy of the License at
//# 
//#      http://www.apache.org/licenses/LICENSE-2.0
//# 
//# Unless required by applicable law or agreed to in writing, software
//# distributed under the License is distributed on an "AS IS" BASIS,
//# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//# See the License for the specific language governing permissions and
//# limitations under the License.
//###

//#########################################################################################
// Program: delete_old_message.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     =========================
// V1.0.00       2018-07-23      DW              Remove messages which are sent 14 days before
//                                               for common groups and private groups which
//                                               auto-delete message flag is set to 0.
// V1.0.01       2019-01-15      DW              Let old messages removal days becomes a variable
//                                               and store on system setting 'old_msg_delete_days'. 
// V2.0.00       2022-12-08      DW              - Rewrite it from Perl to Node.js (javascript).
//                                               - Install a scheduler to operate this service
//                                                 periodically.
// V2.0.01       2025-06-27      DW              Show timestamp on error message.                                                
//#########################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');
const msglib = require('./lib/msg_lib.js');
//-- Notificator to pass notices to all SMS server instances via RabbitMQ broker. --//
//-- Note: RabbitMQ broker login parameters are put on the file './etc/config.js' --//
const notificator = require('./lib/notificatorSingleton');

var interval = 3600000;        // Repeat every hour

async function runNotificator() {
  await notificator.init();
  //-- Start listening notificator channel and install notice handler --//
  notificator.receive(noticeHandler);
}

function noticeHandler(notice) {
  //-- Do nothing in here. All messages must be passed to RabbitMQ and --//
  //-- spread to all application server instances. Actual operations   --//
  //-- is executed inside the application servers.                     --// 
}

//-- Start notificator (notices are via RabbitMQ message broker) --//
runNotificator();


async function _getMessageGroupsToBeChecked(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT group_id ` +
          `  FROM msg_group ` +
          `  WHERE (group_type = 0 ` +
          `    AND msg_auto_delete = 1) ` +
          `     OR (group_type = 1 ` +
          `    AND msg_auto_delete = 0)`;
    
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push(data[i].group_id);
    }    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getMessagesShouldBeDeleted(conn, group_id, cutoff_days) {
  var sql, param, data;
  var result = [];
  
  try {
    sql = `SELECT HEX(msg_id) AS msg_id ` +
          `  FROM message ` +
          `  WHERE group_id = ? ` +
          `    AND DATEDIFF(CURRENT_TIMESTAMP(), send_time) >= ?`;
    
    param = [group_id, cutoff_days];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      result.push(data[i].msg_id);
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _informMemberToRefresh(group_id) {
  try {
    //-- Inform users on all app servers to handle message refresh operation which is initiated by --//
    //-- user of this app server.                                                                  --//
    var notice = {op: 'msg_refresh', content: {type: 'msg', group_id: group_id, my_user_id: 0}};
    notificator.notify(notice);
  }
  catch(e) {
    throw e;
  }  
}


async function deleteOldMessages(interval) {
  var scheduler_id;

  //-- Run "_deleteOldMessages()" immediately, then put it into a scheduler. --//
  await _deleteOldMessages();
  scheduler_id = setInterval(_deleteOldMessages, interval);
  
  async function _deleteOldMessages() {
    var conn, cutoff_days;
    var msg_groups = [];
  
    try {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      
      cutoff_days = await wev.getSysSettingValue(conn, 'old_msg_delete_days');
      cutoff_days = (parseInt(cutoff_days, 10) > 0)? parseInt(cutoff_days, 10): 14;  
      
      msg_groups = await _getMessageGroupsToBeChecked(conn);
      
      for (var i = 0; i < msg_groups.length; i++) {
        var this_group_id = msg_groups[i];
        var messages = await _getMessagesShouldBeDeleted(conn, this_group_id, cutoff_days);
        
        for (var k = 0; k < messages.length; k++) {
          var this_msg_id = messages[k];          
          await msglib.removeMessageDataSet(conn, this_group_id, this_msg_id);
        }        
        
        if (messages.length > 0) {
          //-- Inform group members to refresh via RabbitMQ broker --//
          await _informMemberToRefresh(this_group_id);                    
        }
      }      
    }   
    catch(e) {
      console.log(wev.sayCurrentTime() + " : " + e.message);
    }
    finally {
      await dbs.dbClose(conn);
    }
  }
}


deleteOldMessages(interval);
