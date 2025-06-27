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

//#################################################################################################################################
// File name: delete_private_message.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-07-18      DW              Remove already read messages for private groups, which auto-delete message flag is 
//                                               set to 1. 
// V2.0.00       2022-12-05      DW              - Rewrite it from Perl to Node.js (javascript).
//                                               - Install a scheduler to operate this service periodically. 
// V2.0.01       2025-06-27      DW              Show timestamp on error message.                                              
//#################################################################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');
const msglib = require('./lib/msg_lib.js');
//-- Notificator to pass notices to all SMS server instances via RabbitMQ broker. --//
//-- Note: RabbitMQ broker login parameters are put on the file './etc/config.js' --//
const notificator = require('./lib/notificatorSingleton');

var interval = 30000;     // Repeat every 30 seconds

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


async function _getPrivateMessageGroups(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT group_id, delete_after_read ` +
          `  FROM msg_group ` +
          `  WHERE group_type = 1 ` +
          `    AND msg_auto_delete = 1`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));      
    
    data.forEach(rec => {
      result.push({group_id: rec.group_id, delete_after_read: parseInt(rec.delete_after_read, 10)});      
    });    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getMessagesShouldBeChecked(conn, group_id, delete_after_read) {
  var sql, param, data, time_limit;
  var result = [];
  
  try {
    time_limit = "00:" + wev.padLeft(delete_after_read.toString(), 2, "0") + ":00";
    
    sql = `SELECT DISTINCT HEX(a.msg_id) AS msg_id ` + 
          `  FROM message a, msg_tx b ` +
          `  WHERE a.msg_id = b.msg_id ` +
          `    AND a.group_id = ? ` +
          `    AND b.read_status = 'R' ` +
          `    AND TIMEDIFF(CURRENT_TIMESTAMP(), b.read_time) >= ? ` +
          `  ORDER BY a.msg_id`;
    
    param = [group_id, time_limit];
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


async function _allMembersHaveReadThisMessage(conn, msg_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM msg_tx ` +
          `  WHERE HEX(msg_id) = ? ` +
          `    AND read_status <> 'R'`;
          
    param = [msg_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? false : true;      
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


async function _deleteReadMembersTxRec(conn, msg_id, delete_after_read) {
  var sql, param, time_limit;
  
  try {
    time_limit = "00:" + wev.padLeft(delete_after_read.toString(), 2, "0") + ":00";
    
    sql = `DELETE FROM msg_tx ` +
          `  WHERE HEX(msg_id) = ? ` +
          `    AND read_status = 'R' ` +
          `    AND TIMEDIFF(CURRENT_TIMESTAMP(), read_time) >= ?`;
          
    param = [msg_id, time_limit];      
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


async function deleteReadPrivateMessages(interval) {
  var scheduler_id;

  //-- Run "_deletePrivateMessages()" immediately, then put it into a scheduler. --//
  await _deletePrivateMessages();
  scheduler_id = setInterval(_deletePrivateMessages, interval);
      
  async function _deletePrivateMessages() {
    var conn;
    var private_groups = [];
    
    try {      
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      
      private_groups = await _getPrivateMessageGroups(conn);
      
      for (const this_group of private_groups) { 
        var this_group_id = this_group.group_id;
        var this_delete_after_read = this_group.delete_after_read;
        
        //-- Get to be deleted message list --//
        var messages = await _getMessagesShouldBeChecked(conn, this_group_id, this_delete_after_read);

        for (var i = 0; i < messages.length; i++) {
          var this_msg_id = messages[i];             // Note: msg_id is a binary data generated as UUID, here is it's hexadecimal form.
          if (await _allMembersHaveReadThisMessage(conn, this_msg_id)) {
            console.log(`* Delete message ${this_msg_id} for group ${this_group_id}`);
            await msglib.removeMessageDataSet(conn, this_group_id, this_msg_id);
            //-- Inform group members to refresh via RabbitMQ broker --//
            await _informMemberToRefresh(this_group_id);
          }
          else {
            console.log(`@ Delete message transaction of message ${this_msg_id} for group ${this_group_id}`);
            //-- The message will disappear for user has read this message --//
            await _deleteReadMembersTxRec(conn, this_msg_id, this_delete_after_read);
            await msglib.updateGroupRefreshToken(conn, this_group_id);
            //-- Inform group members to refresh via RabbitMQ broker --//
            await _informMemberToRefresh(this_group_id);
          } 
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


deleteReadPrivateMessages(interval);




