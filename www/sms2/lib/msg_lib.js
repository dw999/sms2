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
// File name: msg_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2022-05-07      DW              Messaging operation library for SMS version 2.
// V1.0.01       2023-05-23      DW              Use Telegram to accelerate referrer inform on new user-request-to-join process. 
// V1.0.02       2023-06-06      DW              Skip member accept new message checking on function '_needToInformMember'.
// V1.0.03       2023-10-13      DW              Use client generated AES key to encrypt and decrypt uploading and downloading 
//                                               messages sending to and received from the server, instead to use session code 
//                                               stored on the cookie.
// V1.0.04       2024-03-02      DW              - Message(s) loading from the server will be continuous, even message decryption error 
//                                                 is found. i.e. Let user has chance to get other normal message(s).
//                                               - Diable embedded javascript on messages to prevent inside job of hacking. 
//#################################################################################################################################

"use strict";
const fs = require('fs');
const execSync = require('node:child_process').execSync;
const dbs = require('../lib/db_lib.js');
const wev = require('../lib/webenv_lib.js');
const cipher = require('../lib/cipher_lib.js');
const telecom = require('../lib/telecom_lib.js');
const smslib = require('../lib/sms_lib.js');


async function _isGroupMember(conn, user_id, group_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM group_member a, user_list b ` +
          `  WHERE a.user_id = b.user_id ` +
          `    AND b.status = 'A' ` + 
          `    AND a.group_id = ? ` +
          `    AND a.user_id = ?`;
          
    param = [group_id, user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);

    if (data.length > 0) {
      result = (parseInt(data[0].cnt, 10) > 0)? true : false;
    }
    else {
      result = false; 
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.isGroupMember = async function(msg_pool, user_id, group_id) {
  var conn, result;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    result = await _isGroupMember(conn, user_id, group_id);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


async function _getMessageGroupMembers(conn, group_id, data_filter) {
  var sql, param, data;
  var members = [];
  
  try {
    sql = `SELECT a.user_id, b.user_name, b.user_alias, b.name, a.group_role ` +
          `  FROM group_member a, user_list b ` +
          `  WHERE a.user_id = b.user_id ` +
          `    AND b.status = 'A' ` +
          `    AND group_id = ? ` +
          `  ORDER BY a.group_role DESC, b.user_name, b.user_alias`;
          
    param = [group_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);      
    
    for (var i = 0; i < data.length; i++) {
      var this_user_id = data[i].user_id;
      var this_user_name = data[i].user_name;
      var this_user_alias = data[i].user_alias;
      var this_name = data[i].name;
      var this_group_role = data[i].group_role;
      
      //-- Note: If 'data_filter' is not defined, it means to return full set of data. --//
      if (typeof(data_filter) == 'object') {
        this_user_id = (data_filter.user_id)? this_user_id : null;
        this_user_name = (data_filter.user_name)? this_user_name : null;
        this_user_alias = (data_filter.user_alias)? this_user_alias : null;  
        this_name = (data_filter.name)? this_name : null;
        this_group_role = (data_filter.group_role)? this_group_role : null;
      }
      
      var this_rec = {user_id: this_user_id, username: this_user_name, alias: this_user_alias, name: this_name, group_role: this_group_role};
      members.push(this_rec);
    }
  }
  catch(e) {
    throw e;
  }
    
  return members;  
}


exports.getMessageGroupMembers = async function(conn, group_id) {
  var close_conn = false;
  var members = [];
  
  try {
    if (conn == null || typeof(conn) == 'undefined') {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      close_conn = true;
    }
    
    members = await _getMessageGroupMembers(conn, group_id);
  }
  catch(e) {
    throw e;  
  }
  finally {
    if (close_conn) {
      await dbs.dbClose(conn);
    }
  }
  
  return members;
}


exports.getMessageGroupMembersViaPool = async function(msg_pool, group_id) {
  var conn;
  var members = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    members = await _getMessageGroupMembers(conn, group_id);
  }
  catch(e) {
    throw e;  
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return members;
}


async function _getMessageGroupKey(conn, group_id) {
  var sql, param, data, key; 
  
  key = '';

  try {
    sql = `SELECT encrypt_key ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      key = data[0].encrypt_key;
    }      
    else {
      throw new Error(`Unable to retrieve encryption key for message group ${group_id}`);
    }
  }
  catch(e) {
    throw e;
  }
  
  return key;
}


async function _getMessageGroupAlgorithm(conn, group_id) {
  var sql, param, data, algorithm; 
  
  algorithm = '';

  try {
    sql = `SELECT algorithm ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      algorithm = data[0].algorithm;
    }      
    else {
      algorithm = "AES-GCM";
    }
  }
  catch(e) {
    throw e;
  }
  
  return algorithm;	
}


async function _getMessageGroupEncryptInfo(conn, group_id) {
  let sql, param, data; 
  let result = {};

  try {
    sql = `SELECT algorithm, encrypt_key ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
			let algorithm = data[0].algorithm;
      let key = data[0].encrypt_key;
      
      result = {'algorithm': algorithm, 'key': key};
    }      
    else {
      throw new Error(`Unable to retrieve algorithm and encryption key for message group ${group_id}`);
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;	
}


async function _updateGroupRefreshToken(conn, group_id) {
  var sql, param, token;
  var result = {ok: true, msg: ''};
  
  try {
    token = cipher.generateTrueRandomStr('A', 16);
    
    sql = `UPDATE msg_group ` +
          `  SET refresh_token = ? ` +
          `  WHERE group_id = ?`;
          
    param = [token, group_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    result = {ok: false, msg: e.message}; 
    smslib.consoleLog(e.message);
  }
    
  return result;  
}


exports.updateGroupRefreshToken = async function(conn, group_id) {
  var result = {ok: true, msg: ''};
  
  try {
    result = await _updateGroupRefreshToken(conn, group_id);
  }
  catch(e) {
    throw e;
  }
  
  return result;
} 


async function _addMessageRecord(conn, user_id, group_id, message, fileloc, op_flag, op_user_id, op_msg, http_user_agent, ip_addr) {
  let msg_id, sql, param, data, algorithm, key, iv, encrypted_msg, op_iv, encrypted_op_msg, add_marker;
  
  msg_id = '';             
  
  try {
    user_id = parseInt(user_id, 10);
    group_id = parseInt(group_id, 10); 
    op_user_id = parseInt(op_user_id, 10);
    message = wev.allTrim(message);
    fileloc = wev.allTrim(fileloc);
    op_flag = wev.allTrim(op_flag);
    op_msg = (typeof(op_msg) == 'undefined' || op_msg == null)? '' : wev.allTrim(op_msg);
    
    user_id = (isNaN(user_id))? 0 : user_id;
    group_id = (isNaN(group_id))? 0 : group_id; 
    op_user_id = (isNaN(op_user_id))? 0 : op_user_id;
    
    //-- Trigger error trapping if invalid data is found --//
    if (user_id == 0 || group_id == 0) {
      throw new Error(`Invalid data is found, operation is aborted. Given data: user_id = ${user_id}, group_id = ${group_id}.`);
    }
    
    //-- Get group message encryption key --//
		let enc_info = await _getMessageGroupEncryptInfo(conn, group_id);
		algorithm = enc_info.algorithm;
		key = enc_info.key;
    
    //-- Encrypt message --//
    let enc_obj = await cipher.aesEncryptBase64(algorithm, key, message);
    iv = enc_obj.iv;
    encrypted_msg = enc_obj.encrypted;
          
		if (op_flag == 'R') {
			//-- Message reply --//
			if (op_msg.length > 30) {                               
				op_msg = op_msg.substring(0, 29) + '...';            
			}
		}
		else {
			op_msg = '';
		}
		//-- op_msg must be encrypted even it is an empty string, because empty string in encrypted base64 --//
		//-- format is not an empty string.                                                                --// 	
		enc_obj = await cipher.aesEncryptBase64(algorithm, key, op_msg);
		op_iv = enc_obj.iv;
		encrypted_op_msg = enc_obj.encrypted;
		
		//-- Generate "add_marker" --//
		add_marker = cipher.generateTrueRandomStr('A', 16);
		
		//-- Create message record --//
		sql = `INSERT INTO message ` +
					`(add_marker, group_id, sender_id, send_time, send_status, iv, msg, fileloc, op_flag, op_user_id, op_iv, op_msg) ` +
					`VALUES ` +
					`(?, ?, ?, CURRENT_TIMESTAMP(), 'S', ?, ?, ?, ?, ?, ?, ?)`;
	
		param = [add_marker, group_id, user_id, iv, encrypted_msg, fileloc, op_flag, op_user_id, op_iv, encrypted_op_msg]; 
		await dbs.sqlExec(conn, sql, param);

		//-- Get message ID of the newly created message --//
		sql = `SELECT hex(msg_id) AS msg_id ` + 
					`  FROM message ` + 
					`  WHERE add_marker = ?`;
					
		param = [add_marker];            
		data = await dbs.sqlQuery(conn, sql, param);
		data = JSON.parse(data);
		if (data.length > 0) {
			msg_id = data[0].msg_id;
			
			//-- Once new 'msg_id' is obtained, clear 'add_marker'. --//
			sql = `UPDATE message ` +
						`  SET add_marker = '' ` +
						`  WHERE hex(msg_id) = ?`;
						
			param = [msg_id];
			await dbs.sqlExec(conn, sql, param);      
		}
		else {
			throw new Error("Unable to retrieve the message id.");
		}
	
		//-- Process will go on even this function is failure --// 
		await _updateGroupRefreshToken(conn, group_id);
  }
  catch(e) {
    throw e;
  }
  
  return msg_id;
}


async function _deliverMessage(conn, msg_id, receiver_id, status) {
  var sql, param;
  var result = {ok: true, msg: ''};
  
  try {
    sql = `INSERT INTO msg_tx ` +
          `(msg_id, receiver_id, read_status) ` +
          `VALUES ` +
          `(unhex(?), ?, ?)`;
          
    param = [msg_id, receiver_id, status];
    await dbs.sqlExec(conn, sql, param);          
  }
  catch(e) {
    result = {ok: false, msg: e.message};
  }
    
  return result;
}


async function _isUserAcceptInform(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT inform_new_msg ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = (parseInt(data[0].inform_new_msg, 10) == 1)? true : false;
    }
    else {
      //-- Something is wrong, assume this user doesn't accept email inform. --//
      result = false;
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _isUserOnline(conn, user_id) {
  var sql, param, data, sess_until, result;
  
  try {
    sql = `SELECT MAX(sess_until) AS last_sess ` +
          `  FROM web_session ` + 
          `  WHERE user_id = ? ` +
          `    AND status = 'A'`;
          
    param = [user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      sess_until = wev.allTrim(data[0].last_sess);
      if (sess_until != '') {
        result = (smslib.isTimeLimitPassed(conn, sess_until, '00:00:00.00'))? false : true;
      }
      else {
        result = false;
      }
    }
    else {
      result = false;
    }      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    //-- Assume user is offline --//
    result = false;    
  }
  
  return result;  
}


async function _hasInformRec(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM new_msg_inform ` +
          `  WHERE user_id = ? ` +
          `    AND (status = 'W' ` +
          `     OR (status = 'E' ` +
          `    AND try_cnt < 3))`;
          
    param = [user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    result = (parseInt(data[0].cnt, 10) > 0)? true : false;          
  }
  catch(e) {
    //-- Assume the user has no wait-for-inform record --//
    result = false;
  }
    
  return result;
}


async function _needToInformMember(conn, member_id) {
  var accept_inform, online, has_inform_rec, result;

  try {
    //-- 2023-06-06: Skip member accept new message checking --//
    //-- Step 1: Check whether the member accept new message inform --//
    //accept_inform = await _isUserAcceptInform(conn, member_id);
    
    //if (accept_inform) {
      //-- Step 2: Check whether the member is currently online. If he/she is, no need to inform him/her by email. --//
      online = await _isUserOnline(conn, member_id);
      
      if (online) {
        result = false;
      }
      else {
        //-- Step 3: Check whether the member has already had wait-for-inform record. If he/she already has pending email --//
        //--         inform record, no need to add one more record for him/her.                                           --// 
        result = (await _hasInformRec(conn, member_id))? false : true; 
      }
    //}
    //else {
    //  result = false;
    //}
  }
  catch(e) {
    //-- If error is found, assume the member doesn't need email inform. --//
    smslib.consoleLog(e.message);
    result = false;
  }

  return result;
}


async function _setUserInformFlag(conn, member_id, flag) {
  var sql, param;
  var result = {ok: true, msg: ''};
  
  try {
    sql = `UPDATE user_list ` +
          `  SET inform_new_msg = ? ` +
          `  WHERE user_id = ?`;
          
    param = [flag, member_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;
}


async function _addNewMessageInformQueueRec(conn, member_id) {
  var sql, param;
  var result = {ok: true, msg: ''};
  
  try {
    sql = `INSERT INTO new_msg_inform ` +
          `(user_id, period, status, try_cnt) ` +
          `VALUES ` +
          `(?, CURRENT_TIMESTAMP(), 'W', 0)`;
          
    param = [member_id];
    await dbs.sqlExec(conn, sql, param);
    //-- Once new record of email inform for this user is added, then set this user to reject further email inform. --//     
    await _setUserInformFlag(conn, member_id, 0);         // 0 = Reject new inform email.      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: e.message};
  } 
    
  return result;
}


//-- Note: Since '_snedMessage' involves multiple tables updating, so it is better to run it within SQL transaction protection. i.e.: Start a SQL   --//
//--       transaction session, then execute involved SQL commands, and determine whether commit or rollback database operations by returned value. --// 
async function _sendMessage(conn, group_id, sender_id, message, fileloc, op_flag, op_user_id, op_msg, http_user_agent, ip_addr) {
  var tx_on, msg_id;
  var result = {ok: true, msg: ''};
  var members = [];
    
  try {
    tx_on = await dbs.startTransaction(conn);
    
    if (tx_on) {
      if (await _isGroupMember(conn, sender_id, group_id)) {
        //-- Step 1: Gather group member list --//        
        members = await _getMessageGroupMembers(conn, group_id);
      
        //-- Step 2: Add message record. Note: Returned value of 'msg_id' is a hexadecimal value of a binary object, which is produced --//
        //--         by default rule "unhex(replace(uuid(), '-', ''))".                                                                --// 
        msg_id = await _addMessageRecord(conn, sender_id, group_id, message, fileloc, op_flag, op_user_id, op_msg, http_user_agent, ip_addr);
        
        //-- Step 3: Delivery message to all members (include message sender) --//
        for (var i = 0; i < members.length; i++) {
          var this_member_id = members[i].user_id;
          result = await _deliverMessage(conn, msg_id, this_member_id, 'U');

          if (result.ok && this_member_id != sender_id) {
            //-- If a member is offline, and user_list.inform_new_msg = 1, then this guy will be informed. --//
            if (await _needToInformMember(conn, this_member_id)) {
              //-- Note: 1. Since email sending is a very slow process, so we put record in a queue, another background process will send out --//
              //--          email to inform group member accordingly.                                                                         --//
              //--       2. Process will go on, even below function is failure.                                                               --//
              await _addNewMessageInformQueueRec(conn, this_member_id);
            }
          }

          if (result.ok == false) {
            //-- If any error is found, abort the process. --//
            break;
          }    
        }
        
        if (result.ok) {
          await dbs.commitTransaction(conn);
        }
        else {
          await dbs.rollbackTransaction(conn);
          //-- If a new message record cannot be created, but related attached file is existed, deleted it. --//
          await wev.deleteFile(fileloc);                           
        }          
      }
      else {
        result.ok = false;
        result.msg = "Message sender is not member of this group, process is aborted.";
        await dbs.rollbackTransaction(conn);
        //-- If a new message record should not be created, but related attached file is existed, deleted it. --//
        await wev.deleteFile(fileloc);
      }
    }
    else {
      result.ok = false;
      result.msg = "Unable to start SQL transaction protection, operation is aborted.";      
      //-- If a new message record should not be created, but related attached file is existed, deleted it. --//
      await wev.deleteFile(fileloc);
    }
  }
  catch(e) {
    if (tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }

  return result;
}


async function _getMessageUpdateToken(conn, group_id) {
  var sql, param, data, result;
  
  result = '';
  
  try {
    sql = `SELECT refresh_token ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = wev.allTrim(data[0].refresh_token);
    }
    else {
      //-- Message group has been deleted or system error has been found --//
      result = "group_deleted";
    }      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = 'error';
  }
    
  return result;
}


exports.sendMessage = async function(msg_pool, group_id, sender_id, message, fileloc, op_flag, op_user_id, op_msg, http_user_agent, ip_addr) {
  var conn, retvals, update_token;
  var result = {mg_status: {update_token: ''}};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    retvals = await _sendMessage(conn, group_id, sender_id, message, fileloc, op_flag, op_user_id, op_msg, http_user_agent, ip_addr);
    
    if (retvals.ok) {
      update_token = await _getMessageUpdateToken(conn, group_id);
      result = {mg_status: {update_token: update_token}};
    }
    else {
      throw new Error(retvals.msg);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


exports.getMessageGroup = async function(conn, user_id) {
  var sqlcmd, param, data, rec;
  var result = [];
  
  try {
    sqlcmd = `SELECT DISTINCT a.group_id, a.group_name, a.group_type, b.group_role ` +
             `  FROM msg_group a, group_member b ` +
             `  WHERE a.group_id = b.group_id ` +
             `    AND b.user_id = ? ` +
             `  ORDER BY a.group_name`;
    
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      var group_id = data[i].group_id;
      var group_name = data[i].group_name;
      var group_type = data[i].group_type;
      var group_role = data[i].group_role;
      var unread_cnt = 0; 
      
      sqlcmd = `SELECT COUNT(*) AS cnt ` +        
               `  FROM msg_tx a, message b ` +
               `  WHERE a.msg_id = b.msg_id ` +
               `    AND a.read_status = 'U' ` +
               `    AND b.group_id = ? ` +
               `    AND a.receiver_id = ?`;
               
      param = [group_id, user_id];
      rec = await dbs.sqlQuery(conn, sqlcmd, param);
      rec = JSON.parse(rec);
      unread_cnt = rec[0].cnt; 
         
      result.push({group_id: group_id, group_name: group_name, group_type: group_type, group_role: group_role, unread_cnt: unread_cnt});
    }
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


exports.isUserGroupMember = async function(msg_pool, user_id, group_id) {
  var conn, is_member;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, 'COOKIE_MSG');
    is_member = await _isGroupMember(conn, user_id, group_id);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return is_member;
}


exports.getMessageGroupName = async function(conn, group_id) {
  var sqlcmd, param, data, result;
  
  result = '';
  
  try {
    sqlcmd = `SELECT group_name ` +
             `  FROM msg_group ` +
             `  WHERE group_id = ?`;
             
    param = [group_id]
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = data[0].group_name;
    }
    else {
      result = 'N/A';
    }         
  }
  catch(e) {
    throw e;
  }
  
  return result;    
}


async function _getMessageUpdateToken(conn, group_id) {
  var sqlcmd, param, data, result;
  
  result = '';
  
  try {
    sqlcmd = `SELECT refresh_token, group_id ` +
             `  FROM msg_group ` +
             `  WHERE group_id = ?`;
             
    param = [group_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      var r_token = data[0].refresh_token;
      var g_id = parseInt(data[0].group_id, 10);
      
      if (g_id == group_id) {
        result = r_token.trim();
      }
      else {
        //-- Unexpected error occurred --//
        result = 'group_deleted';        
      } 
    }
    else {
      //-- -- Message group has been deleted --//
      result = 'group_deleted';
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.getMessageUpdateToken = async function(conn, group_id) {
  var result = '';
    
  try {
    result = await _getMessageUpdateToken(conn, group_id);
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _getGroupRole(conn, group_id, user_id) {
  var sql, param, data, result;
  
  result = 0;
  
  try {
    sql = `SELECT group_role ` +
          `  FROM group_member ` +
          `  WHERE group_id = ? ` +
          `    AND user_id = ?`;
          
    param = [group_id, user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = parseInt(data[0].group_role, 10);
    }
    else {
      throw new Error('No group role is found.');
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;    
}
 

exports.getGroupRole = async function(conn, group_id, user_id) {
  var result = 0;
  
  try {
    result = await _getGroupRole(conn, group_id, user_id);
  }
  catch(e) {
    throw e;
  }
    
  return result;    
}


exports.getGroupName = async function(conn, group_id) {
  var sql, param, data, group_name;
  
  group_name = '';
  
  try {
    sql = `SELECT group_name ` + 
          `  FROM msg_group ` + 
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      group_name = data[0].group_name;
    }
    else {
      throw new Error('No such message group');
    }      
  }
  catch(e) {
    throw e;
  }
  
  return group_name;
}


async function _getGroupSettings(conn, group_id) {
  var sql, param, data;
  var result = {};
  
  try {
    sql = `SELECT group_name, group_type, msg_auto_delete, delete_after_read, algorithm, encrypt_key, status, refresh_token ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = {group_id: data[0].group_id, group_name: data[0].group_name, group_type: data[0].group_type, msg_auto_delete: data[0].msg_auto_delete,
                delete_after_read: data[0].delete_after_read, algorithm: data[0].algorithm, encrypt_key: data[0].encrypt_key, status: data[0].status, 
                refresh_token: data[0].refresh_token};
    }
    else {
      throw new Error('Message group cannot be found.');
    }      
  }
  catch(e) {
    throw e;
  }
    
  return result;  
}


exports.getGroupSettings = async function(conn, group_id) {
  var result = {};
  
  try {
    result = await _getGroupSettings(conn, group_id);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getGroupType(conn, group_id) {
  var group_type;
  var group_profile = {};

  try {
    group_profile = await _getGroupSettings(conn, group_id);
    group_type = parseInt(group_profile.group_type, 10);
  }
  catch(e) {
    throw e;
  }

  return group_type;    
}


exports.getGroupType = async function(conn, group_id) {
  var group_type;

  try {
    group_type = await _getGroupType(conn, group_id);
  }
  catch(e) {
    throw e;
  }

  return group_type;  
}


exports.isPrivateGroup = async function(conn, group_id) {
  var group_type, close_conn, result;

  try {
    if (conn == null) {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      close_conn = true;
    }
    else {
      close_conn = false;
    }
    
    group_type = await _getGroupType(conn, group_id);    
    result = (group_type == 1)? true : false;
  }
  catch(e) {
    throw e;
  }
  finally {
    if (close_conn) {
      await dbs.dbClose(conn);
    }
  }

  return result;  
}


function _12HourTimeFormat(given_time) {    // Note: given_time must be in 12 hours time format.
  var time, hh, mm, ampm, result;
  var parts = [];
  
  try {
    parts = given_time.split(' ');
    time = parts[0].trim();
    ampm = parts[1].trim();
    
    if (time != '' && ampm != '') {
      parts = time.split(':');
      hh = parts[0].trim();
      mm = parts[1].trim();
      result = hh + ':' + mm + ' ' + ampm;   // Format: hour:minute AM/PM     
    }
    else {
      result = given_time;
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = given_time;
  }
  
  return result;  
}


function _descFromNow(time_diff) {
  var hr, min, sec, result;
  var dateparts = []; 

  try {
    dateparts = time_diff.split(':');
    hr = parseInt(dateparts[0], 10);
    min = parseInt(dateparts[1], 10);
    sec = parseInt(dateparts[2], 10);
    
    //-- Only interpret time difference within 60 minutes --//
    if (hr == 0) {
      if (sec >= 30) {
        min++;
      }
      
      if (min == 0) {
        result = 'Just now';
      }
      else {
        result = min.toString() + ' min ago.';
      }
    } 
    else {
      result = '';
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = '';
  }
  
  return result;  
}


function _descWeekDay(mysql_week_day_no) {
  var result;
  
  try {
    switch (mysql_week_day_no) {
      case 0:
        result = 'Mon';
        break;
        
      case 1:
        result = 'Tue';
        break;
            
      case 2:
        result = 'Wed';
        break;
            
      case 3:
        result = 'Thu';
        break;      
      
      case 4:
        result = 'Fri';
        break;      
      
      case 5:
        result = 'Sat';
        break;
            
      case 6:
        result = 'Sun';
        break;      
      
      default:  
        result = '';
    }    
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = '';
  }
  
  return result;
}


async function _checkoutMessage(algorithm, key, iv, msg) {
  let result = '';
  
  try {
    result = wev.disableEmbedJavascript(await cipher.aesDecryptBase64(algorithm, key, iv, msg));
  }
  catch(e) {
    result = "<font color='red'>Due to error, the message on the server cannot be extracted.</font>";
  }
  
  return result;
}


async function _gatherMessage(conn, sql, sql_params, algorithm, key, group_id, user_id, client_device_info) {
  let param, data, is_iOS, err_msg, ok;
  let messages = [];
  let result = {'ok': true, 'msg': '', 'messages': ''};     // Note: 'messages' is a stringified JSON object.
    
  err_msg = '';
  ok = true;
    
  try {
    is_iOS = (client_device_info.os.name.trim() == 'iOS')? true : false; 
    
    //-- Note: the position of values put on 'param' is according to the position of those parameters required --//
    //--       on the SQL command 'sql'. So, if position of required parameters are changed, position of the   --//
    //--       values put on 'param' must be changed accordingly.                                              --//
    param = (Array.isArray(sql_params))? sql_params : [];    
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (let i = 0; i < data.length; i++) {
      let msg_id = data[i].msg_id;     
      let is_my_msg = (data[i].sender_id == user_id)? true : false;     // It means that the user is the sender of this message.
      let sender_id = parseInt(data[i].sender_id, 10);
      let sender = (wev.allTrim(data[i].user_alias) != '')? data[i].user_alias : data[i].user_name;
      let s_datetime = data[i].send_time;
      let s_date = data[i].s_date;
      let s_time = data[i].s_time;
      let s_time_12 = _12HourTimeFormat(data[i].s_time_12); 
      let from_now = _descFromNow(data[i].t_diff);
      let week_day = _descWeekDay(data[i].wday);
      let this_message = await _checkoutMessage(algorithm, key, data[i].iv, data[i].msg);
      let this_ok = true;
      let fileloc = wev.allTrim(data[i].fileloc);
      let op_flag = wev.allTrim(data[i].op_flag);
      let op_user_id = parseInt(data[i].op_user_id, 10);
      let op_user = (op_user_id > 0)? await smslib.getUserName(conn, op_user_id) : '';
      let this_op_msg = await _checkoutMessage(algorithm, key, data[i].op_iv, data[i].op_msg);
      let this_op_ok = true;
      let user_status = data[i].status;
      let is_member = (parseInt(data[i].is_member, 10) == 1)? true : false;
      let is_new_msg = (parseInt(data[i].is_new_msg, 10) == 1)? true : false;
      let this_msg_30 = (this_message.length > 30)? this_message.substring(0, 30) + '...' : this_message;
      let file_info = (fileloc != '')? await wev.fileNameParser(fileloc) : {filename: '', dirs: '', ext: ''};
      let filename = file_info.filename;   // Note: 'filename' is the original file name without extension. e.g. 'filename' of 'example.doc' will be 'example'.
      let dirs = file_info.dirs;           // Note: It is the full directory name where the file is located and it contains '/' at the end.
      let suffix = file_info.ext;          // Note: It is the file extension with '.' in front of it. e.g. extension of 'example.doc' will be '.doc'.
      let file_type = '';
      let file_link = '';

      if (fileloc != '') {
        file_type = await wev.findFileType(conn, suffix);
        
        if (file_type.toLowerCase() == 'image') {
          let thumbnail_file = wev.getGlobalValue('ITN_TN_PATH') + '/' + filename + '.jpg';
          let thumbnail = (await wev.fileExist(thumbnail_file))? '/itnews/data/thumbnail/' + filename + '.jpg' : '/itnews/data/' + filename + suffix;
          
          //-- Note: style="display:block;" for image object is used to restrict the image within a table cell --//
          file_link = `<a href="/itnews/data/` + filename + suffix + `" target="_blank"><img style="display:block;" src="` + thumbnail + `" width="100%"></a>`;
        }
        else if (file_type.match(/audio/i) != null) {
          //-- Since HTML5 multimedia files handling is not consistent, so that it needs to provide a download link below <audio> --//
          //-- object, so that users still have chance to listen the audio file by downloading it.                                --//
          let download_link = `<br><a href="/itnews/data/` + filename + suffix + `" target="_blank">Download Audio</a>`;
          
          file_link = `
          <audio controls>
            <source src="/itnews/data/` + filename + suffix + `" type="` + file_type + `"/>
            <!-- Fallback content //-->
            <p><a href="/itnews/data/` + filename + suffix + `" target="_blank"><img src="/images/folder.png" height="100px"></a><br>` + filename + suffix + `</p>
          </audio>` +          
          download_link;          
        }
        else if (file_type.match(/video/i) != null) {
          //-- Since HTML5 multimedia files handling is not consistent, so that it needs to provide a download link below <video> --//
          //-- object, so that users still have chance to view the video file by downloading it.                                  --//
          let download_link = `<br><a href="/itnews/data/${filename}${suffix}" target="_blank">Download Video</a><br>`;
          
          file_link = `
          <video controls width="100%" preload="meta">
            <source src="/itnews/data/` + filename + suffix + `" type="${file_type}"/>
            <!-- Fallback content //-->
            <p><a href="/itnews/data/` + filename + suffix + `" target="_blank"><img src="/images/folder.png" height="100px"></a><br>` + filename + suffix + `</p>
          </video>` + 
          download_link
        }
        else {
          file_link = `<a href="/itnews/data/` + filename + suffix + `" target="_blank"><img src="/images/folder.png" height="100px"></a><br>` + filename + suffix;          
        }
      }

      if (!this_ok) {
        this_message = 'Error: Original message decryption error, please report to your referrer for supporting.';
        err_msg += 'Unable to decrypt message (message id = ' + msg_id + '). \n';
        ok = 0;
      }
      else {
        this_message = this_message.replace(/\n/g, '<br>');
        this_op_msg = this_op_msg.replace(/\n/g, '<br>');
        this_msg_30 = this_msg_30.replace(/'/g, '¡');         // All single quote characters are replaced by '¡', so that it can be passed to javascript function without error.
        //-- Make URL link(s) on message alive --//
        this_message = wev.makeUrlAlive(this_message); 
      }
      
      // Note: 'iv', 'op_iv' and 'msg_30_iv' will be used in next step. //  
      messages.push({'msg_id': msg_id, 'is_my_msg': is_my_msg, 'sender_id': sender_id, 'sender': sender, 's_datetime': s_datetime,
                     's_date': s_date, 's_time': s_time, 's_time_12': s_time_12, 'from_now': from_now, 'week_day': week_day, 'iv': '',
                     'message': this_message, 'fileloc': fileloc, 'file_link': file_link, 'op_flag': op_flag, 'op_user_id': op_user_id,
                     'op_user': op_user, 'op_msg': this_op_msg, 'op_iv': '', 'user_status': user_status, 'is_member': is_member, 
                     'is_new_msg': is_new_msg, 'msg_30': this_msg_30, 'msg_30_iv': '', 'algorithm': algorithm});
    } 
  }
  catch(e) {
    throw e;
  }
  
  result = {'ok': ok, 'msg': err_msg, 'messages': JSON.stringify(messages)};
  
  return result;
}


async function _markMessagesAreRead(conn, group_id, user_id, http_user_agent) {
  var ok, msg, sql, param;
  var result = {ok: true, msg: ''};
  
  try {
    sql = `UPDATE msg_tx JOIN message ON msg_tx.msg_id = message.msg_id ` +
          `  SET msg_tx.read_status = 'R', ` +
          `      msg_tx.read_time = CURRENT_TIMESTAMP() ` +
          `  WHERE message.group_id = ? ` +
          `    AND msg_tx.receiver_id = ? ` +
          `    AND msg_tx.read_status = 'U'`;
          
    param = [group_id, user_id];
    await dbs.sqlExec(conn, sql, param);          
  }
  catch(e) {
    msg = 'Unable to mark message as read (group_id = ' + group_id + ', receiver_id = ' + user_id + '). Error: ' + e.message;
    ok = 0;
    result.ok = ok;
    result.msg = msg;  
    smslib.consoleLog(msg);
    await smslib.logSystemError(conn, user_id, msg, 'Unable to mark message read status', http_user_agent);    
  }

  return result; 
}


async function _getSessionSecureKey(conn, user_id, sess_code) {
	let sql, param, data, aes_key;
	
	try {
		sql = `SELECT secure_key ` +
		      `  FROM web_session ` +
		      `  WHERE user_id = ? ` +
		      `    AND sess_code = ? ` +
		      `    AND status = 'A'`;
		      
		param = [user_id, sess_code];
		data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
		
		if (data.length > 0) {
			aes_key = wev.allTrim(data[0].secure_key);
			
			if (typeof(aes_key) != "string") {
				throw new Error("Session AES key is lost!");
			} 
			else {
				if (aes_key.length < 16) {
					throw new Error("Session AES key is invalid or too weak!");
				}
			}
		}
		else {
			throw new Error("Invalid session parameters are given!");
		}		      
	}
	catch(e) {
		throw e;
	}
	
	return aes_key;
}


exports.getSessionSecureKey = async function(msg_pool, user_id, sess_code) {
	let conn, aes_key;
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));		
		aes_key = await _getSessionSecureKey(conn, user_id, sess_code);		
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return aes_key;
}


async function _getGroupMessage(conn, group_id, user_id, m_params, client_device_info, http_user_agent) {
  let sql, param, data, new_msg_only, rows_limit, f_m_id, algorithm, key, sql_filter, data_set_rows, sort_order;
  let result = [];
  
  try {
    new_msg_only = m_params.new_msg_only;     // 0 = load all messages, 1 = Load unread messages only.
    rows_limit = m_params.rows_limit;         // It means to get number of last messages as 'rows_limit' specified, if it is larger than zero.
    f_m_id = m_params.f_m_id;                 // ID of the first message which has already loaded.
    
    sql_filter = (new_msg_only == 1)? ` AND d.read_status = 'U' ` : ``;
    //-- Note: Field message.msg_id is now a UUID value, which is not in sequence of message creation time. Therefore, it needs to get the creation time --//
    //--       of 'f_m_id', and use it's creation time (i.e. send_time) as filtering criteria.                                                           --// 
    if (wev.allTrim(f_m_id) != '') {
      //-- Case 1: Previous messages has been loaded, so that messages must be retrieved to the last loaded message, and don't --//
      //--         be limited by pre-defined message block size.                                                               --// 
      //-- Note  : 'send_time' format is very important to get correct data set.                                               --// 
      sql = `SELECT DATE_FORMAT(send_time, '%Y-%m-%d %H:%i:%s') AS send_time ` +
            `  FROM message ` +
            `  WHERE hex(msg_id) = ?`;
            
      param = [f_m_id];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));      

      if (data.length > 0) {      
        let this_send_time = data[0].send_time;
        sql_filter += ` AND a.send_time >= '` + this_send_time + `' `;       
      }
      
      data_set_rows = '';
    }
    else {
      //-- Case 2: No previous messages is loaded, so just load the lastest message block. --//
      data_set_rows = (rows_limit > 0)? 'LIMIT ' + rows_limit.toString() : '';
    }
    
    sort_order = (rows_limit > 0)? 'DESC' : '';

    //-- Step 1: Get group message decryption key --//
    sql = `SELECT algorithm, encrypt_key ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
    
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
			algorithm = data[0].algorithm;
      key = data[0].encrypt_key;
      
      //-- Step 2: Get messages --//
      sql = `SELECT hex(a.msg_id) AS msg_id, a.sender_id, b.user_name, b.user_alias, a.send_time, DATE_FORMAT(DATE(a.send_time), '%Y-%m-%d') AS s_date, TIME(a.send_time) AS s_time, ` +
            `       TIME_FORMAT(TIME(a.send_time), '%r') AS s_time_12, TIMEDIFF(CURRENT_TIMESTAMP(), a.send_time) AS t_diff, WEEKDAY(a.send_time) AS wday, ` +
            `       a.msg, a.iv, a.fileloc, a.op_flag, a.op_user_id, a.op_msg, a.op_iv, b.status, CASE WHEN c.user_id is null THEN 0 ELSE 1 END AS is_member, ` +
            `       CASE WHEN d.read_status = 'U' THEN 1 ELSE 0 END AS is_new_msg ` +
            `  FROM message a LEFT OUTER JOIN group_member c ON a.group_id = c.group_id AND a.sender_id = c.user_id, user_list b, msg_tx d ` +
            `  WHERE a.sender_id = b.user_id ` +
            `    AND a.msg_id = d.msg_id ` + 
            `    AND a.group_id = ? ` +
            `    AND d.receiver_id = ? ` + 
                 sql_filter +
            `  ORDER BY a.send_time ` + sort_order + ` ` +
               data_set_rows;
               
      if (rows_limit > 0) {
        let data_set = sql;
      
        sql = `SELECT * ` +
              `  FROM (` + data_set + `) data_set ` +
              `  ORDER BY send_time ASC`;
      }
            
      //-- Since it has many different ways to extract messages, but returned data set format is equal, so function '_gatherMessage' is created --//
      //-- to return message data set which is formed by same method in order to reduce possible error in the future.                           --//
      let sql_params = [group_id, user_id];
      let task_result = await _gatherMessage(conn, sql, sql_params, algorithm, key, group_id, user_id, client_device_info);
      
      if (task_result.ok) {            
        await _markMessagesAreRead(conn, group_id, user_id, http_user_agent);
      }
      else {
        await smslib.logSystemError(conn, user_id, task_result.msg, 'getGroupMessage error', http_user_agent);
      }
      
      result = JSON.parse(task_result.messages);
    }
    else {
      let msg = 'Unable to get message group encryption key (group id = ' + group_id + ').';
      await smslib.logSystemError(conn, user_id, msg, "getGroupMessage error", http_user_agent);
      throw new Error(msg);
    }
  }
  catch(e) {
    await smslib.logSystemError(conn, user_id, e.message, "getGroupMessage error", http_user_agent);
    throw e;
  }
      
  return result;  
}


exports.getGroupMessage = async function(conn, group_id, user_id, m_params, client_device_info, http_user_agent) {
  var close_conn = false;
  var result = [];
  
  try {
    if (typeof(conn) == 'undefined' || conn == null) {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      close_conn = true;
    }
    
    result = await _getGroupMessage(conn, group_id, user_id, m_params, client_device_info, http_user_agent);
  }
  catch(e) {
    throw e;
  }
  finally {
    if (close_conn) {
      await dbs.dbClose(conn);
    }
  }
  
  return result; 
}


exports.loadGroupMessages = async function(msg_pool, group_id, user_id, m_params, sess_code, client_device_info, http_user_agent) {
  let conn, algorithm, aes_key, token;
  let msg_rec = [];
  let result = {update_token: '', message: msg_rec};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    aes_key = await _getSessionSecureKey(conn, user_id, sess_code);     // It is used to encrypt messages before sent to client side
    algorithm = await _getMessageGroupAlgorithm(conn, group_id);
    msg_rec = await _getGroupMessage(conn, group_id, user_id, m_params, client_device_info, http_user_agent);
    
    //-- Encrypt messages before send to client side --//
		let encrypt_obj;          
		for (let i = 0; i < msg_rec.length; i++) {
			let this_message = msg_rec[i].message;
			let this_op_msg = msg_rec[i].op_msg;
			let this_msg_30 = msg_rec[i].msg_30;
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_message);
			let encrypt_msg = encrypt_obj.encrypted;      // In base64 format
			let enc_msg_iv = encrypt_obj.iv;              // In base64 format;        
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_op_msg);
			let encrypt_op_msg = encrypt_obj.encrypted;
			let enc_op_msg_iv = encrypt_obj.iv;
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_msg_30);
			let encrypt_msg_30 = encrypt_obj.encrypted;
			let enc_msg_30_iv = encrypt_obj.iv;
			
			msg_rec[i].message = encrypt_msg;
			msg_rec[i].iv = enc_msg_iv;
			msg_rec[i].op_msg = encrypt_op_msg;
			msg_rec[i].op_iv = enc_op_msg_iv;
			msg_rec[i].msg_30 = encrypt_msg_30;
			msg_rec[i].msg_30_iv = enc_msg_30_iv;
		}
    
    token = await _getMessageUpdateToken(conn, group_id);
    result = {update_token: token, message: msg_rec};
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


exports.getGroupMessageViaDbPool = async function(msg_pool, group_id, user_id, m_params, sess_code, client_device_info, http_user_agent) {
  var conn, algorithm, aes_key;
  var result = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    aes_key = await _getSessionSecureKey(conn, user_id, sess_code);     // It is used to encrypt messages before sent to client side     
    algorithm = await _getMessageGroupAlgorithm(conn, group_id);        // Message group AES encryption algorithm     
    result = await _getGroupMessage(conn, group_id, user_id, m_params, client_device_info, http_user_agent);
    
    //-- Encrypt messages before send to client side --//
		let encrypt_obj;          
		for (let i = 0; i < result.length; i++) {
			let this_message = result[i].message;
			let this_op_msg = result[i].op_msg;
			let this_msg_30 = result[i].msg_30;
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_message);
			let encrypt_msg = encrypt_obj.encrypted;      // In base64 format
			let enc_msg_iv = encrypt_obj.iv;              // In base64 format;        
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_op_msg);
			let encrypt_op_msg = encrypt_obj.encrypted;
			let enc_op_msg_iv = encrypt_obj.iv;
			
			encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_msg_30);
			let encrypt_msg_30 = encrypt_obj.encrypted;
			let enc_msg_30_iv = encrypt_obj.iv;
			
			result[i].message = encrypt_msg;
			result[i].iv = enc_msg_iv;
			result[i].op_msg = encrypt_op_msg;
			result[i].op_iv = enc_op_msg_iv;
			result[i].msg_30 = encrypt_msg_30;
			result[i].msg_30_iv = enc_msg_30_iv;
		}    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;   
}


async function _markMessageIsRead(conn, group_id, receiver_id, msg_id) {
  var sql, param, result;
  
  try {
    sql = `UPDATE msg_tx JOIN message ON msg_tx.msg_id = message.msg_id ` +
          `  SET msg_tx.read_status = 'R', ` +
          `      msg_tx.read_time = CURRENT_TIMESTAMP() ` +
          `  WHERE message.group_id = ? ` +
          `    AND msg_tx.receiver_id = ? ` +
          `    AND hex(msg_tx.msg_id) = ? ` +
          `    AND msg_tx.read_status = 'U'`;

    param = [group_id, receiver_id, msg_id];
    await dbs.sqlExec(conn, sql, param);        
    result = true;
  }
  catch(e) {
    result = false;
  }
  
  return result;
}


exports.getLastSentMessage = async function(msg_pool, group_id, sender_id, sess_code, client_device_info, http_user_agent) {
  let conn, sql, param, data, key, algorithm, last_sent_msg_id;
  let sql_params = [];
  let result = [];

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Step 1: Get group message decryption key --//
    sql = `SELECT algorithm, encrypt_key ` +
          `  FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      key = data[0].encrypt_key;
      algorithm = data[0].algorithm;
      
      //-- Step 2: Find the last sent message ID --//
      sql = `SELECT hex(msg_id) AS last_msg_id ` +
            `  FROM message ` +
            `  WHERE group_id = ? ` +
            `    AND sender_id = ? ` + 
            `  ORDER BY send_time DESC ` +
            `  LIMIT 0,1`;
      
      param = [group_id, sender_id];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      if (data.length > 0) {
        last_sent_msg_id = data[0].last_msg_id;
        
        //-- Step 3: Extract the last sent message --//
        sql = `SELECT hex(a.msg_id) AS msg_id, a.sender_id, b.user_name, b.user_alias, a.send_time, DATE_FORMAT(DATE(a.send_time), '%Y-%m-%d') AS s_date, TIME(a.send_time) AS s_time, ` +
              `       TIME_FORMAT(TIME(a.send_time), '%r') AS s_time_12, TIMEDIFF(CURRENT_TIMESTAMP(), a.send_time) AS t_diff, WEEKDAY(a.send_time) AS wday, ` + 
              `       a.msg, a.iv, a.fileloc, a.op_flag, a.op_user_id, a.op_msg, a.op_iv, b.status, CASE WHEN c.user_id is null THEN 0 ELSE 1 END AS is_member, ` + 
              `       CASE WHEN d.read_status = 'U' THEN 1 ELSE 0 END AS is_new_msg ` +  
              `  FROM message a LEFT OUTER JOIN group_member c ON a.group_id = c.group_id AND a.sender_id = c.user_id, user_list b, msg_tx d ` +
              `  WHERE a.sender_id = b.user_id ` + 
              `    AND a.msg_id = d.msg_id ` +
              `    AND a.sender_id = d.receiver_id ` +
              `    AND d.read_status = 'U' ` +         
              `    AND a.group_id = ? ` + 
              `    AND hex(d.msg_id) = ?`;

        //-- Since it has many different ways to extract messages, but returned data set format is equal, so function '_gatherMessage' is created --//
        //-- to return message data set which is formed by same method in order to reduce possible error in the future.                           --//         
        sql_params = [group_id, last_sent_msg_id];
        let task_result = await _gatherMessage(conn, sql, sql_params, algorithm, key, group_id, sender_id, client_device_info);
                
        if (task_result.ok) {     
					//-- Get the session AES key for message encryption --//
					let aes_key = await _getSessionSecureKey(conn, sender_id, sess_code);
										     
          //-- Encrypt message before return to client side --//
          let msg_rec = JSON.parse(task_result.messages);
          
          //-- Handle it like it has multiple records, even it contains just one record. --//
          let encrypt_obj;          
          for (let i = 0; i < msg_rec.length; i++) {
            let this_message = msg_rec[i].message;
            let this_op_msg = msg_rec[i].op_msg;
            let this_msg_30 = msg_rec[i].msg_30;
            
            encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_message);
            let encrypt_msg = encrypt_obj.encrypted;      // In base64 format
            let enc_msg_iv = encrypt_obj.iv;              // In base64 format;        
            
            encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_op_msg);
            let encrypt_op_msg = encrypt_obj.encrypted;
            let enc_op_msg_iv = encrypt_obj.iv;
            
            encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_msg_30);
            let encrypt_msg_30 = encrypt_obj.encrypted;
            let enc_msg_30_iv = encrypt_obj.iv;
            
            msg_rec[i].message = encrypt_msg;
            msg_rec[i].iv = enc_msg_iv;
            msg_rec[i].op_msg = encrypt_op_msg;
            msg_rec[i].op_iv = enc_op_msg_iv;
            msg_rec[i].msg_30 = encrypt_msg_30;
            msg_rec[i].msg_30_iv = enc_msg_30_iv;
          }
          
          result = msg_rec;
          await _markMessageIsRead(conn, group_id, sender_id, last_sent_msg_id);
        }  
        else {              
          await smslib.logSystemError(conn, user_id, task_result.msg, 'getLastSentMessage error', http_user_agent);
          throw new Error(task_result.msg);
        }
      }
      else {
        throw new Error(`Unable to get the ID of your last sent message for group ${group_id}`);
      }
    }      
    else {
      throw new Error(`Unable to get decryption key for group ${group_id}`);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }

  return result;
}


async function _messageExist(conn, receiver_id, msg_id) {
  var sql, param, data, result;

  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM message a, msg_tx b ` +
          `  WHERE a.msg_id = b.msg_id ` +
          `    AND b.receiver_id = ? ` +
          `    AND hex(a.msg_id) = ?`;
          
    param = [receiver_id, msg_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = (data[0].cnt > 0)? true : false;
    }
    else {
      result = false;
    }      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    //-- Just play safe, assume the message and it's delivery transaction still exist. --//
    result = true;
  }
    
  return result;  
}


exports.getDeletedMessageIdList = async function(msg_pool, receiver_id, omid_list) {
  var conn;
  var omid = [];
  var result = [];

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    omid = omid_list.split('|');
    
    for (var i = 0; i < omid.length; i++) {
      //-- Note: 1. For private group, if one of my message delivery transaction record is deleted, then related message should  --//
      //--          be considered as 'deleted', even the message still exists.                                                   --//
      //--       2. In a private group, all the messages displaying is from my point of view. i.e. A message will be shown, even --//
      //--          it's delivery transaction record for another group member has been deleted. Conversely, A message will not   --//
      //--          be displayed if it's delivery transaction record for me is deleted.                                          --//
      if (await _messageExist(conn, receiver_id, omid[i]) == false) {
        var this_rec = {msg_id: omid[i], msg_status: 'deleted'};
        result.push(this_rec);
      }    
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }

  return result;
}


//-- Note: Used for websocket operations only --//
exports.getOtherGroupMembers = async function(msg_pool, group_id, user_id, callback) {     // 'callback' is a function to return the result and error (if any) to the caller.
  var conn, sql, param, data, error;
  var result = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    sql = `SELECT user_id ` + 
          `  FROM group_member ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      for (var i = 0; i < data.length; i++) {
        if (data[i].user_id != user_id) {
          result.push(data[i].user_id); 
        }
      }
    }          
  }
  catch(e) {
    smslib.consoleLog(e.message);
    error = e.message;
    result = [];    
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  callback(error, result);
}


async function _isUserLocked(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT status ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = (data[0].status == 'A')? false : true;
    }
    else {
      //-- If unable to find the user, it is better to assume the user has been locked. --//
      result = true;      
    }      
  }
  catch(e) {
    smslib.consoleLog(e.message);
    //-- If unable to get user status, it is better to assume the user has been locked. --//
    result = true;
  }
  
  return result;
}


exports.checkMessageUpdateToken = async function(msg_pool, group_id, user_id) {
  var conn, token;
  var result = {mg_status: {update_token: ''}};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, 'COOKIE_MSG');
    
    if (await _isUserLocked(conn, user_id)) {
      result = {mg_status: {update_token: 'user_locked'}};
    }
    else if (await _isGroupMember(conn, user_id, group_id) == false) {
      result = {mg_status: {update_token: 'not_group_member'}};
    }
    else {
      token = await _getMessageUpdateToken(conn, group_id);
      result = {mg_status: {update_token: token}}; 
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {mg_status: {update_token: 'error', error: e.message}};
  }
  finally {
    dbs.releasePoolConn(conn);
  }
    
  return result;  
}


async function _loadAudioConverter(conn) {
  var audio_converter_setting, audio_converter, result;

  try {
    audio_converter_setting = wev.allTrim(await wev.getSysSettingValue(conn, 'audio_converter')); 
    
    if (audio_converter_setting != '') {
      var parts = audio_converter_setting.split(' ');
      audio_converter = wev.allTrim(parts[0]);         // Audio converter (with full path) must be the first data
      if ((await wev.fileExist(audio_converter)) && audio_converter_setting.match(/{input_file}/) && audio_converter_setting.match(/{output_file}/)) {
        result = audio_converter_setting;
      }
      else {
        result = '';
      }
    }
    else {
      result = '';
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = '';
  }

  return result;
}


exports.uploadFileToMessageGroup = async function(msg_pool, group_id, sender_id, ul_ftype, upload_file, caption, op_flag, op_user_id, op_msg, http_user_agent, ip_addr) {
  var conn, filename, tn_filename, audio_converter, token;
  
  token = '';
  filename = '';
  tn_filename = '';
  audio_converter = '';
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await _isGroupMember(conn, sender_id, group_id)) {
      //-- Load up the audio converter --//
      audio_converter = await _loadAudioConverter(conn);
      
      //-- Step 1: Move the uploaded file to the right place --//
      filename = await wev.fileUpload(upload_file, wev.getGlobalValue('ITN_FILE_PATH'));
      
      //-- Step 2: Process multimedia files. If it is image file, create thumbnail for it. If it is --//
      //--         audio file and can be converted to compatible format handled by mobile devices,  --//
      //--         convert it to compatible audio file format.                                      --//
      if (filename != '') {
        if (ul_ftype == 'photo') {
          //-- Note: The process will continue even thumbnail file can't be created --//
          tn_filename = await wev.createThumbnail(filename, wev.getGlobalValue('ITN_TN_PATH'));          
        }
        else {
          var fileinfo = await wev.fileNameParser(filename);                  
          var file_type = await wev.findFileType(conn, fileinfo.ext);                               
          if (file_type == 'image') {
            //-- Note: The process will continue even thumbnail file can't be created --//
            tn_filename = await wev.createThumbnail(filename, wev.getGlobalValue('ITN_TN_PATH'));      
          }
          else if (file_type == 'aud_convertable' && audio_converter != '') {
            //-- Note: Once an audio file is converted successfully, the value of 'filename' will be changed, and the --//
            //--       original audio file will be deleted. However, if file conversion is failure, the original file --// 
            //--       name will be returned. i.e. The original uploaded file will be used. That means the operation  --//
            //--       will go on even the file conversion process is failure.                                        --//
            filename = await wev.convertAudioFile(audio_converter, filename);     
          }
        }    
      }     
      else {
        throw new Error("The uploaded file is lost!");
      }
      
      //-- Step 3: Send out message --//
      var retvals = await _sendMessage(conn, group_id, sender_id, caption, filename, op_flag, op_user_id, op_msg, http_user_agent, ip_addr);     
      if (retvals.ok) {
        token = await _getMessageUpdateToken(conn, group_id);
      }
      else {
        throw new Error(retvals.msg);
      }      
    }
    else {    
      var msg = `upload_files: User ${sender_id} tries to upload file to group ${group_id}, but this guy is not member of this group. It may be a hacking activity, check for it.`;
      await smslib.logSystemError(conn, sender_id, msg, 'Alert', http_user_agent);
      throw new Error("Can't upload file to a message group as you are not group member");
    }
  }
  catch(e) {
    if (conn) {
      await smslib.logSystemError(conn, sender_id, e.message, 'File upload failure', http_user_agent);
    }
    
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return token;  
}


async function _isMessageOwner(conn, group_id, user_id, msg_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM message ` +
          `  WHERE hex(msg_id) = ? ` +
          `    AND group_id = ? ` +
          `    AND sender_id = ?`;
          
    param = [msg_id, group_id, user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));          
    result = (parseInt(data[0].cnt) > 0)? true : false;
  }
  catch(e) {
    smslib.consoleLog(e.message);
    //-- To play safe, assume the user is not the message owner. --//
    //-- Then, the message will not be deleted until the system  --//
    //-- error is cleared.                                       --//  
    result = false;
  }
  
  return result;  
}


async function _getMessageAttachment(conn, msg_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT fileloc ` +
          `  FROM message ` +
          `  WHERE hex(msg_id) = ?`;
          
    param = [msg_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = wev.allTrim(data[0].fileloc);
    }
    else {
      result = '';
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _removeMessage(conn, msg_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM message ` +
          `  WHERE hex(msg_id) = ?`;
         
    param = [msg_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }  
}


async function _removeMessageDeliveryRecord(conn, msg_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM msg_tx ` +
          `  WHERE hex(msg_id) = ?`;
          
    param = [msg_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }
}


async function _removeMessageDataSet(conn, group_id, msg_id) {
  var tx_on, fileloc, fname, tn_file;
  
  try {
    tx_on = await dbs.startTransaction(conn);
    
    if (tx_on) {
      //-- Step 1: Check whether any file relate to this message --//
      fileloc = await _getMessageAttachment(conn, msg_id);
      
      //-- Step 2: Delete message --//      
      await _removeMessage(conn, msg_id);
      await _removeMessageDeliveryRecord(conn, msg_id);
      await _updateGroupRefreshToken(conn, group_id);       // Note: Message deleteion process will continue even '_updateGroupRefreshToken' is failure.  
      
      //-- Delete attached file (if any), after database is updated sucessfully. --//
      if (wev.allTrim(fileloc) != '') {
        if (await wev.fileExist(fileloc)) {
          await wev.deleteFile(fileloc);
        } 
        
        var fileinfo = await wev.fileNameParser(fileloc);
        fname = fileinfo.filename;
        tn_file = (wev.getGlobalValue('ITN_TN_PATH')) + '/' + fname + '.jpg';
        if (await wev.fileExist(tn_file)) {
          await wev.deleteFile(tn_file);
        }
      }
      
      await dbs.commitTransaction(conn);      
    }
    else {
      throw new Error('Unable to start SQL transaction for this operation, process is aborted.');
    }  
  }
  catch(e) {
    if (tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
}


exports.deleteMessage = async function(msg_pool, group_id, user_id, msg_id, http_user_agent, ip_addr) {
  var conn, token;
  
  token = '';
    
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await _isMessageOwner(conn, group_id, user_id, msg_id)) {
      await _removeMessageDataSet(conn, group_id, msg_id);
      token = await _getMessageUpdateToken(conn, group_id);  
    }
    else {
      var err_msg = `delete_message: User ${user_id} tries to delete message belongs to another user! The message ID is ${msg_id}.`;
      await smslib.logSystemError(conn, user_id, err_msg, 'Alert', http_user_agent);
      throw new Error(err_msg);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return token;
}


exports.removeMessageDataSet = async function(conn, group_id, msg_id) {
  try {
    await _removeMessageDataSet(conn, group_id, msg_id);
  }
  catch(e) {
    throw e;
  }
}


async function _getForwardMessageDetails(conn, msg_id) {
  let sql, param, data;
  let result = {};
  
  try {
    sql = `SELECT a.sender_id, a.iv, a.msg, a.fileloc, b.algorithm, b.encrypt_key ` +
          `  FROM message a, msg_group b ` +
          `  WHERE a.group_id = b.group_id ` +
          `    AND hex(a.msg_id) = ?`;
          
    param = [msg_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
			let message = await cipher.aesDecryptBase64(data[0].algorithm, data[0].encrypt_key, data[0].iv, data[0].msg);			
      result = {sender_id: data[0].sender_id, message: message, fileloc: data[0].fileloc};
    }
    else {
      throw new Error('Unable to get the message to be forwarded, process cannot proceed.');
    }      
  }
  catch(e) {
    throw e;
  }

  return result;  
}


async function _copyForwardFile(file) {
  var filename, dirs, suffix, tn_file, fw_fileloc, fw_tn_file, idx, stop_run;
  var result = {ok: false, msg: 'Not known', fw_fileloc: '', fw_tn_file: ''}; 

  try {
    var fileinfo = await wev.fileNameParser(file);
    filename = fileinfo.filename; 
    dirs = fileinfo.dirs;
    suffix = fileinfo.ext;
    tn_file = wev.getGlobalValue('ITN_TN_PATH') + '/' + filename + '.jpg';
    if (await wev.fileExist(tn_file) == false) {
      tn_file = '';
    }  
    
    idx = 1;
    stop_run = false;
    while (!stop_run) {
      var ver_no = idx.toString().padStart(3, '0');
      fw_fileloc = `${dirs}${filename}-${ver_no}${suffix}`;
      fw_tn_file = (tn_file != '')? wev.getGlobalValue('ITN_TN_PATH') + '/' + `${filename}-${ver_no}.jpg` : '';      // Note: Thumbnail file may not exist.
      
      if (await wev.fileExist(fw_fileloc) == false) {
        stop_run = true;
      }
      else {
        idx++;
        if (idx > 999) {
          //-- Last resort --//
          var curr_time = new Date().getTime();
          fw_fileloc = `${dirs}${filename}-${curr_time}${suffix}`;
          fw_tn_file = (tn_file != '')? wev.getGlobalValue('ITN_TN_PATH') + '/' + `${filename}-${curr_time}.jpg` : '';
          stop_run = true;  
        }
      }        
    }
    
    if (fw_fileloc != '') {
      var cp_ok = await wev.copyFile(file, fw_fileloc);
      
      if (cp_ok) {
        result = {ok: true, msg: '', fw_fileloc: fw_fileloc, fw_tn_file: ''};
        
        if (tn_file != '') {
          //-- Note: Process won't stop even thumbnail file can't be copied --//
          await wev.copyFile(tn_file, fw_tn_file);
          result.fw_tn_file = fw_tn_file;
        }
      }
      else {
        result = {ok: false, msg: `Unable to copy file ${fw_fileloc}`, fw_fileloc: '', fw_tn_file: ''};
      }       
    }
    else {
      result = {ok: false, msg: "By unknown reason, it is unable to determine the name of the attached file of the forwarding message.", fw_fileloc: '', fw_tn_file: ''};
    }
  }
  catch(e) {
    result = {ok: false, msg: e.message, fw_fileloc: '', fw_tn_file: ''};
  }

  return result;  
}


async function _forwardMessage(conn, user_id, to_group_id, a_message, fw_message, http_user_agent, ip_addr) {
  var ok, msg, op_flag, op_user_id, message, fileloc, fw_fileloc, fw_tn_file;

  ok = true;
  msg = '';
  fw_fileloc = '';
  fw_tn_file = '';

  try {
    op_flag = 'F';
    op_user_id = fw_message.sender_id;
    message = fw_message.message;
    fileloc = wev.allTrim(fw_message.fileloc);
    a_message = wev.allTrim(a_message);

    if (fileloc != '') {
      //-- When a message with attached file is forwarded, then the attached file must be copied as a new file for message forwarding. --//
      //-- Otherwise, it would be lost in the forwarded message if the original message is deleted.                                    --//             
      var retval = await _copyForwardFile(fileloc);
      ok = retval.ok;
      msg = retval.msg;
      fw_fileloc = retval.fw_fileloc; 
      fw_tn_file = retval.fw_tn_file;
      
      if (!ok || fw_fileloc == '') {
        throw new Error(`Fail to copy the attached file of the forwarding message. Error: ${msg}`);
      } 
    }
    
    if (ok) {
      //-- Forward the message --//
      await _sendMessage(conn, to_group_id, user_id, message, fw_fileloc, op_flag, op_user_id, '', http_user_agent, ip_addr);
      
      //-- If additional message is for the forwarded message, create it in next message. --// 
      if (a_message != '') {
        await _sendMessage(conn, to_group_id, user_id, a_message, '', '', 0, '', http_user_agent, ip_addr);
      }
    }
  }
  catch(e) {
    //-- If error is found, try to clean up the mess. --//
    if (fw_fileloc != '') {
      await wev.deleteFile(fw_fileloc);
    }
    
    if (fw_tn_file != '') {
      await wev.deleteFile(fw_tn_file);
    }
    
    throw e;
  }
}


async function _informGroupMemberAndGotoGroup(conn, user_id, group_id, clear_local_data) {
  var m_site_dns, wspath, html;
  
  m_site_dns = await wev.getSiteDNS(conn, 'M');
  if (m_site_dns != '') {
    wspath = m_site_dns.replace('https', 'wss') + '/ws';
  }
  else {
    //-- Process will go on even the system unable to inform other group members to refresh messages --//
    smslib.consoleLog("Unable to construct websocket link to inform group members to refresh");
    wspath = '';
  }
  
  //-- Step 1: Load all required javascript libraries --//
  html = `<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
          <link rel="shortcut icon" href="/favicon.ico">
          <script src="/js/jquery.min.js"></script>
          <script src="/js/jquery.mobile-1.4.5.min.js"></script>
          <script src="/js/js.cookie.min.js"></script>
          <script src="/js/common_lib.js"></script> `;
  
  //-- Step 2: If websocket link can be built, inform other group members to refresh message. --//        
  if (wspath != '') {        
    html += `<script>
               var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
               var myWebSocket = null;
               var wsOpenSocket = null;   
               var is_reopen = false;
               var group_id = ${group_id};
               var user_id = ${user_id};
            
               function connectWebServer() {
                 var ws = new WebSocket("${wspath}");
                                        
                 function reopenWebSocket() {                                    
                   is_reopen = true; 
                   myWebSocket = connectWebServer();
                 }
              
                 ws.onopen = function(e) {
                   //-- Once the websocket has been opened, stop the websocket openning scheduler (if it is activated). --//  
                   if (wsOpenSocket != null) {clearTimeout(wsOpenSocket)};
                   
                   var cnt = 0;
                   var stop_run = false;
                   while (!stop_run) {
                     var inform_ok = informGroupMembers(group_id, user_id);
                     if (inform_ok) {
                       stop_run = true;
                     } 
                     else {
                       cnt++;
                       if (cnt >= 10) {
                         console.log("Fail to inform group members to refresh messages");
                         stop_run = true;
                       }
                       else {
                         sleep(100);
                       }
                     }
                   }
                 }
                                
                 ws.onclose = function(e) {
                   //-- Reopen websocket automatically within 100ms --//
                   wsOpenSocket = setTimeout(reopenWebSocket, 100);
                 }
                
                 ws.onerror = function(e) {
                   console.log('Error: ' + e.message);
                 }
                
                 return ws;
               }          
              
               function informGroupMembers(group_id, user_id) {
                 var result;
                
                 if (typeof(myWebSocket) != 'undefined' && myWebSocket != null) {
                   var packet = {type: 'msg', content: {op: 'msg_refresh', group_id: group_id, user_id: user_id}};
                   myWebSocket.send(JSON.stringify(packet));
                   result = true;
                 }
                 else {
                   console.log("Websocket handler is lost!");
                   result = false;
                 }              
                
                 return result;
               }

               function sleep(ms) {
                 return new Promise(resolve => setTimeout(resolve, ms));
               }

               myWebSocket = connectWebServer(); `;               
  }
  else {
    html += `<script>
               alert("Unable to inform group members to refresh messages!");
               var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false); `;                 
  }              
  
  //-- Step 3: If it needs to switch to another message group, delete all storage data. --// 
  if (clear_local_data) {
    html += `if (is_iOS) {
               Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
               Cookies.remove("u_id");
               Cookies.remove("m_id");
               Cookies.remove("top_id");
             }
             else {
               deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
               deleteLocalStoredItem("u_id");                             
               deleteLocalStoredItem("m_id");                             
               deleteLocalStoredItem("top_id");                                   
             } `;
  }

  //-- Step 4: Build page redirection link --//
  html += `  var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");        // Defined on common_lib.js : js.cookie.min.js
             var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
             window.location.href = "/do_sms?g_id=${group_id}&f_m_id=" + f_m_id + "&top_id=" + top_id;
           </script>`;
  
  return html;  
}


exports.forwardMessage = async function(msg_pool, from_group_id, to_group_id, user_id, msg_id, a_message, http_user_agent, ip_addr) {
  var conn, is_from_group_member, is_to_group_member, html;
  var fw_message = {};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    is_from_group_member = await _isGroupMember(conn, user_id, from_group_id);
    is_to_group_member = await _isGroupMember(conn, user_id, to_group_id);
    
    if (is_from_group_member && is_to_group_member) {
      //-- Get details of the forwarded message and send to the new group --//
      fw_message = await _getForwardMessageDetails(conn, msg_id);
      await _forwardMessage(conn, user_id, to_group_id, a_message, fw_message, http_user_agent, ip_addr);
      
      //-- If everything is OK, prepare a HTML page to switch to the group which the message --//
      //-- is forwarded to, and inform all members in that group to refresh.                 --// 
      if (from_group_id == to_group_id) {
        html = await _informGroupMemberAndGotoGroup(conn, user_id, from_group_id, false);
      }
      else {
        html = await _informGroupMemberAndGotoGroup(conn, user_id, to_group_id, true);
      }    
    } 
    else {
      //-- Log down potential hacking activity and force log out the current user --//
      var msg = '';
      
      if (!is_from_group_member && is_to_group_member) {
        msg = `User ${user_id} tries to steal message from another group`;
      }
      else if (is_from_group_member && !is_to_group_member) {
        msg = `User ${user_id} tries to give his/her message to another group which he/she is not member`;
      }
      else {
        msg = `User ${user_id} tries to hack the system and steal messages from other groups`;
      }
      
      await smslib.logSystemError(conn, user_id, msg, 'Alert', http_user_agent); 
      
      html = `<script>
                alert("The system has detected you are doing something abnormal, you are forced to logout."); 
                var url = window.location.href;
                var host = url.split('/');
                location.href = host[0] + '//' + host[2] + '/logout_msg';
              </script>`;
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.getPrevGroupMessage = async function(msg_pool, group_id, user_id, first_msg_id, rows_limit, sess_code, client_device_info, http_user_agent, ip_addr) {
  let conn, enc_info, algorithm, key, aes_key, sql, sql_params;
  let message = {msg_status: '', message: ''};

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG')); 
    
    group_id = (parseInt(group_id, 10) > 0)? group_id : 0;
    user_id = (parseInt(user_id, 10) > 0)? user_id : 0;
    first_msg_id = wev.allTrim(first_msg_id);
    rows_limit = (parseInt(rows_limit, 10) > 0)? rows_limit : 0;
    
    //-- Step 1: Check validity of passed parameters --//
    if (group_id <= 0 || user_id <= 0 || first_msg_id == '' || rows_limit <= 0) {
      let msg = `Invalid parameter(s) is/are found. Parameters: group id = ${group_id}, user id = ${user_id}, first message id = ${first_msg_id}, message block size = ${rows_limit}.`;
      message = {msg_status: 'error', message: msg};;
    }
    else {
      //-- Step 2: Get group message decryption key --//
      enc_info = await _getMessageGroupEncryptInfo(conn, group_id);
      algorithm = enc_info.algorithm;
      key = enc_info.key;
                  
      //-- -- Step 3: Get messages --//
      sql = `SELECT hex(a.msg_id) AS msg_id, a.sender_id, b.user_name, b.user_alias, a.send_time, DATE_FORMAT(DATE(a.send_time), '%Y-%m-%d') AS s_date, TIME(a.send_time) AS s_time, ` +
            `       TIME_FORMAT(TIME(a.send_time), '%r') AS s_time_12, TIMEDIFF(CURRENT_TIMESTAMP(), a.send_time) AS t_diff, WEEKDAY(a.send_time) AS wday, ` +
            `       a.msg, a.iv, a.fileloc, a.op_flag, a.op_user_id, a.op_msg, a.op_iv, b.status, CASE WHEN c.user_id is null THEN 0 ELSE 1 END AS is_member, ` +
            `       CASE WHEN d.read_status = 'U' THEN 1 ELSE 0 END AS is_new_msg ` +
            `  FROM message a LEFT OUTER JOIN group_member c ON a.group_id = c.group_id AND a.sender_id = c.user_id, user_list b, msg_tx d ` +
            `  WHERE a.sender_id = b.user_id ` +
            `    AND a.msg_id = d.msg_id ` + 
            `    AND a.group_id = ? ` +
            `    AND d.receiver_id = ? ` +
            `    AND a.send_time < (SELECT send_time FROM message WHERE hex(msg_id) = ?) ` +
            `  ORDER BY a.send_time DESC ` +
            `  LIMIT ${rows_limit}`;
      
      sql_params = [group_id, user_id, first_msg_id];       
      let retval = await _gatherMessage(conn, sql, sql_params, algorithm, key, group_id, user_id, client_device_info)
      
      if (retval.ok) {
				//-- Get the session AES key for message encryption --//
				aes_key = await _getSessionSecureKey(conn, user_id, sess_code);
				
        //-- Encrypt messages before send to client side --//
        let msg_rec = JSON.parse(retval.messages);
                
        let encrypt_obj;
        for (let i = 0; i < msg_rec.length; i++) {
          let this_message = msg_rec[i].message;
          let this_op_msg = msg_rec[i].op_msg;
          let this_msg_30 = msg_rec[i].msg_30;
        
					encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_message);
					let encrypt_msg = encrypt_obj.encrypted;      // In base64 format
					let enc_msg_iv = encrypt_obj.iv;              // In base64 format;        
					
					encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_op_msg);
					let encrypt_op_msg = encrypt_obj.encrypted;
					let enc_op_msg_iv = encrypt_obj.iv;
					
					encrypt_obj = await cipher.aesEncryptBase64(algorithm, aes_key, this_msg_30);
					let encrypt_msg_30 = encrypt_obj.encrypted;
					let enc_msg_30_iv = encrypt_obj.iv;
					
					msg_rec[i].message = encrypt_msg;
					msg_rec[i].iv = enc_msg_iv;
					msg_rec[i].op_msg = encrypt_op_msg;
					msg_rec[i].op_iv = enc_op_msg_iv;
					msg_rec[i].msg_30 = encrypt_msg_30;
					msg_rec[i].msg_30_iv = enc_msg_30_iv;
        } 
        
        message = {msg_status: 'ok', message: JSON.stringify(msg_rec)};
      }
      else {
        message = {msg_status: 'error', message: retval.err_msg};
      }
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return message;
}


async function _getUserRole(conn, user_id) {
  var sql, param, data, result;
  
  result = 0;
  
  try {
    sql = `SELECT user_role ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = parseInt(data[0].user_role, 10);
    }
    else {
      throw new Error('No such user');
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.getUserRole = async function(conn, user_id) {
  var result;
  
  try {
    result = await _getUserRole(conn, user_id);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.hasRightToMgtMember = async function(msg_pool, group_id, user_id) {
  var conn, result;
  
  result = 0;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Check whether this user is group administrator --//
    result = await _getGroupRole(conn, group_id, user_id);
    
    if (result == 0) {
      //-- If current user is not group administrator, check whether he/she is system administrator. --// 
      result = await _getUserRole(conn, user_id);
      
      if (result < 2) {
        result = 0;
      }
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return (result > 0)? true : false;  
}


async function _findAndVerifyNewMember(conn, group_id, user_id, new_members) {
  var sql, param, data;
  var result = [];
    
  try {
    for (var i = 0; i < new_members.length; i++) {
      var this_alias = new_members[i];
      var this_username = '';
      var this_user_id = 0;
      
      //-- Step 1: Try to find the new member by his/her alias. --//
      sql = `SELECT user_id, user_name ` +
            `  FROM user_list ` +
            `  WHERE user_alias = ? ` +
            `    AND status = 'A' `;
      
      param = [this_alias];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      if (data.length > 0) {
        this_user_id = data[0].user_id;
        this_username = data[0].user_name;
        
        if (this_user_id != user_id) {   // Don't invite yourself 
          //-- Step 2: If the guy does exist, then check whether he/she has already been member of the group. If he/she is not --//
          //--         group member, grant he/she as a valid candidate. Otherwise, reject him/her.                             --//
          sql = `SELECT COUNT(*) AS cnt ` +
                `  FROM group_member ` +
                `  WHERE group_id = ? ` +
                `    AND user_id = ?`;
          
          param = [group_id, this_user_id];
          data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
          
          if (data[0].cnt == 0) {
            result.push({user_id: this_user_id, user_name: this_username, alias: this_alias});
          }
        }
      }       
    }    
  }
  catch(e) {
    throw e;  
  }
  
  return result;
}


async function _loadGroupMessagesForNewMember(conn, group_id, member_id) {
  var sql, param, data;
  
  try {
    //-- Step 1: Find out all missing messages for the new member --//
    sql = `SELECT DISTINCT hex(a.msg_id) AS msg_id ` +
          `  FROM message a, msg_tx b ` +
          `  WHERE a.msg_id = b.msg_id ` +
          `    AND a.group_id = ? ` +
          `    AND b.receiver_id <> ?`;
    
    param = [group_id, member_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));

    //-- Step 2: Recreate message delivery transaction records for the new member --//    
    for (var i = 0; i < data.length; i++) {
      sql = `INSERT INTO msg_tx ` +
            `(msg_id, receiver_id, read_status) ` +
            `VALUES ` +
            `(unhex(?), ?, 'U')`;
      
      param = [data[i].msg_id, member_id];
      await dbs.sqlExec(conn, sql, param);
    }    
  }
  catch(e) {
    throw e;
  }
}


async function _addNewGroupMember(conn, group_id, final_members, http_user_agent, ip_addr) {
  var sql, param, msg;
  
  msg = '';
  
  try {
    for (var i = 0; i < final_members.length; i++) {
      var this_user_id = final_members[i].user_id;
      var this_member = (wev.allTrim(final_members[i].alias) == '')? final_members[i].user_name : final_members[i].alias;
      
      //-- Step 1: Add new member to the group --//
      sql = `INSERT INTO group_member ` +
            `(group_id, user_id, group_role) ` +
            `VALUES ` +
            `(?, ?, 0)`; 
            
      param = [group_id, this_user_id];      
      await dbs.sqlExec(conn, sql, param);
      
      //-- Step 2: Resent existing old messages to the new member --//
      await _loadGroupMessagesForNewMember(conn, group_id, this_user_id);
      
      //-- Step 3: The new member sends an inform message to all other group members --//    
      var message = `I am ${this_member}, just join this group.`;
      await _sendMessage(conn, group_id, this_user_id, message, '', '', 0, '', http_user_agent, ip_addr);
    }    
  }
  catch(e) {
    smslib.consoleLog(e.message);
    msg = e.message; 
  }
  
  return msg;
}


exports.addNewMemberToGroup = async function(msg_pool, group_id, user_id, new_members, http_user_agent, ip_addr) {
  var conn, msg;
  var final_members = [];
  
  msg = '';
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Verify proposed new members to added --//
    final_members = await _findAndVerifyNewMember(conn, group_id, user_id, new_members);
    
    if (final_members.length > 0) {
      msg = await _addNewGroupMember(conn, group_id, final_members, http_user_agent, ip_addr);      
    }
    else {
      msg = "It is either proposed new member(s) don't exist or qualify, no member is added.";         
    }
    
    if (msg == '') {
      msg = 'Success';
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return msg;
}


exports.removeMemberFromGroup = async function(msg_pool, group_id, delete_members) {
  try {
    for (var i = 0; i < delete_members.length; i++) {
      smslib.quitMessageGroup(msg_pool, group_id, delete_members[i]);
    }
  }
  catch(e) {
    throw e;
  }
}


exports.promoteGroupMember = async function(msg_pool, group_id, promote_members) {
  var conn, sql, param;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    for (var i = 0; i < promote_members.length; i++) {
      var this_member_id = promote_members[i];
      
      sql = `UPDATE group_member ` +
            `  SET group_role = '1' ` +
            `  WHERE group_id = ? ` +
            `    AND user_id = ?`;
            
      param = [group_id, this_member_id];
      await dbs.sqlExec(conn, sql, param);      
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
}


exports.demoteGroupAdmin = async function(msg_pool, group_id, demote_admin) {
  var conn, sql, param;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    for (var i = 0; i < demote_admin.length; i++) {
      var this_member_id = demote_admin[i];
      
      sql = `UPDATE group_member ` +
            `  SET group_role = '0' ` +
            `  WHERE group_id = ? ` +
            `    AND user_id = ?`;
            
      param = [group_id, this_member_id];
      await dbs.sqlExec(conn, sql, param);      
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }  
}


exports.sendGroupInformMessage = async function(msg_pool, group_id, inform_message) {
  var conn, sql, param, data, msg, url, subject, mail_body, tg_bot_api_token;
  var from_mail, from_user, from_pass, smtp_server, port;
  var mail_worker = {};
  
  msg = '';
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Note: Just send out email and Telegram message to inform those group --//
    //--       members who do not read their SMS messages.                    --// 
    sql = `SELECT DISTINCT a.user_id, a.email, a.tg_id ` +
          `  FROM user_list a, msg_tx b, message c ` +
          `  WHERE a.user_id = b.receiver_id ` +
          `    AND b.msg_id = c.msg_id ` +
          `    AND c.group_id = ? ` +
          `    AND b.read_status = 'U' ` +
          `    AND a.status = 'A'`;
          
    param = [group_id];      
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length == 0) {
      msg = "All members read all the messages, no need to send out notified message.";
    }
    else {
      //-- Obtain Telegram Bot API token (if any) --//
      tg_bot_api_token = wev.allTrim(await telecom.getTelegramBotApiToken(conn));
      
      //-- Get email worker data --//
      mail_worker = await telecom.getMailWorker(conn);
      
      if (tg_bot_api_token == '' && mail_worker.email == null) {
        msg = "No Telegram Bot and email worker are found, so that you cannot inform group member(s). Operation is aborted.";
      }
      else {
        if (tg_bot_api_token == '') {
          msg = "No Telegram Bot has been defined, so that the system just inform group member(s) via email.";
        }
        else if (mail_worker.email == null) {
          msg = "No email worker is found, so that the system just inform group member(s) via Telegram. However, system can't inform those group member(s) without Telegram ID.";  
        }
        
        if (mail_worker.email != null) {
          from_mail = mail_worker.email;
          from_user = mail_worker.m_user;
          from_pass = mail_worker.m_pass; 
          smtp_server = mail_worker.smtp_server;
          port = mail_worker.port;
        }
                
        url = await wev.getSiteDNS(conn, 'D');
        subject = "Important News";
        mail_body = `${inform_message} \n\n${url}\n`;

        for (var i = 0; i < data.length; i++) {
          var this_user_id = data[i].user_id;
          var this_to_mail = data[i].email;
          var this_tg_id = wev.allTrim(data[i].tg_id);
          
          if (mail_worker.email != null) {
            //-- Send inform email --//
            await telecom.sendEmail(smtp_server, port, from_mail, this_to_mail, from_user, from_pass, subject, mail_body);
            smslib.consoleLog(`Has sent inform email to user ${this_user_id}`);
          }
          
          if (tg_bot_api_token != '' && this_tg_id != '') {
            //-- Send Telegram message --//
            await telecom.sendTelegramMessage(tg_bot_api_token, this_tg_id, mail_body);            
            smslib.consoleLog(`Has sent inform Telegram message to user ${this_user_id}`);
          }           
        }
        
        var result_msg = 'Members are informed';
        if (msg == '') {
          msg = result_msg;
        }
      }
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return msg;
}


async function _getGroupAttachedFiles(conn, group_id) {
  var sql, param, data, tn_path;
  var result = [];
  
  try {
    tn_path = wev.getGlobalValue('ITN_TN_PATH');
    
    sql = `SELECT fileloc ` +
          `  FROM message ` +
          `  WHERE group_id = ? ` +
          `    AND TRIM(fileloc) <> '' ` +
          `    AND fileloc IS NOT NULL`;
          
    param = [group_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      var this_file = data[i].fileloc;
      var file_info = await wev.fileNameParser(this_file);
      var this_filename = wev.allTrim(file_info.filename);
      var this_tn_file = `${tn_path}/${this_filename}.jpg`;   
      
      result.push(this_file);
      //-- If related thumbnail file exists, include it also. --//
      if (await wev.fileExist(this_tn_file)) {
        result.push(this_tn_file);
      }
    }          
  }
  catch(e) {
    throw e;
  }

  return result;
}


async function _removeGroup(conn, group_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM msg_group ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }  
}


async function _removeGroupMember(conn, group_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM group_member ` +
          `  WHERE group_id = ?`;
          
    param = [group_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }  
}


async function _removeGroupMessageAndDeliveryHistory(conn, group_id) {
  var sql, param;
  
  try {
    sql = `DELETE message, msg_tx ` + 
          `  FROM message INNER JOIN msg_tx ON message.msg_id = msg_tx.msg_id ` +
          `  WHERE message.group_id = ?`;
          
    param = [group_id];
    await dbs.sqlExec(conn, sql, param);       
  }
  catch(e) {
    throw e;
  }
}


async function _deleteGroupAttachedFiles(attached_files) {
  for (var i = 0; i < attached_files.length; i++) {
    var this_file = attached_files[i];
    
    if (await wev.fileExist(this_file)) {
      var ok = await wev.deleteFile(this_file);
      
      if (ok) {
        smslib.consoleLog(`delete_group: ${this_file} is deleted.`);
      }
      else {
        smslib.consoleLog(`delete_group: ${this_file} can't be deleted.`);
      }  
    }
    else {
      smslib.consoleLog(`delete_group: ${this_file} doesn't exist.`);
    }
  }
}


exports.deleteMessageGroup = async function(msg_pool, group_id) {
  var conn, ok;
  var attached_files = [];
  
  ok = true;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      //-- Step 1: Get the list of all attachment files of the group --//
      attached_files = await _getGroupAttachedFiles(conn, group_id);

      //-- Step 2: Delete group, messages and delivery transactions --// 
      await _removeGroup(conn, group_id);
      await _removeGroupMember(conn, group_id);
      await _removeGroupMessageAndDeliveryHistory(conn, group_id);
      
      //-- Step 3: Commit SQL transaction --//
      if (await dbs.commitTransaction(conn)) {
        if (attached_files.length > 0) {
          //-- Step 4: If SQL transaction is committed, delete all attachment --//
          //--         files (if any).                                        --// 
          await _deleteGroupAttachedFiles(attached_files);
        }
      }
      else {
        await dbs.rollbackTransaction(conn);
        ok = false;
      }
    }
    else {
      throw new Error('Unable to start SQL transaction session, operation aborted.');
    }
  }
  catch(e) {
    await dbs.rollbackTransaction(conn);
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);    
  }
  
  return ok;
}


exports.updateAutoDeleteSettings = async function(msg_pool, group_id, auto_delete, delete_after) {
  var conn, sql, param;
  
  
  try {
    //-- Note: As we set 'auto delete' to 'off', then passed value of 'auto_delete' is 'undefined'. --//
    auto_delete = (typeof(auto_delete) == 'undefined')? 0 : parseInt(auto_delete, 10);    
    //-- Ensure it is an integer, not a real number with decimal points. --//
    delete_after = Math.round(delete_after);       
    
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
        
    sql = `UPDATE msg_group ` +
          `  SET msg_auto_delete = ?, ` +
          `      delete_after_read = ? ` +
          `  WHERE group_id = ?`;
    
    param = [auto_delete, delete_after, group_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
}


async function _aliasHasBeenUsed(conn, user_id, alias) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM user_list ` +
          `  WHERE user_alias = ? ` +
          `    AND user_id <> ?`;
          
    param = [alias, user_id];      
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;          
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _saveUserAlias(conn, user_id, alias) {
  var sql, param;
  
  try {
    sql = `UPDATE user_list ` +
          `  SET user_alias = ? ` +
          `  WHERE user_id = ?`;
          
    param = [alias, user_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }
}


exports.updateUserAlias = async function(msg_pool, user_id, alias) {
  var conn;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await _aliasHasBeenUsed(conn, user_id, alias)) {
      result = {ok: false, msg: 'Alias ' + alias + ' is invalid'};
    }
    else {
      await _saveUserAlias(conn, user_id, alias);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


async function _saveUserEmail(conn, user_id, email) {
  var sql, param;
  
  try {
    sql = `UPDATE user_list ` + 
          `  SET email = ? ` +
          `  WHERE user_id = ?`;
          
    param = [email, user_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }  
}


exports.updateUserEmail = async function(msg_pool, user_id, email) {
  var conn;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    await _saveUserEmail(conn, user_id, email);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }  
  
  return result;
}


async function _telegramIdBelongsToAnotherUser(conn, user_id, tg_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM user_list ` +
          `  WHERE tg_id = ? ` +
          `    AND user_id <> ? ` +
          `    AND status = 'A'`;
    
    param = [tg_id, user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;    
}


async function _saveUserTelegramId(conn, user_id, tg_id) {
  var sql, param;
  
  try {
    sql = `UPDATE user_list ` + 
          `  SET tg_id = ? ` +
          `  WHERE user_id = ?`;
          
    param = [tg_id, user_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }    
}


exports.updateUserTelegramId = async function(msg_pool, user_id, tg_id) {
  var conn;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await _telegramIdBelongsToAnotherUser(conn, user_id, tg_id)) {
      result = {ok: false, msg: 'Telegram ID ' + tg_id + ' is invalid'};
    }
    else {
      await _saveUserTelegramId(conn, user_id, tg_id);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


async function _equalUnhappyPassword(conn, user_id, happy_passwd) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT unhappy_passwd ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = await cipher.isPasswordMatch(happy_passwd, data[0].unhappy_passwd);
    }
    else {
      throw new Error('Unable to get unhappy password to verify with the new happy password.');
    }       
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.updateUserHappyPassword = async function(msg_pool, user_id, happy_passwd) {
  var conn, sql, param, encrypt_happy_passwd;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
        
    if (await _equalUnhappyPassword(conn, user_id, happy_passwd)) {
      result = {ok: false, msg: 'Happy password must not be equal to unhappy password!'};      
    }
    else {
      encrypt_happy_passwd = await cipher.encryptPassword(happy_passwd);
      
      sql = `UPDATE user_list ` + 
            `  SET happy_passwd = ? ` + 
            `  WHERE user_id = ?`;
            
      param = [encrypt_happy_passwd, user_id];          
      await dbs.sqlExec(conn, sql, param);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;    
}


async function _equalHappyPassword(conn, user_id, unhappy_passwd) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT happy_passwd ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = await cipher.isPasswordMatch(unhappy_passwd, data[0].happy_passwd);
    }
    else {
      throw new Error('Unable to get happy password to verify with the new unhappy password.');
    }       
  }
  catch(e) {
    throw e;
  }
  
  return result;    
}


exports.updateUserUnhappyPassword = async function(msg_pool, user_id, unhappy_passwd) {
  var conn, sql, param, encrypt_unhappy_passwd;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));

    if (await _equalHappyPassword(conn, user_id, unhappy_passwd)) {
      result = {ok: false, msg: 'Unhappy password must not be equal to happy password!'};      
    }
    else {    
      encrypt_unhappy_passwd = await cipher.encryptPassword(unhappy_passwd);
      
      sql = `UPDATE user_list ` + 
            `  SET unhappy_passwd = ? ` + 
            `  WHERE user_id = ?`;
            
      param = [encrypt_unhappy_passwd, user_id];          
      await dbs.sqlExec(conn, sql, param);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;      
}


async function _verifyMembers(conn, user_id, members) {
  var sql, param, data;
  var list = [];
  
  try {
    for (var i = 0; i < members.length; i++) {
      var this_alias = members[i];
      
      sql = `SELECT user_id ` + 
            `  FROM user_list ` +
            `  WHERE user_alias = ? ` +
            `    AND status = 'A'`;
            
      param = [this_alias];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      if (data.length > 0) {
        var user_exist = false;
        //-- Case 1: No duplicate user is allowed --//
        for (var k = 0; k < list.length; k++) {
          if (list[k] == data[0].user_id) {
            user_exist = true;
            break;
          }
        }
        
        //-- Case 2: No group creator should be included --// 
        if (data[0].user_id == user_id) {
          user_exist = true;
        }
        
        if (!user_exist) {
          list.push(data[0].user_id);
        } 
      }            
    }    
  }
  catch(e) {
    throw e;
  }
  
  return list;
}


async function _addMessageGroup(conn, group_name, msg_auto_delete) {
  var sql, param, data, group_id, encrypt_key;
  
  try {
    group_id = 0;
    encrypt_key = cipher.generateTrueRandomStr('A', 32);
    
    sql = `INSERT INTO msg_group ` + 
          `(group_name, group_type, msg_auto_delete, delete_after_read, algorithm, encrypt_key, status, refresh_token) ` +
          `VALUES ` +
          `(?, 0, ?, 0, 'AES-GCM', ?, 'A', '')`;
          
    param = [group_name, msg_auto_delete, encrypt_key];
    data = JSON.parse(await dbs.sqlExec(conn, sql, param));
    
    if (data.affectedRows > 0) {      
      sql = `SELECT LAST_INSERT_ID() AS last_group_id`;
      data = JSON.parse(await dbs.sqlQuery(conn, sql));
      if (data.length > 0) {
        group_id = data[0].last_group_id;
      }
    }
  }  
  catch(e) {
    throw e;
  }
  
  return group_id;    
}


async function _addGroupMember(conn, group_id, user_id, final_list) {
  var sql, param;
  
  try {
    //-- This is the group administrator --//
    sql = `INSERT INTO group_member ` +
          `(group_id, user_id, group_role) ` +
          `VALUES ` +
          `(?, ?, '1')`;
          
    param = [group_id, user_id];
    await dbs.sqlExec(conn, sql, param);      
    
    //-- Add other group members --//
    for (var i = 0; i < final_list.length; i++) {
      var this_member_id = final_list[i];
      
      sql = `INSERT INTO group_member ` +
            `(group_id, user_id, group_role) ` +
            `VALUES ` +
            `(?, ?, '0')`;
      
      param = [group_id, this_member_id];
      await dbs.sqlExec(conn, sql, param);
    }
  }
  catch(e) {
    throw e;
  }
}


async function _sendMemberFirstMessage(conn, group_id, user_id, http_user_agent, ip_addr) {
  var message;
  
  try {
    message = "You are invited to join this group.";
    await _sendMessage(conn, group_id, user_id, message, '', '', 0, '', http_user_agent, ip_addr);
  }
  catch(e) {
    throw e;
  }  
}


exports.createMessageGroup = async function(msg_pool, user_id, group_name, msg_auto_delete, members, http_user_agent, ip_addr) {
  var conn, group_id;
  var final_list = [];
  var result = {ok: true, msg: ''};

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    final_list = await _verifyMembers(conn, user_id, members);
    
    if (final_list.length > 0) {    
      if (await dbs.startTransaction(conn)) {
        group_id = await _addMessageGroup(conn, group_name, msg_auto_delete);
        
        if (group_id > 0) {
          await _addGroupMember(conn, group_id, user_id, final_list);            
        }
        else {
          result = {ok: false, msg: 'Unable to get the ID of the newly created message group.'};
        }
                
        if (result.ok) {
          await dbs.commitTransaction(conn);
          await _sendMemberFirstMessage(conn, group_id, user_id, http_user_agent, ip_addr);
        }
        else {
          await dbs.rollbackTransaction(conn);
        }
      }
      else {
        result = {ok: false, msg: 'Unable to start transaction session, process cannot proceed.'};
      }
    }
    else {
      result = {ok: false, msg: 'Given aliases are invalid.'};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn); 
  }
   
  return result;  
}


async function _getMemberId(conn, member) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT user_id ` +
          `  FROM user_list ` +
          `  WHERE user_alias = ? ` +
          `    AND status = 'A'`;
          
    param = [member];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = data[0].user_id;
    }
    else {
      result = 0;
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _addPrivateGroup(conn, group_name, auto_delete, delete_after) {
  var sql, param, data, group_id, encrypt_key;
  
  try {
    group_id = 0;
    encrypt_key = cipher.generateTrueRandomStr('A', 32);
    
    sql = `INSERT INTO msg_group ` +
          `(group_name, group_type, msg_auto_delete, delete_after_read, algorithm, encrypt_key, status, refresh_token) ` +
          `VALUES ` +
          `(?, 1, ?, ?, 'AES-GCM', ?, 'A', '')`;
          
    param = [group_name, auto_delete, delete_after, encrypt_key];      
    data = JSON.parse(await dbs.sqlExec(conn, sql, param));
    
    if (data.affectedRows > 0) {      
      sql = `SELECT LAST_INSERT_ID() AS last_group_id`;
      data = JSON.parse(await dbs.sqlQuery(conn, sql));
      if (data.length > 0) {
        group_id = data[0].last_group_id;
      }
    }
  }
  catch(e) {
    throw e;
  } 

  return group_id;    
}


async function _createPrivateMessageGroup(conn, user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr) {
  var member_id, group_id;
  var result = {ok: true, msg: ''};
  
  try {
    member_id = await _getMemberId(conn, member);
    
    if (member_id == 0) {
      result = {ok: false, msg: "The person you want to invit does not exist."};
    }
    else if (member_id == user_id) {
      result = {ok: false, msg: "Guy, do not invit yourself to form a private group."};
    }
    else {
      if (await dbs.startTransaction(conn)) {      
        group_id = await _addPrivateGroup(conn, group_name, auto_delete, delete_after);
        
        if (group_id > 0) {
          var member_list = [member_id];
          await _addGroupMember(conn, group_id, user_id, member_list);                    
        }
        else {
          result = {ok: false, msg: 'Unable to get the ID of the newly created private group.'};
        }
        
        if (result.ok) {
          await dbs.commitTransaction(conn);
          await _sendMemberFirstMessage(conn, group_id, user_id, http_user_agent, ip_addr);          
        }
        else {
          await dbs.rollbackTransaction(conn);
        }
      }
      else {
        result = {ok: false, msg: 'Unable to start transaction session, process cannot proceed.'};
      }
    }     
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.createPrivateMessageGroup = async function(msg_pool, user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr) {
  var conn;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    result = await _createPrivateMessageGroup(conn, user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr); 
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }

  return result;
}


exports.isSystemAdmin = async function(msg_pool, user_id) {
  var conn, role, result;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    role = await _getUserRole(conn, user_id);    
    result = (role == 2)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.isTrustedUser = async function(msg_pool, user_id) {
  var conn, role, result;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    role = await _getUserRole(conn, user_id);    
    result = (role >= 1)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;    
} 


exports.getAllMessageGroups = async function(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT group_id, group_name ` +
          `  FROM msg_group ` + 
          `  ORDER BY group_name`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      var this_group = {group_id: data[i].group_id, group_name: data[i].group_name};
      result.push(this_group);
    }      
  }
  catch(e) {
    throw e;
  }
    
  return result;  
}


async function _buildDeletedGroupMemberInformPage(conn, fail_cnt, inform_members) {
  var html, m_site_dns, wspath, jsonInformMembers;
  
  try {
    jsonInformMembers = JSON.stringify(inform_members);
    
    //-- Construct websocket access path from DNS of messaging site. It will --//
    //-- be in format "wss://<your messaging site>/ws".                      --//        
    m_site_dns = await wev.getSiteDNS(conn, 'M');
    if (m_site_dns != '') {
      wspath = m_site_dns.replace('https', 'wss') + '/ws';
    }
    else {
      wspath = '';
    }

    html = wev.printHeader('Inform Members'); 

    html += `
    <body style="width:auto;">  
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/js.cookie.min.js"></script>
    <script src='/js/crypto-js.js'></script>
    <script src="/js/common_lib.js"></script>

    <script>
      var fail_cnt = ${fail_cnt};
      var inform_members = ${jsonInformMembers};                  // Note: 'inform_members' in here is an object, not string.  
      var myWebSocket = null;
      var wsOpenSocket = null;   
      
      function connectWebServer() {
        var ws = new WebSocket("${wspath}");
                                                
        ws.onopen = function(e) {
          for (var i = 0; i < inform_members.length; i++) {
            var group_id = inform_members[i].group_id;
            var members = inform_members[i].members;            
            var this_cmd = {type: 'cmd', content:{op: 'group_deleted', group_id: group_id, members: members}};
            groupDeleted(this_cmd);
          }
        }
                            
        ws.onerror = function(e) {
          console.log('Error: ' + e.message);
        }
        
        return ws;
      }  
        
      $(document).on("pageshow", function(event) {
        //-- Open a websocket and send out group deleted message --//
        myWebSocket = connectWebServer();

        if (fail_cnt > 0) {
          alert("${fail_cnt} group(s) cannot be deleted, please try again.");
          window.location.href = "/delete_group_by_admin";
        }
        else {
          //alert("Message group(s) are deleted successfully");        
          window.location.href = "/message";
        }              
      });

      function groupDeleted(cmd) {
        var message = JSON.stringify(cmd);
        
        if (myWebSocket.readyState == WebSocket.OPEN) {
          myWebSocket.send(message);
        }
        else {
          console.log('Unable to send group_deleted message due to websocket is not opened'); 
        }
      }    
    </script>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.deleteGroupByAdmin = async function(msg_pool, delete_groups) {
  var conn, group_id, html, fail_cnt, sqlTxStarted;
  var attached_files = [];
  var group_members = [];
  var inform_members = [];
  var result = {ok: true, msg: '', html: ''}; 
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));

    fail_cnt = 0;
    sqlTxStarted = false;
    for (var i = 0; i < delete_groups.length; i++) {    
      group_id = delete_groups[i];
      attached_files = [];
      group_members = [];
      
      if (await dbs.startTransaction(conn)) {
        sqlTxStarted = true;
        
        //-- Step 1: Get group members --//
        //-- Note: 'group_members' is an array with record structure as {user_id, username, alias, name, group_role}, but now --//
        //--       I only want to get value of 'user_id' only. The other values, such as usernamem alias, name and group_role --//
        //--       will become null. It is for security measure: Don't transfer sensitive data which is don't needed.         --//                                       
        group_members = await _getMessageGroupMembers(conn, group_id, {user_id: true});
                
        //-- Step 2: Get the list of all attachment files of the group --//
        attached_files = await _getGroupAttachedFiles(conn, group_id);
  
        //-- Step 3: Delete group, messages and delivery transactions --// 
        await _removeGroup(conn, group_id);
        await _removeGroupMember(conn, group_id);
        await _removeGroupMessageAndDeliveryHistory(conn, group_id);
        
        //-- Step 4: Commit SQL transaction --//
        if (await dbs.commitTransaction(conn)) {
          sqlTxStarted = false;
          
          if (attached_files.length > 0) {
            //-- Step 5: If SQL transaction is committed, delete all attachment --//
            //--         files (if any).                                        --// 
            await _deleteGroupAttachedFiles(attached_files);
            
            //-- Log down group members that should be informed, which will be used on step 6. --//
            var inform_rec = {group_id: group_id, members: group_members}; 
            inform_members.push(inform_rec);
          }
        }
        else {
          await dbs.rollbackTransaction(conn);
          sqlTxStarted = false;          
          result = {ok: false, msg: `Unable to delete group ${group_id}, operation is aborted`, html: ''};
          fail_cnt++;
        }
      }
      else {
        throw new Error('Unable to start SQL transaction session, operation is aborted.');
      }
    }
    
    //-- Step 6: Build HTML to inform members of deleted groups. --//
    if (inform_members.length > 0) {
      //-- Note: This step should be performed even error is found --//
      //--       during operation.                                 --//              
      html = await _buildDeletedGroupMemberInformPage(conn, fail_cnt, inform_members);       
    }
    else {
      html = `
      <script>
        alert("Unable to commit any group deletion process to the database by unknown reason, please try again."); 
        var url = window.location.href;
        var host = url.split('/');
        location.href = host[0] + '//' + host[2] + '/delete_group_by_admin';
      </script>      
      `;
    }
    
    result.html = html;
  }
  catch(e) {
    if (sqlTxStarted) {await dbs.rollbackTransaction(conn);}      // Rollback any SQL transaction session before throw out error.
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);    
  }
  
  return result;    
}


async function _userHasExisted(conn, user) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM user_list ` +
          `  WHERE user_name = ?`;
    
    param = [user];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;      
}


async function _aliasHasExisted(conn, alias) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM user_list ` +
          `  WHERE user_alias = ?`;
    
    param = [alias];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;        
}


async function _createUserAccount(conn, user_id, name, user, alias, email, happy_passwd, unhappy_passwd) {
  var sql, param, data, crypted_happy_passwd, crypted_unhappy_passwd, new_user_id;
  var result = {ok: true, msg: ''};
  
  try {
    if (await _userHasExisted(conn, user)) {
      result = {ok: false, msg: 'User name ' + user + ' is invalid'};
    }    
    else if (await _aliasHasExisted(conn, alias)) {
      result = {ok: false, msg: 'Alias ' + alias + ' is invalid'};
    }
    else {        
      crypted_happy_passwd = await cipher.encryptPassword(happy_passwd); 
      crypted_unhappy_passwd = await cipher.encryptPassword(unhappy_passwd);
      
      sql = `INSERT INTO user_list ` +
            `(user_name, user_alias, name, happy_passwd, unhappy_passwd, login_failed_cnt, user_role, email, refer_by, join_date, status, cracked, inform_new_msg) ` +
            `VALUES ` +
            `(?, ?, ?, ?, ?, 0, 0, ?, ?, CURRENT_TIMESTAMP(), 'A', 0, 1)`;

      param = [user, alias, name, crypted_happy_passwd, crypted_unhappy_passwd, email, user_id]; 
      await dbs.sqlExec(conn, sql, param);   
    }    
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.createUserAccount = async function(msg_pool, user_id, name, user, alias, email, happy_passwd, unhappy_passwd) {
  var conn;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    result = await _createUserAccount(conn, user_id, name, user, alias, email, happy_passwd, unhappy_passwd);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


exports.checkReferrer = async function(msg_pool, refer) {
  var conn, sql, param, data;
  var result = {is_trusted: false, user_role: 0};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Here imply a potential issue: If a guy has more than one user accounts by using same email address, if role on one of these accounts --//
    //-- is non-trusted user (user_role = 0), and this non-trusted user account record is picked up, then this referrer will be considered    --//
    //-- untrusted. Therefore, we need to put the higher user role record go first to resolve this issue.                                     --//     
    sql = `SELECT user_role, tg_id ` +
          `  FROM user_list ` +
          `  WHERE status = 'A' ` +
          `    AND email = ? ` +
          `  ORDER BY user_role DESC`;
          
    param = [refer];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      var user_role = data[0].user_role;
      var tg_id = (data[0].tg_id == null)? '' : data[0].tg_id;
      result.is_trusted = (user_role >= 1)? true : false;
      result.user_role = user_role;
      result.tg_id = tg_id;
    }      
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;  
}


exports.saveApplicantInfo = async function(msg_pool, name, email, refer, remark) {
  var conn, sql, param, key, paratext, algorithm, token_iv, token, enc_obj;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    algorithm = "AES-GCM";
    key = cipher.generateTrueRandomStr('A', 32);
    paratext = `name=${name}&email=${email}&seed=${key}`;
    //-- Note: 1. Although function 'escape' is depreciated, no equivalent function is   --//
    //--          available to replace it. So, I am forced to use it in here.            --//
    //--       2. Beware character '+' on the encrypted token, it may need to be further --//
    //--          processed to avoid error between 'GET' method transferring over HTTPS. --//
    //--       3. Since the value of saved token is escaped, so that it must be          --//
    //--          unescaped before use.                                                  --//     
    enc_obj = await cipher.aesEncryptBase64(algorithm, key, paratext);
    token_iv = enc_obj.iv;  
    token = escape(enc_obj.encrypted);     
    
    if (token != '') {
      sql = `INSERT INTO applicant ` +
            `(name, email, refer_email, remark, apply_date, status, seed, algorithm, token_iv, token) ` +
            `VALUES ` +
            `(?, ?, ?, ?, CURRENT_TIMESTAMP(), 'W', ?, ?, ?, ?)`;
      
      param = [name, email, refer, remark, key, algorithm, token_iv, token];
      await dbs.sqlExec(conn, sql, param);
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return token;  
}


exports.informReferrerToApproval = async function(msg_pool, name, refer, remark, token, tg_id) {
  var conn, subject, site_dns, accept_url, reject_url, mail_body, html;
  var smtp = {email: null, m_user: null, m_pass: null, smtp_server: null, port: 0};
  var tg_profile = {};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
   
    smtp = await telecom.getMailWorker(conn);
    site_dns = await wev.getSiteDNS(conn, 'M');
    
    if (smtp.email != null && site_dns != '') {
      subject = "Someone wants to join us, please take a look.";
      accept_url = `${site_dns}/join_us?S=A&tk=${token}`;
      reject_url = `${site_dns}/join_us?S=R&tk=${token}`;
      mail_body = `A new guy wants to join us. His/her name is listed below, and he/she may say something to you also: \n\n` +
                  `Name: ${name} \n` +
                  `Message to you: ${remark} \n\n` +
                  `There are two links for you to choose. Clicking on the first link will accept this applicant to join, but the second link is used for rejection. \n\n` +
                  `Accept: ${accept_url} \n\n` +
                  `Reject: ${reject_url} \n\n` +
                  `You have 3 days to make the decision.\n\n` +
                  `Important Note: Please delete this mail after you make your decision.\n`;
                  
      await telecom.sendEmail(smtp.smtp_server, smtp.port, smtp.email, refer, smtp.m_user, smtp.m_pass, subject, mail_body)            
      html = await smslib.printRegistedOkPage(msg_pool, name);
      
      //-- Use Telegram to accelerate referrer inform process --// 
      if (tg_id != "" && typeof(tg_id) != "undefined") {
        tg_profile = await telecom.getTelegramBotProfile(conn);
        
        if (wev.allTrim(tg_profile.http_api_token) != '') {
          await telecom.sendTelegramMessage(tg_profile.http_api_token, tg_id, "Please check your email now, you need to perform an action.");
        }        
      } 
    }
    else {
      var error = '';
      
      if (smtp.email == null) {
        error = 'Error: No SMTP server is found.';
        if (site_dns == '') {
          error += ' Site settings are missing also.';
        }
      }
      else {
        error = 'Error: Site settings are missing';
      }
      
      throw new Error(error);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _loadApplicantInfo(conn, token) {
  var sql, param, data, apply_id, name, email, seed, algorithm, token_iv, apply_date;
  var applicant = {};
  
  try {
    sql = `SELECT apply_id, name, email, seed, algorithm, token_iv, DATE_FORMAT(apply_date, '%Y-%m-%d %H:%i:%s') AS apply_date ` +
          `  FROM applicant ` +
          `  WHERE status = 'W' ` +
          `    AND token = ?`;
          
    param = [token];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      apply_id = data[0].apply_id;
      name = data[0].name; 
      email = data[0].email;
      seed = data[0].seed;
      algorithm = data[0].algorithm;
      token_iv = data[0].token_iv;
      apply_date = data[0].apply_date;
      
      if (await smslib.isTimeLimitPassed(conn, apply_date, '3 00:00:00')) {        // Note: '3 00:00:00' means 3 days
        await _setApplicantStatus(conn, apply_id, 'T');                            // 'T' means to mark applicant record status as timeout.
        applicant = {exist: false, msg: 'You are too late to activate the approval process, the request has been timeout.'}; 
      }
      else {
        applicant = {exist: true, apply_id: apply_id, name: name, email: email, seed: seed, algorithm: algorithm, token_iv: token_iv};
      }
    }
    else {
      applicant = {exist: false, msg: 'No such applicant, the token is fabricated.'};
    }      
  }
  catch(e) {
    throw e;
  }
  
  return applicant; 
}


function _extractParameters(paratext) {
  var buffer = [];
  var result = {name: '', email: '', seed: ''};
  
  try {
    buffer = paratext.split('&');
    for (var i = 0; i < buffer.length; i++) {
      var this_param = buffer[i];
      var parts = this_param.split('=');
      var param_name = wev.allTrim(parts[0]);
      var param_data = wev.allTrim(parts[1]);
      
      if (param_name.match(/name/)) {
        result.name = param_data;
      } 
      else if (param_name.match(/email/)) {
        result.email = param_data;
      }
      else if (param_name.match(/seed/)) {
        result.seed = param_data;
      }      
    }    
  }
  catch(e) {
    throw e;
  }

  return result;
}


async function _verifyApplicantOk(name, email, seed, algorithm, token_iv, token) {
  var decrypt_obj, paratext, chk_obj, result;
  
  try {
		paratext = await cipher.aesDecryptBase64(algorithm, seed, token_iv, unescape(token));		      
		chk_obj = _extractParameters(paratext);		
		if (name != chk_obj.name || email != chk_obj.email || seed != chk_obj.seed) {
			result = false;
		}
		else {
			result = true;
		}
  }
  catch(e) {
    throw e;
  }

  return result;  
}


async function _setApplicantStatus(conn, apply_id, decision) {
  var sql, param;
  var result = {ok: true, msg: ''};
  
  try {
    sql = `UPDATE applicant ` +
          `  SET status = ? ` +
          `  WHERE apply_id = ?`;
    
    param = [decision, apply_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;
}


async function _informApplicantToJoin(conn, name, email, token) {
  var mail_worker, site_dns, subject, link, mail_body;
  var result = {ok: true, msg: ''};
  
  try {
    mail_worker = await telecom.getMailWorker(conn);
    site_dns = await wev.getSiteDNS(conn, 'D');
    
    if (site_dns != '' && mail_worker.email != null) {
      subject = "You are accepted";
      link = `${site_dns}/add_user?tk=${token}`;
      mail_body = `Hi ${name}, \n\n` +
                  `Please follow the link below to finalize the registration process: \n\n` +
                  `${link} \n\n` +
                  `Important Notes: \n` +
                  `1. You have 4 days to complete the process. \n` +
                  `2. For security reason, please delete this mail after you complete the registration. \n`;
            
      await telecom.sendEmail(mail_worker.smtp_server, mail_worker.port, mail_worker.email, email, mail_worker.m_user, mail_worker.m_pass, subject, mail_body);      
    }
    else {
      result = {ok: false, msg: "Unable to send confirmation email to applicant due to system error, please let system administrator check for it."};
    }    
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
    
  return result;
}


async function _informSysAdminNewGuyAccepted(conn, apply_id) {
  var sql, param, data, applicant, referer_username, referer_alias, referer_realname, subject, mail_content;
  var result = {ok: true, msg: ''};

  try {
    sql = `SELECT a.name, b.user_name, b.user_alias, b.name AS refer_name ` +
          `  FROM applicant a, user_list b ` +
          `  WHERE a.refer_email = b.email ` +
          `    AND a.apply_id = ? ` +
          `    AND b.status = 'A'`;
    
    param = [apply_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      applicant = data[0].name;
      referer_username = wev.allTrim(data[0].user_name);  
      referer_alias = wev.allTrim(data[0].user_alias);
      referer_realname = wev.allTrim(data[0].refer_name);
      
      subject = "New guy is accepted";
      mail_content = `A new guy named ${applicant} has been accepted by our member ${referer_username} / ${referer_alias} / ${referer_realname} (username / alias / name).`; 
      await wev.informSystemAdmin(conn, subject, mail_content);
    } 
    else {
      result = {ok: false, msg: "Unable to collect data of the newly added user to inform system administrator"};
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: `Unable to inform system administrator a new guy is accepted. Error: ${e.message}`};
  }

  return result;
}


exports.applicantApproval = async function(msg_pool, decision, token) {
  var conn, applicant, retval;
  var result = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    applicant = await _loadApplicantInfo(conn, token);
    
    if (applicant.exist) {
      if (await _verifyApplicantOk(applicant.name, applicant.email, applicant.seed, applicant.algorithm, applicant.token_iv, token)) {
        retval = await _setApplicantStatus(conn, applicant.apply_id, decision);
        
        if (retval.ok) {
          if (decision == 'A') {
            retval = await _informApplicantToJoin(conn, applicant.name, applicant.email, token);
            
            if (retval.ok) {
              await _informSysAdminNewGuyAccepted(conn, applicant.apply_id);
            }
            else {
              result = {ok: false, msg: `The applicant is accepted, but unable to inform this guy to complete the account creation process. Error: ${retval.msg}`};
            }
          }
        }
        else {
          result = {ok: false, msg: retval.msg};
        }
      }
      else {
        result = {ok: false, msg: 'Data of this applicant is not match, it may be tampered by someone.'};
      }
    }
    else {
      result = {ok: false, msg: applicant.msg};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


async function _retrieveApplicantInfo(conn, token) {
  var sql, param, data;
  var applicant = {exist: false, apply_id: 0, status: ''};
  
  try {
    sql = `SELECT apply_id, DATE_FORMAT(apply_date, '%Y-%m-%d %H:%i:%s') AS apply_date, status ` +
          `  FROM applicant ` +
          `  WHERE token = ?`;
    
    param = [token];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      var apply_id = data[0].apply_id;
      var apply_date = data[0].apply_date;
      var status = data[0].status;
      
      if (await smslib.isTimeLimitPassed(conn, apply_date, '7 00:00:00')) {        // Note: '7 00:00:00' means 7 days
        var retval = await _setApplicantStatus(conn, apply_id, 'T');               // 'T' means to mark applicant record status as timeout.
        if (retval.ok) {
          applicant = {exist: true, apply_id: apply_id, status: 'T'};
        }
        else {
          throw new Error(retval.msg);
        }        
      }
      else {
        applicant = {exist: true, apply_id: apply_id, status: status};
      }
    }
  }
  catch(e) {
    throw e;
  }
  
  return applicant;
}


exports.checkApplicantInfo = async function(msg_pool, token) {
  var conn, applicant, html;
  var result = {ok: true, msg: '', err_type: 0, apply_id: 0};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    applicant = await _retrieveApplicantInfo(conn, token);
    
    if (applicant.exist) {
      if (applicant.status == 'A') {
        //-- If everything is OK, turn applicant status to 'S' temporary, in order to ensure the same    --//
        //-- person to create his/her user account in the entire process. Note: Current applicant status --//
        //-- is 'A', it needs to change it to 'S' temporary.                                             --//        
        var retval = await _setApplicantStatus(conn, applicant.apply_id, 'S');
        if (retval.ok) {        
          result.apply_id = applicant.apply_id;
          result.ok = true;
        } 
        else {
          result.msg = "Unable to switch to user account preparation mode, please try again.";
          result.ok = false;                     
          result.err_type = 0;             
        }        
      }
      else if (applicant.status == 'C') {
        //-- Alert applicant that his/her registration acceptance link may have been intercepted and used by someone --//
        result.msg = "You have already created your account. If you don't know it, something is wrong, please contact your referrer ASAP!";
        result.ok = false;                     
        result.err_type = 1;   
      }
      else if (applicant.status == 'T') {
        result.msg = "Your application has already expired, please apply again.";
        result.ok = false;
        result.err_type = 2;                
      }
      else if (applicant.status == 'S') {
        result.msg = "Someone is creating your user account. If it is not you, please contact your referrer at once.";
        result.ok = false; 
        result.err_type = 3;       
      }
    }
    else {
      result.msg = "The token is fabricated, who are you?";
      result.ok = false;    
      result.err_type = 4;   
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;  
}


exports.verifyApplicantToken = async function(msg_pool, token, apply_id) {
  var conn, sql, param, data, is_valid_token;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    sql = `SELECT COUNT(*) AS cnt ` + 
          `  FROM applicant ` +
          `  WHERE token = ? ` +
          `    AND apply_id = ? ` +
          `    AND status = 'S'`;
          
    param = [token, apply_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));      
    
    is_valid_token = (data[0].cnt > 0)? true : false;    
    
    if (is_valid_token) {
      //-- Correct token has been given, so turn applicant's status from 'S' to 'A' again. --//
      var retval = await _setApplicantStatus(conn, apply_id, 'A');
      if (!retval.ok) {
        throw new Error('Unable to switch to user account creation ready mode, please contact your referrer now.');
      }
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return is_valid_token;
}


exports.checkApplicantToken = async function(msg_pool, token, apply_id) {
  var conn, sql, param, data, is_valid_token;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    sql = `SELECT COUNT(*) AS cnt ` + 
          `  FROM applicant ` +
          `  WHERE token = ? ` +
          `    AND apply_id = ? ` +
          `    AND status = 'A'`;
          
    param = [token, apply_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));      
    
    is_valid_token = (data[0].cnt > 0)? true : false;    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return is_valid_token;  
}


async function _getReferUserInfo(conn, apply_id) {
  var sql, param, data;
  var result = {user_id: 0, name: '', user_role: 0};
  
  try {
    sql = `SELECT a.user_id, a.user_alias, a.name, a.user_role ` + 
          `  FROM user_list a, applicant b ` + 
          `  WHERE a.email = b.refer_email ` +
          `    AND a.user_role >= 1 ` +
          `    AND a.status = 'A' ` +
          `    AND b.apply_id = ?`;
    
    param = [apply_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      //-- Note: It may have more than one record, but using same email address means they are referred to --//
      //--       the same person. So, just accept the first record is good enough.                         --// 
      var name = (wev.allTrim(data[0].user_alias) != '')? data[0].user_alias : data[0].name;       
      result = {user_id: data[0].user_id, name: name, user_role: data[0].user_role};
    }      
    else {
      result = {user_id: 0, name: '', user_role: 0};
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _informSysAdminNewUserIsCreated(conn, referrer, name, user, alias) {
  var subject, mail_content;
  var result = {ok: true, msg: ''};

  try {
    subject = "New member has joined";
    mail_content = `A new guy ${user} / ${alias} / ${name} (username / alias / name) who is referred by ${referrer.name} has joined us as member.`;
    await wev.informSystemAdmin(conn, subject, mail_content);
    
    if (referrer.user_role < 2) {   
      //-- If the referrer is not system administrator, inform him/her also. --//
      mail_content = `A new guy ${user} / ${alias} / ${name} (username / alias / name) who is referred by you has joined us as member.`;
      await wev.informMember(conn, referrer.user_id, subject, mail_content);
    }
  }
  catch(e) {
    smslib.consoleLog(e.message);
    result = {ok: false, msg: `Unable to inform system administrator a new guy is accepted. Error: ${e.message}`};
  }

  return result;  
}


exports.goCreateUserAccount = async function(msg_pool, apply_id, name, user, alias, email, happy_passwd, unhappy_passwd, http_user_agent, ip_addr) {
  let conn, refer_user;
  let result = {ok: true, msg: '', stage: 0};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));

    refer_user = await _getReferUserInfo(conn, apply_id);

    if (refer_user.user_id > 0) {          
      if (await dbs.startTransaction(conn)) {           
        result = await _createUserAccount(conn, refer_user.user_id, name, user, alias, email, happy_passwd, unhappy_passwd);   
        
        if (result.ok) { 
          result = await _setApplicantStatus(conn, apply_id, 'C');
        }
        
        if (result.ok) {
          await dbs.commitTransaction(conn);
          //-- Indicate the user account has been created --//
          result.stage = 1;
                    
          //-- Inform all system administrators, new user has been added. --//
          await _informSysAdminNewUserIsCreated(conn, refer_user, name, user, alias);
          
          //-- If user account is created successfully, then add a private group for the new user and his/her referrer. --// 
          let group_name = "Welcome " + name;
          let member = alias;
          let auto_delete = 1;
          let delete_after = 10;      
          await _createPrivateMessageGroup(conn, refer_user.user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr);      
        }
        else {
          await dbs.rollbackTransaction(conn);
          result.stage = 0;
        }
      }
      else {
        result = {ok: false, msg: 'Unable to start SQL transaction session, user creation process is aborted.', stage: 0};
      }
    }
    else {
      //-- The referrer may be arrested (i.e. unhappy), locked or disabled. --// 
      result = {ok: false, msg: 'Your referrer is disabled in the system, try to contact him/her if it is safe.', stage: 0};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


exports.confirmPromoteSelectedUsers = async function(msg_pool, op, promote_users) {
  var conn, sql, param, sql_tx_on;
  var retval = {ok: true, msg: ''};

  sql_tx_on = false;

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      for (var i = 0; i < promote_users.length; i++) {
        var this_user_id = promote_users[i];
        
        sql = `UPDATE user_list ` +
              `  SET user_role = ? ` +
              `  WHERE user_id = ?`;
              
        param = [op, this_user_id];
        await dbs.sqlExec(conn, sql, param);        
      }
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: 'Unable to start SQL transaction session, operation cannot proceed.'};
    }        
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}    
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


exports.confirmDemoteSelectedUsers = async function(msg_pool, op, demote_users) {
  var conn, sql, param, role, sql_tx_on;
  var retval = {ok: true, msg: ''};

  sql_tx_on = false;
  role = op - 1;

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      for (var i = 0; i < demote_users.length; i++) {
        var this_user_id = demote_users[i];
        
        sql = `UPDATE user_list ` +
              `  SET user_role = ? ` +
              `  WHERE user_id = ?`;
              
        param = [role, this_user_id];
        await dbs.sqlExec(conn, sql, param);
        
        //-- Delete session of demoted user to prevent he/she to perform any activity which --//
        //-- should not be done by him/her.                                                 --//
        sql = `DELETE FROM web_session ` +
              `  WHERE user_id = ?`;
              
        param = [this_user_id];
        await dbs.sqlExec(conn, sql, param);              
      }
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: 'Unable to start SQL transaction session, operation cannot proceed.'};
    }            
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }   
  
  return retval;
}


exports.confirmLockUnlockSelectedUsers = async function(msg_pool, op, select_users) {
  var conn, sql, param, status, sql_tx_on;
  var retval = {ok: true, msg: ''};

  sql_tx_on = false;
  status = (op == 1)? "D" : "A";
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      for (var i = 0; i < select_users.length; i++) {
        var this_user_id = select_users[i];
        
        sql = `UPDATE user_list ` +
              `  SET status = ? ` +
              `  WHERE user_id = ?`;
              
        param = [status, this_user_id];
        await dbs.sqlExec(conn, sql, param);      
        
        if (status == "D") {
          sql = `DELETE FROM web_session ` +
                `  WHERE user_id = ?`;
                
          param = [this_user_id];
          await dbs.sqlExec(conn, sql, param);       
        }
      }
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: 'Unable to start SQL transaction session, operation cannot proceed.'};
    }      
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;    
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _removeMainSites(conn) {
  var sql;
  
  try {
    sql = `DELETE FROM sites`;
    await dbs.sqlExec(conn, sql);    
  }
  catch(e) {
    throw e;
  }
}


async function _addSite(conn, site_dns, site_type) {
  var sql, param;
  
  try {
    sql = `INSERT INTO sites ` +
          `(site_type, site_dns, status) ` +
          `VALUES ` +
          `(?, ?, 'A')`;
          
    param = [site_type, site_dns];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }  
}


exports.saveMainSites = async function(msg_pool, decoy_site, message_site) {
  var conn, sql_tx_on;
  var retval = {ok: true, msg: ''};
  
  sql_tx_on = false;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;      
      await _removeMainSites(conn);      
      await _addSite(conn, decoy_site, "DECOY");
      await _addSite(conn, message_site, "MESSAGE");      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: "Unable to start data update protection session, process cannot proceed."};
    }
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _addNewEmailSender(conn, email, m_user, m_pass, smtp_server, port) {
  var sql, param;
  
  try {
    sql = `INSERT INTO sys_email_sender ` +
          `(email, m_user, m_pass, smtp_server, port, status) ` +
          `VALUES ` +
          `(?, ?, ?, ?, ?, 'A')`;
          
    param = [email, m_user, m_pass, smtp_server, port];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }  
}


async function _modifyEmailSender(conn, ms_id, email, m_user, m_pass, smtp_server, port) {
  var sql, param;
  
  try {
    sql = `UPDATE sys_email_sender ` +
          `  SET email = ?, ` +
          `      m_user = ?, ` +
          `      m_pass = ?, ` +
          `      smtp_server = ?, ` +
          `      port = ? ` +
          `  WHERE ms_id = ?`;
    
    param = [email, m_user, m_pass, smtp_server, port, ms_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


async function _deleteEmailSender(conn, ms_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM sys_email_sender ` +
          `  WHERE ms_id = ?`;
          
    param = [ms_id];
    await dbs.sqlExec(conn, sql, param);       
  }
  catch(e) {
    throw e;
  }
}


exports.saveEmailSender = async function(msg_pool, op, ms_id, email, m_user, m_pass, smtp_server, port) {
  var conn;
  var retval = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (op == "A") {
      await _addNewEmailSender(conn, email, m_user, m_pass, smtp_server, port);
    }
    else if (op == "E") {
      if (ms_id > 0) {
        await _modifyEmailSender(conn, ms_id, email, m_user, m_pass, smtp_server, port);
      }
      else {
        retval = {ok: false, msg: "Invalid value of email worker ID is found, process is aborted."};
      }
    }
    else if (op == "D") {
      if (ms_id > 0) {
        await _deleteEmailSender(conn, ms_id);
      }
      else {
        retval = {ok: false, msg: "Invalid value of email worker ID is found, process is aborted."};
      }
    }
    else {
      retval = {ok: false, msg: "Invalid value of operation is found, process is aborted."};
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;  
}


async function _isDecoySiteExist(conn, site_url) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM decoy_sites ` +
          `  WHERE site_url = ?`;
    
    param = [site_url];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _addNewDecoySite(conn, site_url, key_words) {
  var sql, param;
  
  try {
    if (await _isDecoySiteExist(conn, site_url)) {
      await _modifyDecoySite(conn, site_url, site_url, key_words);
    }
    else {
      sql = `INSERT INTO decoy_sites ` +
            `(site_url, key_words) ` +
            `VALUES ` +
            `(?, ?)`;
            
      param = [site_url, key_words];
      await dbs.sqlExec(conn, sql, param);      
    }
  }
  catch(e) {
    throw e; 
  }
}


async function _modifyDecoySite(conn, site_url_old, site_url, key_words) {
  var sql_tx_on = false;
  
  try {
    site_url_old = wev.allTrim(site_url_old);    
    site_url = wev.allTrim(site_url);
    
    if (site_url_old == site_url) {
      //-- In this case, decoy site URL is remain the same --//
      await _updateDecoySite(conn, site_url_old, site_url, key_words);
    }
    else {
      if (await _isDecoySiteExist(conn, site_url)) {
        if (await dbs.startTransaction(conn)) {
          sql_tx_on = true;
          await _deleteDecoySite(conn, site_url_old);
          await _updateDecoySite(conn, site_url, site_url, key_words);
          await dbs.commitTransaction(conn);
        }
        else {
          throw new Error("Unable to start SQL transaction session, the decoy site can't be updated.");
        }
      }
      else {
        //-- In this case, decoy site URL is changed --//
        await _updateDecoySite(conn, site_url_old, site_url, key_words);
      }
    } 
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
}


async function _updateDecoySite(conn, site_url_old, site_url, key_words) {
  var sql, param;
  
  try {
    sql = `UPDATE decoy_sites ` +
          `  SET site_url = ?, ` +
          `      key_words = ? ` +
          `  WHERE site_url = ?`;
          
    param = [site_url, key_words, site_url_old];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }
}


async function _deleteDecoySite(conn, site_url) {
  var sql, param;
  
  try {
    sql = `DELETE FROM decoy_sites ` +
          `  WHERE site_url = ?`;
          
    param = [site_url];      
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


exports.saveDecoySite = async function(msg_pool, op, site_url_old, site_url, key_words) {
  var conn;
  var retval = {ok: true, msg: ''};

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (op == "A") {
      await _addNewDecoySite(conn, site_url, key_words);
    }
    else if (op == "E") {
      await _modifyDecoySite(conn, site_url_old, site_url, key_words);
    }  
    else if (op == "D") {
      await _deleteDecoySite(conn, site_url);
    }
    else {
      retval = {ok: false, msg: "Invalid value of operation is found, process is aborted."};
    }  
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _isFileTypeExist(conn, file_ext) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT ftype_id ` +
          `  FROM file_type ` +
          `  WHERE file_ext = ?`;
          
    param = [file_ext];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = parseInt(data[0].ftype_id, 10);
    }
    else {
      result = 0;
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _addFileType(conn, file_ext, file_type) {
  var sql, param;
  
  try {
    sql = `INSERT INTO file_type ` +
          `(file_ext, file_type) ` +
          `VALUES ` +
          `(?, ?)`;
          
    param = [file_ext, file_type];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }    
}


async function _addNewFileType(conn, file_ext, file_type) {
  var ftype_id = 0;
  
  try {
    ftype_id = await _isFileTypeExist(conn, file_ext);
    
    if (ftype_id > 0) {
      await _updateFileType(conn, ftype_id, file_ext, file_type);  
    }
    else {
      await _addFileType(conn, file_ext, file_type);
    }
  }
  catch(e) {
    throw e; 
  }  
}


async function _updateFileType(conn, ftype_id, file_ext, file_type) {
  var sql, param;
  
  try {
    sql = `UPDATE file_type ` +
          `  SET file_ext = ?, ` +
          `      file_type = ? ` +
          `  WHERE ftype_id = ?`;
    
    param = [file_ext, file_type, ftype_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e; 
  }
}


async function _modifyFileType(conn, ftype_id, file_ext, file_type) {
  var new_ftype_id, sql_tx_on;
  
  try {
    sql_tx_on = false;
    
    new_ftype_id = await _isFileTypeExist(conn, file_ext);
    
    if (ftype_id == new_ftype_id) {
      //-- File extension is remain unchanged --//
      await _updateFileType(conn, ftype_id, file_ext, file_type);
    }
    else {
      if (new_ftype_id > 0) {
        //-- File extension is changed, and the file type record of the amended file extension has already existed. --//
        if (await dbs.startTransaction(conn)) {
          sql_tx_on = true;
          
          await _deleteFileType(conn, ftype_id);
          await _updateFileType(conn, new_ftype_id, file_ext, file_type);
          
          await dbs.commitTransaction(conn);
        }
        else {
          throw new Error("Unable to start SQL transaction session, file type record cannot be updated.");
        }
      }
      else {
        //-- File extension is changed, and the file type record of the amended file extension does not exist. --//
        await _updateFileType(conn, ftype_id, file_ext, file_type);
      }
    }    
  }
  catch(e) {
    throw e; 
  }
}


async function _deleteFileType(conn, ftype_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM file_type ` +
          `  WHERE ftype_id = ?`;
          
    param = [ftype_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }
}


exports.saveFileTypes = async function(msg_pool, op, ftype_id, file_ext, file_type) {
  var conn;
  var retval = {ok: true, msg: ''};

  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (op == "A") {
      await _addNewFileType(conn, file_ext, file_type);
    }
    else if (op == "E") {
      await _modifyFileType(conn, ftype_id, file_ext, file_type);
    }
    else if (op == "D") {
      await _deleteFileType(conn, ftype_id);
    }
    else {
      retval = {ok: false, msg: "Invalid value of operation is found, process is aborted."};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }  
  
  return retval;
}


async function _modifySysSetting(conn, sys_key_old, sys_key, sys_value) {
  var sql, param;
  
  try {
    if (sys_key_old == sys_key) {
      sql = `UPDATE sys_settings ` +
            `  SET sys_value = ? ` +
            `  WHERE sys_key = ?`;
      
      param = [sys_value, sys_key];
      await dbs.sqlExec(conn, sql, param);
    }
    else {
      throw new Error("Key of the system setting is inconsistant.");
    } 
  }
  catch(e) {
    throw e;
  }
}


exports.saveSystemSetting = async function(msg_pool, op, sys_key_old, sys_key, sys_value) {
  var conn;
  var retval = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
  
    if (op == "E") {
      await _modifySysSetting(conn, sys_key_old, sys_key, sys_value);
    }
    else {
      retval = {ok: false, msg: "Invalid value of operation is found, process is aborted."};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _deleteBotProfile(conn) {
  var sql;
  
  try {
    sql = `DELETE FROM tg_bot_profile`;
    await dbs.sqlExec(conn, sql);
  }
  catch(e) {
    throw e;
  }
}


async function _addBotProfile(conn, bot_name, bot_username, http_api_token) {
  var sql, param;
  
  try {
    sql = `INSERT INTO tg_bot_profile ` +
          `(bot_name, bot_username, http_api_token) ` +
          `VALUES ` +
          `(?, ?, ?)`;
          
    param = [bot_name, bot_username, http_api_token];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }
}


exports.saveTelegramBotProfile = async function(msg_pool, bot_name, bot_username, http_api_token) {
  var conn, sql_tx_on;
  var retval = {ok: true, msg: ''};
  
  sql_tx_on = false;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      await _deleteBotProfile(conn);
      await _addBotProfile(conn, bot_name, bot_username, http_api_token);
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: "Unable to start SQL transaction session, process is aborted."};
    }
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _deleteDatabase(conn, db_name) {
  var sql, param, data;
  
  try {
    sql = `SELECT table_name ` +
          `  FROM information_schema.tables ` +
          `  WHERE table_schema = ? ` +
          `  ORDER BY table_name`;
          
    param = [db_name];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      var this_table = data[i].table_name;
      
      sql = `DELETE FROM ${this_table}`;
      await dbs.sqlExec(conn, sql);
      
      sql = `DROP TABLE ${this_table}`;
      await dbs.sqlExec(conn, sql);
    }   
    
    //-- Finally, drop the database. --//
    sql = `DROP DATABASE ${db_name}`;
    await dbs.sqlExec(conn, sql);
  }
  catch(e) {
    throw e;
  }
}


async function _deleteAllFiles() {
  var command, console_result;
  
  try {    
    command = "rm -rf /www/sms2/itnews/*";
    console_result = execSync(command, {timeout:60000});
    
    command = "rm -rf /www/sms2/pdatools/*";
    console_result = execSync(command, {timeout:60000}); 
    
    command = "rm -rf /www/sms2/*";
    console_result = execSync(command, {timeout:60000});        
  }
  catch(e) {
    throw e;
  }
}


exports.destroyEntireSystem = async function(msg_pool, pda_pool) {
  var conn_msg, conn_pda, ok;
  
  try {
    ok = true;
    
    conn_msg = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    conn_pda = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    await _deleteDatabase(conn_msg, 'msgdb');
    await _deleteDatabase(conn_pda, 'pdadb');
    await _deleteAllFiles();
  }
  catch(e) {
    throw e;
  }
  
  return ok;
}
