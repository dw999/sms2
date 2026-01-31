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

//##########################################################################################
// Program: new_message_inform.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     =========================
// V1.0.00       2018-07-18      DW              Inform offline users who get new messages.
// V1.0.01       2018-08-24      DW              Inform offline users with new messages via
//                                               Telegram.
// V2.0.00       2022-12-09      DW              - Rewrite it from Perl to Node.js (javascript).
//                                               - Install a scheduler to operate this service
//                                                 periodically.
// V2.0.01       2023-06-06      DW              If an user is currently online, don't send out
//                                               notification.
// V2.0.02       2023-06-07      DW              Change new message notification period from
//                                               1 minute to 15 minutes.
// V2.0.03       2025-06-27      DW              Show timestamp on error message.
// V2.0.04       2025-07-08      DW              Use database connection pool to avoid database 
//                                               connection timeout issue.
// V2.0.05       2026-01-30      DW              Refine scope of variables declare in this library.  
//##########################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');
const telecom = require('./lib/telecom_lib.js');

var interval = 60000 * 15;        // Repeat every 15 minutes
//-- Open database pool --//
var msg_pool = dbs.createConnectionPool('COOKIE_MSG', 1);


async function _deleteInformRecordWithError(conn, error_limit) {
  let sql, param;
  
  try {
    sql = `DELETE FROM new_msg_inform ` +
          `  WHERE try_cnt >= ?`;
          
    param = [error_limit];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e; 
  }
}


async function _getInformRecords(conn) {
  let sql, data;
  let result = [];
  
  try {
    sql = `SELECT a.user_id, DATE_FORMAT(a.period, '%Y-%m-%d %H:%i:%s') AS period, b.email, b.tg_id, b.status ` +
          `  FROM new_msg_inform a, user_list b ` +
          `  WHERE a.user_id = b.user_id ` +
          `  ORDER BY a.user_id, a.period`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (let i = 0; i < data.length; i++) {
      result.push({user_id: data[i].user_id, period: data[i].period, email: data[i].email, tg_id: data[i].tg_id, status: data[i].status});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _hasBeenInformed(user_id, informed_users) {
  let result = false;
  
  try {
    for (let i = 0; i < informed_users.length; i++) {
      if (informed_users[i] == user_id) {
        result = true;
        break;
      }
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _isUserOnline(conn, user_id) {
  let sql, param, data;
  let result = false;
  
  try {
    sql = `SELECT status, TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), sess_until) AS timeout  ` +
          `  FROM web_session ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];        
    data = dbs.sqlQuery(conn, sql, param);
    
    if (data.length > 0) {
      if (data[0].status == "A" && parseInt(data[0].timeout) > 0) {
        result = true;
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
    throw e;
  }
  
  return result;
}


async function _deleteInformRecord(conn, user_id, period) {
  let sql, param;
  
  try {
    sql = `DELETE FROM new_msg_inform ` +
          `  WHERE user_id = ? ` +
          `    AND period = ?`;
          
    param = [user_id, period];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }  
}


async function informUserHasNewMessage(interval) {
  let scheduler_id;

  //-- Run "_informUserHasNewMessage()" immediately, then put it into a scheduler. --//
  await _informUserHasNewMessage();
  scheduler_id = setInterval(_informUserHasNewMessage, interval);  
  
  async function _informUserHasNewMessage() {
    let conn, url, subject, body, api, has_tg_bot, bot_ok;
    let mail_worker = {email:'', m_user:'', m_pass:'', smtp_server:'', port:0};
    let informed_user = {};
    let tg_bot_profile = {bot_name:'', bot_username:'', http_api_token:''};
    let inform_rec = [];
    let informed_users = [];
    
    try {
      //conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
      
      //-- Gather require data in here --//
      url = await wev.getSiteDNS(conn, "D");
      subject = "Greetings from your friends";
      body = `Your friends miss you so much, please click the link below to get their greetings: \n\n${url}\n`;
      mail_worker = await telecom.getMailWorker(conn);
      tg_bot_profile = await telecom.getTelegramBotProfile(conn);
      has_tg_bot = (tg_bot_profile.http_api_token != '')? true : false;
      bot_ok = (tg_bot_profile.http_api_token != '')? true : false;
      
      //-- Remove those inform records with error in the list before proceed, so that no extra effort and --//
      //-- resources are wasted.                                                                          --//
      await _deleteInformRecordWithError(conn, 3);
      
      inform_rec = await _getInformRecords(conn);
      
      for (let i = 0; i < inform_rec.length; i++) {
        let to_user_id = inform_rec[i].user_id;
        let status = wev.allTrim(inform_rec[i].status);
        let period = inform_rec[i].period;
        let to_mail = wev.allTrim(inform_rec[i].email);
        let tg_id = wev.allTrim(inform_rec[i].tg_id);          // It is the Telegram chat ID of this SMS user.
        let tg_err_msg = '';

        console.log(wev.sayCurrentTime() + ` Processing user ${to_user_id} ....`);

        //-- It may contain multiple new message inform records for same user, try not to send more than one email to him/her. --//        
        if (await _hasBeenInformed(to_user_id, informed_users) == false) {
          if (status == "A") {
            if (await _isUserOnline(conn, to_user_id) == false) {  
              if (to_mail != '') {
                console.log(wev.sayCurrentTime() + `  >>> Send email`);
                await telecom.sendEmail(mail_worker.smtp_server, mail_worker.port, mail_worker.email, to_mail, mail_worker.m_user, mail_worker.m_pass, subject, body); 
              } 
              
              if (bot_ok && tg_id != '') {
                console.log(wev.sayCurrentTime() + `  +++ Send T.G. message`);
                await telecom.sendTelegramMessage(tg_bot_profile.http_api_token, tg_id, "You have new message");
              }
  
              console.log(wev.sayCurrentTime() + ` === Finished ===\n`);
              await _deleteInformRecord(conn, to_user_id, period);
              informed_users.push(to_user_id);
            }
            else {
              console.log(wev.sayCurrentTime() + ` User ${to_user_id} is currently online, skip notification.\n`);
              await _deleteInformRecord(conn, to_user_id, period);
              informed_users.push(to_user_id);
            } 
          }
          else {
            await _deleteInformRecord(conn, to_user_id, period);
          }
        } 
        else {
          await _deleteInformRecord(conn, to_user_id, period);
        }
      }
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + ' : ' + e.message);
    }
    finally {
      //await dbs.dbClose(conn);
      dbs.releasePoolConn(conn);
    }
  }
}


informUserHasNewMessage(interval);

