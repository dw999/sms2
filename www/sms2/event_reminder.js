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
// File name: event_reminder.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-07-18      DW              Remind users for scheduled event(s).
// V2.0.00       2023-01-26      DW              - Rewrite it from Perl to Node.js (javascript).
//                                               - Install a scheduler to operate this service periodically. 
// V2.0.01       2025-07-08      DW              Use database connection pool to avoid database connection timeout issue.
// V2.0.02       2026-01-30      DW              Refine scope of variables declare in this library.  
//#################################################################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');
const msglib = require('./lib/msg_lib.js');
const telecom = require('./lib/telecom_lib.js');

var interval = 60000;     // Repeat every 60 seconds
//-- Open database pool --//
var msg_pool = dbs.createConnectionPool('COOKIE_MSG', 1);
var pda_pool = dbs.createConnectionPool('COOKIE_PDA', 1);


async function _getEventReminders(conn_pda) {
  let sql, data;
  let result = [];
  
  try {
    sql = `
    SELECT a.reminder_id, b.user_id, b.event_title, DATE_FORMAT(b.ev_start, '%Y-%m-%d %H:%i') AS ev_start, a.remind_before, a.remind_unit, 
           CASE
             WHEN b.ev_start < CURRENT_TIMESTAMP() THEN 1
             ELSE 0
           END AS ev_passed  
      FROM schedule_reminder a, schedule_event b
      WHERE a.event_id = b.event_id
        AND a.has_informed = 0
      ORDER BY b.ev_start
    `;
    
    data = JSON.parse(await dbs.sqlQuery(conn_pda, sql));
    
    for (let i = 0; i < data.length; i++) {
      result.push({reminder_id: data[i].reminder_id, user_id: data[i].user_id, event_title: data[i].event_title, ev_start: data[i].ev_start, 
                   remind_before: data[i].remind_before, remind_unit: data[i].remind_unit, ev_passed: data[i].ev_passed});
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _setReminderOff(conn_pda, reminder_id) {
  let sql, param;
  
  try {
    sql = `
    UPDATE schedule_reminder
      SET has_informed = 1
      WHERE reminder_id = ?
    `;
    
    param = [reminder_id];
    await dbs.sqlExec(conn_pda, sql, param);
  }
  catch(e) {
    throw e; 
  }
}


async function _remindTimeHasReached(conn_pda, reminder_id, ev_start, remind_before, remind_unit) {
  let sql, data, result;
  
  try {
    result = false;
    
    sql = `
    SELECT CASE
             WHEN (DATE_FORMAT('${ev_start}' - INTERVAL ${remind_before} ${remind_unit}, '%Y-%m-%d %H:%i')) <= CURRENT_TIMESTAMP() THEN 1 
             ELSE 0
           END AS passed
    `;
    data = JSON.parse(await dbs.sqlQuery(conn_pda, sql));
    result = (parseInt(data[0].passed, 10) == 1)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getUserInformData(conn_msg, user_id) {
  let sql, param, data;
  let result = {email: '', tg_id: ''};
  
  try {
    sql = `
    SELECT email, tg_id
      FROM user_list 
      WHERE user_id = ?
    `;
    
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn_msg, sql, param));
    
    if (data.length > 0) {
      result = {email: data[0].email, tg_id: data[0].tg_id};
    }
    else {
      throw new Error(`Unable to get contact information for user ${user_id}.`);
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function runEventReminder(interval) {
  let scheduler_id;
  
  //-- Run "_eventReminder()" immediately, then put it into a scheduler. --//
  await _eventReminder();
  scheduler_id = setInterval(_eventReminder, interval);
  
  async function _eventReminder() {
    let conn_pda, conn_msg;
    let event_reminders = [];
    let mail_worker = {};
    let tg_profile = {};
    
    try {
      //conn_pda = await dbs.dbConnect(dbs.selectCookie('PDA'));
      //conn_msg = await dbs.dbConnect(dbs.selectCookie('MSG'));
      conn_pda = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
      conn_msg = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
      
      event_reminders = await _getEventReminders(conn_pda);
            
      if (event_reminders.length > 0) {
        mail_worker = await telecom.getMailWorker(conn_msg);
        tg_profile = await telecom.getTelegramBotProfile(conn_msg);
        
        for (let i = 0; i < event_reminders.length; i++) {
          let this_reminder_id = event_reminders[i].reminder_id;
          let this_user_id = event_reminders[i].user_id;
          let this_event_title = event_reminders[i].event_title;       
          let this_ev_start = event_reminders[i].ev_start;
          let this_remind_before = event_reminders[i].remind_before;
          let this_remind_unit = event_reminders[i].remind_unit;
          let this_ev_passed = (parseInt(event_reminders[i].ev_passed, 10) > 0)? true : false;
          
          if (this_ev_passed) {
            await _setReminderOff(conn_pda, this_reminder_id);
          }
          else {
            if (await _remindTimeHasReached(conn_pda, this_reminder_id, this_ev_start, this_remind_before, this_remind_unit)) {
              let user_profile = await _getUserInformData(conn_msg, this_user_id);
              let remainder_delivered = false;
              
              if (user_profile.email != "" || user_profile.tg_id != "") {
                let subject = this_event_title + " " + this_remind_before + " " + ((this_remind_before > 1)? this_remind_unit + "s" : this_remind_unit) + " later";
                let body = "It reminds you that event " + this_event_title + " will start on " + this_ev_start;
                
                //-- Deliver event reminder via email --//
                if (user_profile.email != "" && wev.allTrim(mail_worker.email) != "") {
                  await telecom.sendEmail(mail_worker.smtp_server, mail_worker.port, mail_worker.email, user_profile.email, mail_worker.m_user, mail_worker.m_pass, subject, body);  
                  remainder_delivered = true;
                }
                
                //-- Deliver event reminder via Telegram --// 
                if (user_profile.tg_id != "" && wev.allTrim(tg_profile.http_api_token) != "") {
                  await telecom.sendTelegramMessage(tg_profile.http_api_token, user_profile.tg_id, subject + "\n\n" + body);
                  remainder_delivered = true;
                }
                
                if (remainder_delivered) {
                  await _setReminderOff(conn_pda, this_reminder_id);
                  console.log(wev.sayCurrentTime() + ` : Reminder of event ${this_reminder_id} has been sent.`);
                }
                else {
                  console.log(wev.sayCurrentTime() + ` : Unable to deliver event reminder for event ${this_reminder_id}.`);
                }
              }
              else {
                await _setReminderOff(conn_pda, this_reminder_id);
                console.log(wev.sayCurrentTime() + ` : User ${this_user_id} has no any contact information, so that no any event reminder for event ${this_event_title} can be delivered.`);                
              }
            }            
          }                      
        }
      }
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + ` : Unable to remind schedule events. Error: ${e.message}`);
    }
    finally {
      //await dbs.dbClose(conn_pda);
      //await dbs.dbClose(conn_msg);
      dbs.releasePoolConn(conn_pda);
      dbs.releasePoolConn(conn_msg);
    }
  }
}


runEventReminder(interval);
