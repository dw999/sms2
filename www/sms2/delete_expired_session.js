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
// Program: delete_expired_session.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     =========================
// V1.0.00       2018-07-19      DW              Remove expired web session and login token queue records.
// V2.0.00       2022-12-11      DW              - Rewrite it from Perl to Node.js (javascript).
//                                               - Install a scheduler to operate this service
//                                                 periodically.
//                                               - Combine functions on 'delete_applicant_rec.pl' into this
//                                                 module.
// V2.0.01       2023-11-03      DW              - Add function to remove expired RSA key pair records. 
// V2.0.02       2024-03-22      DW              - Add function to remove expired Kyber key pair records.
// V2.0.03       2025-06-27      DW              Show timestamp on error message.
// V2.0.04       2025-07-07      DW              Use database connection pool to avoid database connection timeout issue.
// V2.0.05       2026-01-22      DW              Delete rolling key records for all invalid web sessions, if any.
// V1.0.06       2026-02-10      DW              Clear expired and used password recovery session.
//##########################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');

const interval = 3600000;        // Repeat every hour
const key_rec_expired_days = 7;  // RSA and Kyber key pair records expired days

//-- Open database pool --//
var msg_pool = dbs.createConnectionPool('COOKIE_MSG', 3);
var pda_pool = dbs.createConnectionPool('COOKIE_PDA', 1);


async function _deleteExpiredWebSession(conn) {
  let sql;
  
  try {
    sql = `DELETE FROM web_session ` +
          `  WHERE TIMEDIFF(CURRENT_TIMESTAMP(), sess_until) > '00:00:00' ` +
          `     OR status <> 'A'`;
          
    await dbs.sqlExec(conn, sql);      

    //-- Delete all rolling keys for those deleted web sessions, if any. --//
    sql = `DELETE FROM sess_roll_key ` +
          `  WHERE sess_code NOT IN (SELECT sess_code FROM web_session)`;
    
    await dbs.sqlExec(conn, sql);       
  }
  catch(e) {
    throw e;
  }
}


async function _deleteUsedAndTimeoutLoginToken(conn) {
  let sql;
  
  try {
    //-- Note: Maximum life span of a login token is 15 minutes. Add 30 seconds to it for precaution. --//
    sql = `DELETE FROM login_token_queue ` +
          `  WHERE TIMEDIFF(CURRENT_TIMESTAMP(), token_addtime) >= '00:15:30' ` +
          `     OR status = 'U' ` +
          `     OR status = 'T'`;
          
    await dbs.sqlExec(conn, sql);      
  }
  catch(e) {
    throw e;
  }
}


async function _removeRejectAndCompletedRecords(conn) {
  let sql;
  
  try {
    sql = `DELETE FROM applicant ` +
          `  WHERE status IN ('R', 'C', 'T')`;
          
    await dbs.sqlExec(conn, sql);      
  }
  catch(e) {
    throw e; 
  }
}


async function _removeTimeoutRecords(conn) {
  let sql;
  
  try {
    sql = `DELETE FROM applicant ` +
          `  WHERE DATEDIFF(CURRENT_TIMESTAMP(), apply_date) >= 7`;
          
    await dbs.sqlExec(conn, sql);      
  }
  catch(e) {
    throw e;
  }
}


async function _delete_applicant_record(conn) {
  try {
    //-- Step 1: Remove those rejected and completed applicant records first --//
    await _removeRejectAndCompletedRecords(conn);  
    //-- Step 2: Then delete all expired records (i.e. more than 7 days of applied date) --//
    await _removeTimeoutRecords(conn);    
  }
  catch(e) {
    throw e;
  }
}


async function _getPasswordRecoverySessionRecord(conn) {
  let sql, data, result = [];
  
  try {
    sql = `SELECT sess_code, DATE_FORMAT(add_datetime, '%Y-%m-%d %H:%i:%s') AS add_datetime ` +
          `  FROM pr_session`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));       
    
    if (data.length > 0) {
      let rec = {sess_code: data[0].sess_code, add_datetime: data[0].add_datetime};
      result.push(rec);
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _calculateSessionValidTime(conn, add_datetime, interval) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT DATE_FORMAT(ADDTIME(?, ?), '%Y-%m-%d %H:%i:%s') AS time_limit`;
    
    param = [add_datetime, interval];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = data[0].time_limit;
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _isPasswordRecoverySessionValid(conn, sess_until) {
  let sql, param, data, sess_valid;
  
  try {
    sql = `SELECT TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), ?) AS timediff`;
    
    param = [sess_until];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    sess_valid = (parseInt(data[0].timediff, 10) > 0)? true : false; 
  }
  catch(e) {
    throw e;
  }
  
  return sess_valid;    
}


async function _deletePasswordRecoverySession(conn, sess_code) {
  let sql, param;
  
  try {
    sql = `DELETE FROM pr_session ` +
          `  WHERE sess_code = ?`;
          
    param = [sess_code];
    await dbs.sqlExec(conn, sql, param);       
  }
  catch(e) {
    throw e;
  }
} 


async function _deleteExpiredAndUsedPasswordRecoverySession(conn) {
  let sql, param, pr_list;
  
  try {
    // Step 1: Delete all used P.R. session(s) firstly //
    sql = `DELETE FROM pr_session ` +
          `  WHERE status = 'U'`;
    
    await dbs.sqlExec(conn, sql);
    
    // Step 2: Then check every remain P.R. session record to see whether it has expired or not.  //
    //         If it has been expired, delete it. Note: Every unused P.R. session will be expired //
    //         after 30 minutes.                                                                  //
    pr_list = await _getPasswordRecoverySessionRecord(conn);
    
    for (let i = 0; i < pr_list.length; i++) {
      let sess_code = pr_list[i].sess_code;
      let add_datetime = pr_list[i].add_datetime;
      
      // Calculate the session valid time. Password recovery session will be expired after 30 minute after it's creation. //
      let sess_until = await _calculateSessionValidTime(conn, add_datetime, '00:30:00');
      
      if (!(await _isPasswordRecoverySessionValid(conn, sess_until))) {
        // Session has expired, delete it. //
        await _deletePasswordRecoverySession(conn, sess_code);        
      }
    }                 
  }
  catch(e) {
    throw e;
  }
}


async function _deleteExpiredRsaKeyPair(conn) {
  let sql, param;
	
  try {
    sql = `DELETE FROM rsa_keypair ` +
	  `  WHERE DATEDIFF(CURRENT_TIMESTAMP(), add_datetime) >= ?`;
    
    param = [key_rec_expired_days];      
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }	
}


async function _deleteExpiredKyberKeyPair(conn) {
  let sql, param;
  
  try {
    sql = `DELETE FROM kyber_keypair ` +
	  `  WHERE DATEDIFF(CURRENT_TIMESTAMP(), add_datetime) >= ?`;
    
    param = [key_rec_expired_days];      
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }	  
}


async function deleteExpiredSession(interval) {
  let msg_scheduler_id, decoy_scheduler_id, rsa_scheduler_id, kyber_scheduler_id;
  
  // Run all processes at once when the program is started //
  await _deleteMsgSiteExpiredSession();
  await _deleteDecoySiteExpiredSession();
  await _deleteExpiredRSAkeypairRecord();
  await _deleteExpiredKyberKeyPairRecord();
  
  // Then put them into a looping schedule //
  msg_scheduler_id = setInterval(_deleteMsgSiteExpiredSession, interval);
  decoy_scheduler_id = setInterval(_deleteDecoySiteExpiredSession, interval);
  rsa_scheduler_id = setInterval(_deleteExpiredRSAkeypairRecord, interval);
  kyber_scheduler_id = setInterval(_deleteExpiredKyberKeyPairRecord, interval);
  
  async function _deleteMsgSiteExpiredSession() {
    let conn;
    
    try {
      //conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Clear MSG site expired web session");
      await _deleteExpiredWebSession(conn);
      console.log(wev.sayCurrentTime() + " Clear MSG site expired login token");
      await _deleteUsedAndTimeoutLoginToken(conn);
      console.log(wev.sayCurrentTime() + " Clear MSG site expired applicant record");
      await _delete_applicant_record(conn);  
      console.log(wev.sayCurrentTime() + " Clear used and expired password recovery session");
      await _deleteExpiredAndUsedPasswordRecoverySession(conn);                     
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + " : " + e.message);
    }
    finally {
      //await dbs.dbClose(conn);
      dbs.releasePoolConn(conn);
    }
  }  
  
  
  async function _deleteDecoySiteExpiredSession() {
    let conn;
    
    try {
      //conn = await dbs.dbConnect(dbs.selectCookie('PDA'));
      conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('PDA'));
      
      console.log(wev.sayCurrentTime() + " Clear decoy site expired web session");
      await _deleteExpiredWebSession(conn);      
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + " : " + e.message);
    }
    finally {
      //await dbs.dbClose(conn);
      dbs.releasePoolConn(conn);
    }
  }    
  
  async function _deleteExpiredRSAkeypairRecord() {
    let conn;
		
    try {
      //conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Delete expired RSA key pair records");
      await _deleteExpiredRsaKeyPair(conn);
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + " : " + e.message);
    }
    finally {
      //await dbs.dbClose(conn);
      dbs.releasePoolConn(conn);
    }		
  }
  
  async function _deleteExpiredKyberKeyPairRecord() {
    let conn;
    
    try {
      //conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Delete expired Kyber key pair records");
			await _deleteExpiredKyberKeyPair(conn);

      console.log(wev.sayCurrentTime() + " Cycle is finished \n");			      
    }
    catch(e) {
      console.log(wev.sayCurrentTime() + " : " + e.message);
    }
    finally {
      //await dbs.dbClose(conn);
      dbs.releasePoolConn(conn);
    }
  }
}


deleteExpiredSession(interval);
