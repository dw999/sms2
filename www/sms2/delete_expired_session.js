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
//##########################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');

const interval = 3600000;        // Repeat every hour
const key_rec_expired_days = 7;  // RSA and Kyber key pair records expired days

async function _deleteExpiredWebSession(conn) {
  let sql;
  
  try {
    sql = `DELETE FROM web_session ` +
          `  WHERE TIMEDIFF(CURRENT_TIMESTAMP(), sess_until) > '00:00:00' ` +
          `     OR status <> 'A'`;
          
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
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Clear MSG site expired web session");
      await _deleteExpiredWebSession(conn);
      console.log(wev.sayCurrentTime() + " Clear MSG site expired login token");
      await _deleteUsedAndTimeoutLoginToken(conn);
      console.log(wev.sayCurrentTime() + " Clear MSG site expired applicant record");
      await _delete_applicant_record(conn);      
    }
    catch(e) {
      console.log(e.message);
    }
    finally {
      await dbs.dbClose(conn);
    }
  }  
  
  
  async function _deleteDecoySiteExpiredSession() {
    let conn;
    
    try {
      conn = await dbs.dbConnect(dbs.selectCookie('PDA'));
      
      console.log(wev.sayCurrentTime() + " Clear decoy site expired web session");
      await _deleteExpiredWebSession(conn);      
    }
    catch(e) {
      console.log(e.message);
    }
    finally {
      await dbs.dbClose(conn);
    }
  }    
  
  async function _deleteExpiredRSAkeypairRecord() {
		let conn;
		
		try {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Delete expired RSA key pair records");
			await _deleteExpiredRsaKeyPair(conn);
		}
		catch(e) {
			console.log(e.message);
		}
		finally {
			await dbs.dbClose(conn);
		}		
	}
  
  async function _deleteExpiredKyberKeyPairRecord() {
    let conn;
    
    try {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
      
      console.log(wev.sayCurrentTime() + " Delete expired Kyber key pair records");
			await _deleteExpiredKyberKeyPair(conn);

      console.log(wev.sayCurrentTime() + " Cycle is finished \n");			      
    }
    catch(e) {
      console.log(e.message);
    }
    finally {
      await dbs.dbClose(conn);
    }
  }
}


deleteExpiredSession(interval);
