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
// File name: input_sms_data.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-12-13      DW              Get important data for SMS server setup. It
//                                               is part of SMS installation program.
// V2.0.00       2023-02-09      DW              Rewrite with Node.js.
// V2.0.01       2023-04-13      DW              Put SMS administrator's email in a temporary file, if the platform is AlmaLinux 8. 
//#################################################################################################################################

"use strict";
const fs = require('fs');
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');
const prompt = require('prompt-sync')();         // For production use.
//-----------------------------------------------------------//
// Use CTRL-C to break the loop. For development stage only. //
//const prompt = require('prompt-sync')({sigint:true});       
//-----------------------------------------------------------//


function _isIPv4FormatOK(ip_addr) {
  var result = true;
  
  try {
    var ip_abcd = ip_addr.split(".");
    if (ip_abcd.length != 4) {
      result = false;
    }
    else {
      for (var i = 0; i < ip_abcd.length; i++) {
        var this_part = Number(ip_abcd[i]);
        
        if (isNaN(this_part)) {
          result = false;
        }
        else {
          if (this_part < 0 || this_part > 255) {
            result = false;
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


async function _verifyInputDataOK(connect_mode, site_dns, sa_email, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port, ip_addr1, ip_addr2) {
  var result = true;
  var buffer = [];
  
  try {
    connect_mode = Number(connect_mode);
    if (connect_mode < 0 || connect_mode > 3 || isNaN(connect_mode)) {
      console.log("  >>> Connection mode is incorrect.");
      result = false;      
    }
    
    if (wev.allTrim(site_dns) == "") {
      console.log("  >>> Site domain name is missing.");
      result = false;            
    }
    
    if (connect_mode != 1) {    
      if (connect_mode == 0 || connect_mode == 2) {
        buffer = sa_email.split("@");
        if (buffer.length != 2 || wev.allTrim(buffer[0]) == "" || wev.allTrim(buffer[1]) == "") {
          console.log("  >>> Administrator email is incorrect or missing.");
          result = false;                  
        }
      }
      
      if (connect_mode == 0 || connect_mode == 3) {
        buffer = tx_email.split("@");
        if (buffer.length != 2 || wev.allTrim(buffer[0]) == "" || wev.allTrim(buffer[1]) == "") {
          console.log("  >>> Worker email is incorrect or missing.");
          result = false;                  
        }
        
        if (wev.allTrim(tx_username) == "") {
          console.log("  >>> Username of the worker email is missing.");
          result = false;                  
        }
    
        if (wev.allTrim(tx_password) == "") {
          console.log("  >>> Password of the worker email is missing.");
          result = false;                  
        }
        
        if (wev.allTrim(tx_smtp_server) == "") {
          console.log("  >>> SMTP server for the worker email is missing.");
          result = false;                  
        }
        
        tx_smtp_port = Number(tx_smtp_port);
        if (tx_smtp_port < 0 || isNaN(tx_smtp_port)) {
          console.log("  >>> SMTP server port number is incorrect.");
          result = false;      
        }
      }
    }
    
    if (wev.allTrim(ip_addr1) == "" && wev.allTrim(ip_addr2) == "") {
      console.log("  >>> You must give me at least one internal IP address.");
      result = false;
    }
    else {
      if (wev.allTrim(ip_addr1) != "") {
        if (!_isIPv4FormatOK(ip_addr1)) {
          console.log(`  >>> Format of internal IP address #1 ${ip_addr1} is incorrect.`);
          console.log(`      It should be like 999.999.999.999, where 999 is from 0 to 255.`); 
          result = false;          
        }
      }
      
      if (wev.allTrim(ip_addr2) != "") {
        if (!_isIPv4FormatOK(ip_addr2)) {
          console.log(`  >>> Format of internal IP address #2 ${ip_addr1} is incorrect.`);
          console.log(`      It should be like 999.999.999.999, where 999 is from 0 to 255.`);           
          result = false;          
        }
      }      
    }
  }
  catch(e) {
    console.log(`Data verification error: ${e.message}`);
    result = false;
  }
  
  return result;
}


async function _updateConnectionMode(conn, connect_mode) {
  var sql, param;
  
  try {
    sql = `DELETE FROM sys_settings ` +
          `  WHERE sys_key = 'connection_mode'`;
    
    await dbs.sqlExec(conn, sql);
    
    sql = `INSERT INTO sys_settings ` +
          `(sys_key, sys_value) ` +
          `VALUES ` +
          `('connection_mode', ?)`;
          
    param = [connect_mode];      
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


async function _updateSiteDNS(conn, site_dns) {
  var sql, param;
  
  try {
    sql = `DELETE FROM sites ` +
          `  WHERE site_type IN ('DECOY', 'MESSAGE')`;
    
    await dbs.sqlExec(conn, sql);
    
    sql = `INSERT INTO sites ` +
          `(site_type, site_dns, status) ` +
          `VALUES ` +
          `('DECOY', ?, 'A')`;
    
    param = [site_dns];
    await dbs.sqlExec(conn, sql, param);

    sql = `INSERT INTO sites ` +
          `(site_type, site_dns, status) ` +
          `VALUES ` +
          `('MESSAGE', ?, 'A')`;
    
    param = [site_dns];
    await dbs.sqlExec(conn, sql, param);    
  }
  catch(e) {
    throw e;
  }
}


async function _updateAdminEmail(conn, sa_email) {
  var sql, param;
  
  try {
    if (wev.allTrim(sa_email) != "") {
      sql = `UPDATE user_list ` +
            `  SET email = ? ` +
            `  WHERE user_name = 'smsadmin' ` +
            `   AND STATUS = 'A'`;
            
      param = [sa_email];
      await dbs.sqlExec(conn, sql, param); 
    }     
  }
  catch(e) {
    throw e;
  }
}


async function _updateWorkerEmailAccount(conn, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port) {
  var sql, param;
  
  try {
    if (wev.allTrim(tx_email) != "") { 
      sql = `DELETE FROM sys_email_sender ` +
            `  WHERE email = ?`;
            
      param = [tx_email];
      await dbs.sqlExec(conn, sql, param);
      
      sql = `INSERT INTO sys_email_sender ` +
            `(email, m_user, m_pass, smtp_server, port, status) ` +
            `VALUES ` +
            `(?, ?, ?, ?, ?, 'A')`;
      
      param = [tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port];
      await dbs.sqlExec(conn, sql, param);
    }      
  }
  catch(e) {
    throw e;
  }
}


async function _updateInternalIPaddresses(conn, ip_addr1, ip_addr2) {
  var sql, param, data;
  
  try {
    ip_addr1 = wev.allTrim(ip_addr1);
    ip_addr2 = wev.allTrim(ip_addr2);
    
    //-- Note: Table 'internal_ip' is used for SMS 2.0 installation only. So, it should be removed --//
    //--       as installation process is completed.                                               --// 
    sql = `CREATE OR REPLACE TABLE internal_ip ` +
          `( ` +
          `  ip_addr varchar(20) ` +
          `)`;
    
    await dbs.sqlExec(conn, sql);
    
    if (ip_addr1 != "") {
      sql = `INSERT INTO internal_ip(ip_addr) VALUES (?)`;
      param = [ip_addr1];
      await dbs.sqlExec(conn, sql, param);
    }

    if (ip_addr2 != "") {
      sql = `INSERT INTO internal_ip(ip_addr) VALUES (?)`;
      param = [ip_addr2];
      await dbs.sqlExec(conn, sql, param);
    }      
  }
  catch(e) {
    throw e;
  }
}


async function _saveInputData(conn, connect_mode, site_dns, sa_email, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port, ip_addr1, ip_addr2) {
  var tx_on = false;
  
  try {
    if (await dbs.startTransaction(conn)) {
      tx_on = true;
      
      await _updateConnectionMode(conn, connect_mode);
      await _updateSiteDNS(conn, site_dns);
      await _updateAdminEmail(conn, sa_email);
      await _updateWorkerEmailAccount(conn, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port);
      await _updateInternalIPaddresses(conn, ip_addr1, ip_addr2);
      
      await dbs.commitTransaction(conn);
      
      tx_on = false;
    }
    else {
      throw new Error("Unable to start SQL transaction session.");
    }
  }
  catch(e) {
    if (tx_on) {
      await dbs.rollbackTransaction(conn);  
    }
    
    throw e;
  }
}


async function _createSuccessMarker(file_name, file_content) {
  try {
    fs.createWriteStream(file_name).write(file_content);
  }
  catch(e) {
    throw e;
  }
}


async function _extractDomainName(url) {
  var result = '';
  
  try {
    //-- Step 1: Remove 'https://' --//
    url = url.replace("https://", "");
    
    //-- Step 2: Remove port number (if any) --//
    var tmp_buf = url.split(':');
    url = tmp_buf[0];
    
    result = url;
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function getSMSdata() {
  var connect_mode = 0;
  var site_dns = '';
  var sa_email = '';
  var tx_email = '';
  var tx_username = '';
  var tx_password = '';
  var tx_smtp_server = '';
  var tx_smtp_port = 0;
  var ip_addr1 = '';
  var ip_addr2 = '';
  var stop_run = false;
  var conn;
  var correct = '';

  try {
    conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
  
    while (!stop_run) {
      connect_mode = prompt("Connection mode (0, 1, 2 or 3): ", connect_mode);
      site_dns = prompt("Site domain name (e.g. https://messaging-site.net:8443): ", site_dns);
      sa_email = prompt("Email address of SMS administrator: ", sa_email);
      tx_email = prompt("Worker email address of SMS: ", tx_email);
      tx_username = prompt("Username of the worker email account: ", tx_username);
      tx_password = prompt("Password of the worker email account: ", tx_password);
      tx_smtp_server = prompt("SMTP server of the worker email: ", tx_smtp_server);
      tx_smtp_port = prompt("Port number of the SMTP server: ", tx_smtp_port);
      ip_addr1 = prompt("Internal IP address #1: ", ip_addr1);
      ip_addr2 = prompt("Internal IP address #2: ", ip_addr2);
      
      if (await _verifyInputDataOK(connect_mode, site_dns, sa_email, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port, ip_addr1, ip_addr2)) {      
        console.log("\n\nYou have input:");
        console.log(`- Connection mode: ${connect_mode}`);
        console.log(`- Site domain name: ${site_dns}`);
        console.log(`- Email for SMS administrator: ${sa_email}`);
        console.log(`- Worker email address: ${tx_email}`);
        console.log(`- Worker email username: ${tx_username}`);
        console.log(`- Worker email password: ${tx_password}`);
        console.log(`- SMTP server for worker email: ${tx_smtp_server}`);
        console.log(`- SMTP server port number: ${tx_smtp_port}`);
        console.log(`- Internal IP address (v4) #1: ${ip_addr1}`);
        console.log(`- Internal IP address (v4) #2: ${ip_addr2}`);
        console.log("");
        
        correct = prompt("Are they correct (Y/N)? ");
        correct = correct.toUpperCase();
        if (correct == "Y") {
          connect_mode = Number(connect_mode);
          tx_smtp_port = Number(tx_smtp_port);
          
          await _saveInputData(conn, connect_mode, site_dns, sa_email, tx_email, tx_username, tx_password, tx_smtp_server, tx_smtp_port, ip_addr1, ip_addr2);
          stop_run = true;
          
          await _createSuccessMarker("/tmp/input_sms_data_ok", "OK");
          //-- Put SMS administrator email into a temporary file, and it will be used in next step if the platform is AlmaLinux 8. --// 
          await _createSuccessMarker("/tmp/sms_admin_email", sa_email);
          //-- Put site domain name into a temporary file, and it will be used in next step if the platform is AlmaLinux 8. --//
          await _createSuccessMarker("/tmp/sms_domain_name", await _extractDomainName(site_dns)); 
        }
        else {
          console.log("Repeat it again...\n\n");
        }       
      }
      else {
        console.log("\n\nIncorrect data input is found, try again...\n\n");
      }
    }
  }
  catch(e) {
    console.log(`Error: ${e.message}`);
  }
  finally {
    await dbs.dbClose(conn);
  }
}

getSMSdata();

