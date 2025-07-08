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
// File name: telecom_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2019-11-22      DW              Library of all telecommunications.
// V1.0.01       2022-08-09      DW              Rename function 'sendGmail' to 'sendEmail', and make it more generic. 
// V1.0.02       2025-04-22      DW              Replace Telegram message sending library 'telegram-bot-api' by 'telegramsjs'.
// V1.0.03       2025-06-03      DW              If system setting 'use_email_gateway' is 'TRUE', then use a remote SMTP gateway to 
//                                               send out email, in order to work around the situation where the SMS server is blocked
//                                               by the worker email server. 
// V1.0.04       2025-07-07      DW              Include DNS name of SMS server on the data set as using remote email gateway to send
//                                               out email.  
//#################################################################################################################################

"use strict";
const mailer = require("nodemailer");
const {TelegramClient} = require("telegramsjs");
const execSync = require('node:child_process').execSync;
const dbs = require('../lib/db_lib.js');
const wev = require('../lib/webenv_lib.js');
const cipher = require('../lib/cipher_lib.js');


exports.telegramBotDefined = async function(conn) {
  var tg_profile, bot_username, http_api_token, result;
  
  try {
    tg_profile = await _getTelegramBotProfile(conn);
    
    bot_username = tg_profile.bot_username;
    http_api_token = tg_profile.http_api_token;
      
    if (bot_username.trim() != '' && http_api_token.trim() != '') {
      result = true;
    }
    else {
      result = false;
    }
  }
  catch(e) {
    console.log(e.message);
    result = false;
  }
  
  return result;
}


exports.getTelegramBotApiToken = async function(conn) {
  var tg_profile, result;

  try {
    tg_profile = await _getTelegramBotProfile(conn);    
    result = tg_profile.http_api_token;
  }
  catch(e) {
  	console.log('Error: ' + e.message);
    result = '';
  }

  return result;
}


async function _getTelegramBotProfile(conn) {
  var sql, data;
  var result = {bot_name: '', bot_username: '', http_api_token: ''};
  
  try {
    sql = `SELECT bot_name, bot_username, http_api_token ` +
          `  FROM tg_bot_profile`;
    
    data = JSON.parse(await dbs.sqlQuery(conn, sql));

    if (data.length > 0) {
      var bot_name = (data[0].bot_name != null)? data[0].bot_name : '';
      var bot_username = (data[0].bot_username != null)? data[0].bot_username: '';
      var http_api_token = (data[0].http_api_token != null)? data[0].http_api_token : '';
          
      result = {bot_name: bot_name, bot_username: bot_username, http_api_token: http_api_token};      
    }
  }
  catch(e) {
    console.log(e.message);
  }
  
  return result;  
}


exports.getTelegramBotProfile = async function(conn) {
  var result = {bot_name: '', bot_username: '', http_api_token: ''};
  
  try {
    result = await _getTelegramBotProfile(conn);     
  }
  catch(e) {
    console.log(e.message);
  }
  
  return result;
}


exports.sendTelegramMessage = async function(http_api_token, tg_id, message) {
  let error = '';
  
  try {  
    let bot = new TelegramClient(http_api_token);
    let sent_message = await bot.sendMessage({chatId: tg_id, disableNotification: false, text: message});
    
    if (sent_message.content.trim() != message.trim()) {
      error = `Something is wrong, the client ${id} may not receive your message.`;
      console.log(error); 
    } 
  }
  catch(e) {
    error = `Telegram message sending error for ID ${tg_id}: ` + e.message;
    console.log(error);
  }
}


async function _selectMailWorker(conn) {
  var sqlcmd, data, result;

  try {
    sqlcmd = `SELECT ms_id ` +
             `  FROM sys_email_sender ` +
             `  WHERE status = 'A'`;

    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);

    if (data.length > 0) {
      if (data.length == 1) {
      	result = data[0].ms_id;
      }
      else {
        var work_list = new Array();
        for (var i = 0; i < data.length; i++) {
          work_list.push(data[i].ms_id);
        }
        //-- Select a email worker randomly --//
        result = work_list[Math.floor(Math.random()*work_list.length)];
      }
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


exports.getMailWorker = async function(conn) {
  var ms_id, sqlcmd, param, data, result;

  try {
    ms_id = await _selectMailWorker(conn);

    if (parseInt(ms_id, 10) > 0) {
      sqlcmd = `SELECT email, m_user, m_pass, smtp_server, port ` +
               `  FROM sys_email_sender ` +
               `  WHERE ms_id = ?`;
      param = [ms_id];
      data = await dbs.sqlQuery(conn, sqlcmd, param);
      data = JSON.parse(data);
   	
      if (data.length > 0) {
        result = {email:data[0].email, m_user:data[0].m_user, m_pass:data[0].m_pass, smtp_server:data[0].smtp_server, port:data[0].port}; 
      }
      else {
        result = {email:null};	
      }
    }
    else {
    	result = {email:null};
    }
  }
  catch(e) {
  	console.log('Error: ' + e.message);
    result = {email:null};
  }

  return result;
}


async function _justSendEmail(smtp_server, port, from, to, user, pass, subject, mail_body) {
  let secure = (port == 465)? true : false; 
  
  let transporter = mailer.createTransport({
    //service: 'gmail',
    host: smtp_server,
    port: port,
    secure: secure,
    auth: {
      user: user, // user of email sender
      pass: pass  // password of email sender
    }
  });

  let mailOptions = {
    from: from, // sender address
    to: to, // list of receivers
    subject: subject, // Subject line
    text: mail_body // plain text body
  };

  // send mail with defined transport object
  transporter.sendMail(mailOptions, function(err, data) {
    if (err) {
      console.log(`Unable to send email to ${to}:`);
      console.log(err);
    }
  });  
}


async function _sendEmailViaGateway(email_gateway, master_passwd, site_dns, smtp_server, port, from, to, user, pass, subject, mail_body) {
  let key, algorithm, enc_object, command, token, tk_iv, receiver, receiver_iv, m_subject, m_subject_iv, m_body, m_body_iv;  
  let site, site_iv, smtp, smtp_iv, sender, sender_iv, m_user, m_user_iv, m_pass, m_pass_iv;
  
  try {
    algorithm = "AES-GCM"; 
    
    // Step 1: Generate a temporary key //   
    key = cipher.generateTrueRandomStr('A', 128);

    // Step 2: Encrypt the temporary key with 'master_passwd' and put it into 'token' //
    enc_object = await cipher.aesEncrypt(algorithm, master_passwd, key);
    token = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    tk_iv = wev.base64Encode(enc_object.iv);
    
    // Step 3: Encrypt 'from', 'to', 'subject', 'mail_body', 'user', 'pass' and 'smtp_server' with 'key' //
    enc_object = await cipher.aesEncrypt(algorithm, key, from);
    sender = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    sender_iv = wev.base64Encode(enc_object.iv);
    
    enc_object = await cipher.aesEncrypt(algorithm, key, to);
    receiver = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    receiver_iv = wev.base64Encode(enc_object.iv);
    
    enc_object = await cipher.aesEncrypt(algorithm, key, subject);
    m_subject = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    m_subject_iv = wev.base64Encode(enc_object.iv);
    
    enc_object = await cipher.aesEncrypt(algorithm, key, mail_body);
    m_body = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    m_body_iv = wev.base64Encode(enc_object.iv);
    
    enc_object = await cipher.aesEncrypt(algorithm, key, user);
    m_user = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    m_user_iv = wev.base64Encode(enc_object.iv);
    
    enc_object = await cipher.aesEncrypt(algorithm, key, pass);
    m_pass = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    m_pass_iv = wev.base64Encode(enc_object.iv);

    enc_object = await cipher.aesEncrypt(algorithm, key, smtp_server);
    smtp = wev.base64Encode(new Uint8Array(enc_object.encrypted));
    smtp_iv = wev.base64Encode(enc_object.iv);
    
    // Note: 1. 'port' doesn't need to be encrypted and become string after transfer to remote site.                         //
    //       2. 'site_dns' is a string and can't be encoded to base64 string by using function wev.base64Encode, since it is //
    //          designed for Unit8Array objects.                                                                             // 
    command = `curl -X POST -H 'Content-Type: application/json' -d '{"token":"${token}","tk_iv":"${tk_iv}","from":"${sender}",` + 
              `"from_iv":"${sender_iv}","to":"${receiver}","to_iv":"${receiver_iv}","subject":"${m_subject}","subject_iv":"${m_subject_iv}",`+
              `"mail_body":"${m_body}","mail_body_iv":"${m_body_iv}","m_user":"${m_user}","m_user_iv":"${m_user_iv}","m_pass":"${m_pass}",` +
              `"m_pass_iv":"${m_pass_iv}","smtp":"${smtp}","smtp_iv":"${smtp_iv}","site":"${site_dns}","port":"${port}"}' ${email_gateway}`;
    
    let exec_result = JSON.parse(execSync(command, {timeout:120000, stdio:'pipe', encoding:'utf8'}));

    if (parseInt(exec_result.status, 10) != 1) {
      // Something is wrong, print the error message. //
      console.log(exec_result.message);      
    }        
  }
  catch(e) {
    throw e; 
  }
}


async function _updateMasterPasswd(conn, sys_key, sys_value) {
  var sql, param;
  
  try {
    sql = `UPDATE sys_settings ` +
          `  SET sys_value = ? ` +
          `  WHERE sys_key = ?`;
    
    param = [sys_value, sys_key];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


exports.sendEmail = async function(smtp_server, port, from, to, user, pass, subject, mail_body) {
  let conn, use_email_gateway, email_gateway, master_passwd, site_dns;
  
  try {
    conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
    
    use_email_gateway = await wev.getSysSettingValue(conn, 'use_email_gateway');
    email_gateway = await wev.getSysSettingValue(conn, 'email_gateway');
    
    if (use_email_gateway.toUpperCase() == "TRUE" && email_gateway.trim() != "") {
      site_dns = await wev.getSiteDNS(conn, 'M');      
      master_passwd = await wev.getSysSettingValue(conn, 'master_passwd');
            
      if (master_passwd.trim() == "") {
        master_passwd = "K5QO6zfF2H8XUYZz";
        await _updateMasterPasswd(conn, 'master_passwd', master_passwd); 
      }
    
      await _sendEmailViaGateway(email_gateway, master_passwd, site_dns, smtp_server, port, from, to, user, pass, subject, mail_body);      
    } 
    else {
      await _justSendEmail(smtp_server, port, from, to, user, pass, subject, mail_body);
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    await dbs.dbClose(conn);
  }    
}



