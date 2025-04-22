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
//#################################################################################################################################

"use strict";
const mailer = require("nodemailer");
const {TelegramClient} = require("telegramsjs");
const dbs = require('../lib/db_lib.js');


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


exports.sendEmail = async function(smtp_server, port, from, to, user, pass, subject, mail_body) {
  var secure = (port == 465)? true : false; 
  
  var transporter = mailer.createTransport({
    //service: 'gmail',
    host: smtp_server,
    port: port,
    secure: secure,
    auth: {
      user: user, // user of email sender
      pass: pass  // password of email sender
    }
  });

  var mailOptions = {
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



