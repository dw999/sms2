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
// File name: webenv_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2019-11-12      DW              Common Javascript library for node.js back-end.
// V1.0.01       2023-08-08      DW              Fix a bug on function 'makeUrlAlive', which exclude the last numeric character in
//                                               the link.
// V1.0.02       2023-11-15      DW              Use "cipher.generateTrueRandomStr" to replace "_generateRandomStr". 
// V1.0.03       2024-03-05      DW              Add function "disableEmbedJavascript" which is used to disable embedded javascript
//                                               coding and highlight it with red colour.
// V1.0.04       2024-03-20      DW              Add functions "base64Encode" and "base64Decode".
// V1.0.05       2025-03-13      DW              Add function "minifyJS" which is used to compress JavaScript code block.
// V1.0.06       2025-06-09      DW              Fix a syntax error on function '_isLeapYear'.
//#################################################################################################################################

"use strict";
const fs = require('fs');
const path = require('node:path');
const execSync = require('node:child_process').execSync;
const imageThumbnail = require('image-thumbnail');
const { minify } = require("terser");
const dbs = require('../lib/db_lib.js');
const telecom = require('../lib/telecom_lib.js');
const cipher = require('../lib/cipher_lib.js');


//*** Note: These system parameters should be put on database later ***//
function _getGlobalValue(option) {
  var value;
  
  switch (option.toUpperCase()) {
    case 'COOKIE_PDA':
      value = 'PDA_USER';
      break;
      
    case 'COOKIE_MSG':
      value = 'MSG_USER';
      break;
      
    case 'COMP_NAME':
      value = 'PDA Tools Corp.';
      break;    
    
    case 'ITN_FILE_PATH':
      value = '/www/sms2/itnews/data';
      break;
      
    case 'ITN_TN_PATH':
      value = '/www/sms2/itnews/data/thumbnail';
      break
      
    case 'PDA_FILE_PATH':
      value = '/www/sms2/pdatools/data';  
      break;
      
    case 'PDA_IMG_PATH':
      value = '/www/sms2/pdatools/images';
      break;
      
    case 'PDA_TOOLS_PATH':
      value = '/www/sms2/pdatools/cgi-pl/tools';
      break;
      
    case 'PDA_BG_COLOR':
      value = '#E0F4FB';
      break;
      
    case 'RSA_KEY_POOL_SIZE':
      value = 50;
      break;  
      
    default:
      value = '';              
  }
  
  return value;
}


exports.getGlobalValue = function(option) {
  return _getGlobalValue(option);
}


function _allTrim(s) {
  if (s == null) {return '';}
  
  if (typeof s != "string") { return s; }
      
  while (s.substring(0,1) == ' ') {
    s = s.substring(1, s.length);
  }
  while (s.substring(s.length-1, s.length) == ' ') {
    s = s.substring(0, s.length-1);
  }
      
  return s;	
}


exports.allTrim = function(s) {      
  return _allTrim(s);	
}


function _padLeft(str, size, filler) {
  try {
    if (typeof(str) == "number") {
      str = str.toString();
    }
    else {
      if (typeof(str) != "string") {
        throw new Error("Passed data cannot be handled.");
      }
    }
    
    if (typeof(size) != "number" || isNaN(size)) {
      throw new Error("Passed data cannot be handled.");
    }
    
    if (typeof(filler) == "number") {
      filler = filler.toString();
    }
    else {
      if (typeof(filler) != "string") {
        throw new Error("Passed data cannot be handled.");
      }
    }
        
    while (str.length < size) {      
       str = filler + str;
    }    
  }
  catch(e) {
    throw e;
  }
  
  return str;  
}


exports.padLeft = function(str, size, filler) {
  try {
    str = _padLeft(str, size, filler);
  }
  catch(e) {
    throw e;
  }
  
  return str;
}


function _padRight(str, size, filler) {
  try {
    if (typeof(str) == "number") {
      str = str.toString();
    }
    else {
      if (typeof(str) != "string") {
        throw new Error("Passed data cannot be handled.");
      }
    }
    
    if (typeof(size) != "number" || isNaN(size)) {
      throw new Error("Passed data cannot be handled.");
    }
    
    if (typeof(filler) == "number") {
      filler = filler.toString();
    }
    else {
      if (typeof(filler) != "string") {
        throw new Error("Passed data cannot be handled.");
      }
    }
        
    while (str.length < size) {      
       str = str + filler;
    }    
  }
  catch(e) {
    throw e;
  }
  
  return str;  
}


exports.padRight = function(str, size, filler) {
  try {
    str = _padRight(str, size, filler);
  }
  catch(e) {
    throw e;
  }
  
  return str;
}


exports.back = function() {
  var result = `<script language="javascript" type="text/javascript">
                  history.go(-1);
                </script>`;

  return result;
}


function _getRandomInt(max) {
	return Math.floor(Math.random() * Math.floor(max));
}


//-- This function is phased out, and replaced by cipher.generateTrueRandomStr --//
function _generateRandomStr(option, max_len) {
  var result = '';
  var ascii_list = new Array();
  var max_ascii_value = 0; 
  var stop_run = 0;
  var cnt = 0;

	//*-- Valid options are: 'A' = Alphanumeric, 'N' = Numeric only, 'S' = English characters only. --*//
  if (typeof(option) != 'string') {
    option = 'A';  
  }
  else {
    option = _allTrim(option);
    
    if (option == '') {
      option = 'A';
    }
    else {
      option = option.toUpperCase();
      if (option != 'A' && option != 'N' && option != 'S') {
        option = 'A';
      }
    }
  } 
  
  max_len = (max_len <= 0)? 10 : max_len;
  

  if (option == 'N') {
    for (var i = 48; i <= 57; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 57;    
  } 
  else if (option == 'S') {
    for (var i = 65; i <= 90; i++) {
    	ascii_list.push(i);
    }

    for (var i = 97; i <= 122; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 122;
  }
  else {
    for (var i = 48; i <= 57; i++) {
    	ascii_list.push(i);
    }

    for (var i = 65; i <= 90; i++) {
    	ascii_list.push(i);
    }

    for (var i = 97; i <= 122; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 122;
  }
  
  while (stop_run == 0) {
    var this_ascii = _getRandomInt(max_ascii_value);
    var valid_value = 0;

    if (ascii_list.includes(this_ascii)) {
      result += String.fromCharCode(this_ascii);
      cnt = 0;
    }

    if (result.length >= max_len) {
    	stop_run = 1;
    }

    if (cnt >= 100) {
    	stop_run = 1;
    }
    else {
    	cnt++;
    }
  }

  return result;  
}


//-- This function is phased out, and replaced by cipher.generateTrueRandomStr --//
exports.generateRandomStr = function(option, max_len) {
  return _generateRandomStr(option, max_len);
}


exports.reverseStr = function (str) {
  var result = '';
  
  if (typeof(str) === 'string') {
    for (var i = str.length - 1; i >= 0; i--) {
	    result = result + str.charAt(i);
    }
  }
  
  return result;
}


exports.asciiToHex = function(str) {
	var arr1 = [];
  
	for (var n = 0, l = str.length; n < l; n ++) {
		var hex = Number(str.charCodeAt(n)).toString(16);
		arr1.push(hex.toUpperCase());
  }
  
	return arr1.join('');
}


async function _getSysSettingValue(conn, sys_key) {
  var sqlcmd, param, data, result;
  
  try {
    sqlcmd = `SELECT sys_value ` +
             `  FROM sys_settings ` +
             `  WHERE sys_key = ?`;
    param = [sys_key];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);

    if (data.length > 0) {
      result = data[0].sys_value;
    }
    else {
      result = '';
    }               
  }
  catch(e) {
		var msg = 'Error: ' + e.message;
    console.log(msg);
    result = '';    
  }
  
  return result;  
}


exports.getSysSettingValue = async function(conn, sys_key) {
  return await _getSysSettingValue(conn, sys_key);
}


async function _generateSessionCode(conn, option, max_len) {  
  var sqlcmd, param, data, stop_run, cnt, rec_cnt, sess_code;
  
  sess_code = '';
  
  try {
    if (typeof(max_len) != 'number') {
      max_len = 64;
    }
    else {
      max_len = parseInt(max_len, 10);
      
      if (max_len < 64) {
        max_len = 64;
      }
      else if (max_len > 128) {
        max_len = 128;
      }
    }
    
    stop_run = false;
    cnt = 0;
    while (!stop_run) {
      //sess_code = _generateRandomStr(option, max_len);     // function '_generateRandomStr' is phased out. 
      sess_code = cipher.generateTrueRandomStr(option, max_len);
      
      sqlcmd = `SELECT COUNT(*) AS rec_cnt ` +
               `  FROM web_session ` +
               `  WHERE sess_code = ?`;
      param = [sess_code];
      data = await dbs.sqlQuery(conn, sqlcmd, param);
      data = JSON.parse(data);
      rec_cnt = data[0].rec_cnt;
      
      stop_run = (rec_cnt == 0)? true : false;
      
      if (!stop_run) {
        cnt++;
        
        if (cnt > 20) {
          //-- It is the last resort --//
          //sess_code = _generateRandomStr('A', 72);         // Note: function '_generateRandomStr' is phased out.
          sess_code = cipher.generateTrueRandomStr(option, 72);          
          stop_run = true;
        }
      }          
    }
  }
  catch(e) {
    //-- Emergency measure --//
    //sess_code = _generateRandomStr('A', 72);              // Note: function '_generateRandomStr' is phased out.
    sess_code = cipher.generateTrueRandomStr(option, 72);
  }

  return sess_code; 
}


function _isLeapYear(year) {
	//-- Every 400 years in gregorian is leap, but in julian it isn't. --//
	if ((year % 400) == 0) 	{		
		if (year < 1752) 		{
			return false;
		}
		else 		{
			return true;
		}
	}	
	else 	{
		//-- Other centuries are not leap --//
		if ((year % 100) == 0) {
			return false;
		}
		else {
			//-- Normal system: every 4th year is leap --//
			if ((year % 4) == 0) {
				return true;
			}
			else {
				return false;
			}
		}
	}  
}


exports.isLeapYear = function(year) {
  return _isLeapYear(year);
}


async function _setSessionValidTime() {
  var conn, sqlcmd, param, data, year, month, day, hour, min, sec, session_period, session_time_limit;
  
  session_time_limit = '';
  
  try {
    conn = await dbs.dbConnect('COOKIE_MSG');      // Note: Value of session_period is stored on msgdb only.
    
    session_period = _allTrim(await _getSysSettingValue(conn, 'session_period'));
    if (session_period == '') {
      //-- Default session valid period is 2 hours --//
      session_period = '02:00:00';      
    }
    
    sqlcmd = `SELECT DATE_FORMAT(ADDTIME(CURRENT_TIMESTAMP(), ?), '%Y-%m-%d %H:%i:%s') AS time_limit`;
    param = [session_period]
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      session_time_limit = data[0].time_limit;
    }
    
    //-- Last resort --//
    if (session_time_limit == '') {
      var days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
      var today = new Date();
      year = today.getFullYear();  
      month = today.getMonth() + 1;
      day = today.getDate();
      hour = today.getHours();
      min = today.getMinutes();
      sec = today.getSeconds();
      
      if (_isLeapYear(year)) {
        days_in_month[2] = 29;
      } 
      
      //-- Default session valid period is 2 hours --//
      hour += 2;
      if (hour > 24) {hour -= 24; day++;}
      if (day > days_in_month[month]) {day -= days_in_month[month]; month++;}
      if (month > 12) {month -= 12; year++;}
      
      month = month.toString().padStart(2, '0');
      day = day.toString().padStart(2, '0');
      hour = hour.toString().padStart(2, '0');
      min = min.toString().padStart(2, '0');
      sec = sec.toString().padStart(2, '0');
      
      session_time_limit = year + '-' + month + '-' + day + ' ' + hour + ':' + min + ':' + sec;      
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    await dbs.dbClose(conn);
  }

	return session_time_limit;	    
}


exports.setSessionValidTime = async function() {
  try {
    return await _setSessionValidTime();
  }
  catch(e) {
    throw e;
  }
}


exports.createSessionRecord = async function(conn, user_id, aes_key, http_user_agent, ip_addr) {
  var sqlcmd, param, data, sess_code, secure_key, valid_until, ip_address, result;

  result = {ok: false, msg: '', sess_code: ''};

  try {
    //-- Step 1: Create new session record for user --//
    sess_code = await _generateSessionCode(conn, 'A', 64);
    secure_key = (typeof(aes_key) != "string")? '' : aes_key;     // It is the secret key used for message encryption and decryption during message sent in and out. 
    valid_until = await _setSessionValidTime();         // Don't call publicly exported function 'setSessionValidTime' directly.  
        
    sqlcmd = `INSERT INTO web_session ` +
             `(sess_code, user_id, sess_until, ip_address, http_user_agent, secure_key, status) ` +
             `VALUES ` +
             `(?, ?, ?, ?, ?, ?, 'A')`;
    param = [sess_code, user_id, valid_until, ip_addr, http_user_agent, secure_key];         
    data = await dbs.sqlExec(conn, sqlcmd, param);
    
    //-- Step 2: Delete all other active session record(s) of this user except the newest created one. i.e. Just one live session --//
    //--         per user is allowed.                                                                                             --//
    sqlcmd = `DELETE FROM web_session ` +
             `  WHERE user_id = ? ` +
             `  AND sess_code <> ? ` +
             `  AND status = 'A'`;
    param = [user_id, sess_code];
    data = await dbs.sqlExec(conn, sqlcmd, param);         
        
    result = {ok: true, msg: '', sess_code: sess_code};                  
  }
  catch(e) {
    result = {ok: false, msg: e.message, sess_code: ''}; 
    throw e;
  }  
    
  return result;
}


exports.getSiteDNS = async function(conn, type) {
  var sqlcmd, param, data, site_type, site_dns
  
  try {
    type = _allTrim(type.toUpperCase());
    
    if (type == 'D' || type == 'M') {
      site_type = (type == 'D')? 'DECOY' : 'MESSAGE';
      
      sqlcmd = `SELECT site_dns ` +
               `  FROM sites ` +
               `  WHERE site_type = ? ` +
               `    AND status = 'A'`;
      param = [site_type];
      data = await dbs.sqlQuery(conn, sqlcmd, param);
      data = JSON.parse(data);
      
      if (data.length > 0) {
        site_dns = data[0].site_dns;
      }
      else {
        site_dns = '';
      }         
    }
    else {
      site_dns = '';
    }
  }
  catch(e) {
    site_dns = '';
    console.log(e.message);
  }
  
  return site_dns;
}


exports.getSessionCode = function(cookie) {
  var sess_code = '';
  
  try {
    var session = JSON.parse(cookie);
    sess_code = session.sess_code;
  }
  catch(e) {
    console.log(e.message);
  }
  
  return sess_code;
}


exports.getSessionUserId = function(cookie) {
  var user_id = 0;
  
  try {
    var session = JSON.parse(cookie);
    user_id = parseInt(session.user_id, 10);
  }
  catch(e) {
    console.log(e.message);
  }
  
  return user_id;
}


async function _fileNameParser(file) {
  var filename, dirs, ext;
  var result = {filename: '', dirs: '', ext: ''};
  
  try {
    if (_allTrim(file) != '') {    
      //-- Note: 'filename' is the file name without extension --//
      var fullname = path.basename(file);
      var parts = fullname.split('.');    
      if (parts.length == 1) {
        filename = fullname;
      }
      else if (parts.length == 2) {
        filename = parts[0];
      }
      else if (parts.length >= 3) {
        filename = parts[0];
        for (var i = 1; i < parts.length - 1; i++) {
          filename += '.' + parts[i];
        }
      }
      
      dirs = path.dirname(file) + '/';        // Fill directory name where the file located
      ext = path.extname(file);               // The file extension with '.' in front of it.
      
      result = {filename: filename, dirs: dirs, ext: ext};
    }
  }
  catch(e) {
    console.log(e.message);
  }
  
  return result;  
}


exports.fileNameParser = async function(file) {
  var result = {filename: '', dirs: '', ext: ''};
  
  try {    
    result = await _fileNameParser(file);
  }
  catch(e) {
    console.log(e.message);
  }
  
  return result;
}


exports.findFileType = async function(conn, file_ext) {
  var sql, param, data, result;
  
  result = '';
  file_ext = file_ext.replace('.', '');
    
  try {
    sql = `SELECT file_type ` +
          `  FROM file_type ` +
          `  WHERE file_ext = ?`;
          
    param = [file_ext];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = data[0].file_type;
    }          
  }
  catch(e) {
    console.log(e.message);
  }

  return _allTrim(result);  
}  


async function _fileExist(file) {
  var result;
  
  try {
    if (fs.existsSync(file)) {
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


exports.fileExist = async function(file) {
  var result;
  
  try {
    result = await _fileExist(file); 
  } catch(e) {
    result = false;
  }  
  
  return result;
}


function _fileSize(file) {
  var size = 0;

  try {
    stats = fs.statSync(file);
    size = stats.size;
  }
  catch(e) {
    console.log(e.message);
    size = 0;
  }

  return size;
}


async function _deleteFile(file) {
  var result = true;
  
  try {
    if (_allTrim(file) != '') {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }            
  }
  catch(e) {
    console.log(e.message);
    result = false;
  }
  
  return result;
}


exports.deleteFile = async function(file) {
  var result = true;
  
  try {
    result = await _deleteFile(file);
  }
  catch(e) {
    result = false;    
  }
  
  return result;
} 


exports.copyFile = async function(src, dest) {
  var result = true;
  
  try {
    if (_fileExist(src)) {
      fs.copyFileSync(src, dest, fs.constants.COPYFILE_EXCL, (error) => {
        if (error) {
          console.log(error);
          result = false;
        }
        else {
          result = true;
        }  
      });
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


exports.fileUpload = async function (upload_file, file_path) {
  var file, filename;  

  try {
    file = upload_file.ul_file; 
    //-- Handle UTF-8 file name (mostly Chinese file name) with 'decodeURIComponent' and 'escape'.  --// 
    //-- Assume the uploaded file name has been treated with 'unescape' and 'encodeURIComponent' in --//
    //-- the front end.                                                                             --//  
    filename = file_path + '/' + decodeURIComponent(escape(file.name));
    
    if (await _fileExist(filename)) {
      var new_filename = new Date().getTime() + '_' + decodeURIComponent(escape(file.name)); 
      filename = file_path + '/' +  new_filename;            
    }
    else {
      //-- Change file name if it is too short. It is work-around a mysterious bug as upload a new image --//
      //-- but old image with name 'image.jpg' shown on client side.                                     --//
      var this_filename = decodeURIComponent(escape(file.name));
      if (this_filename.length < 12) {
        var new_filename = new Date().getTime() + '_' + decodeURIComponent(escape(file.name)); 
        filename = file_path + '/' +  new_filename;                    
      }      
    }
        
    //-- Note: Don't use the method on frozen code segment, or else this function will return control --//
    //--       to the caller before the 'mv' operation is finished, let next operations depended on   --//
    //--       the uploaded file fail, like the uploaded file doesn't exist, but actually it exists.  --//  
    /*
    file.mv(filename, (err) => {
      if (err) {
        console.log(err);
        filename = '';
      }
    });
    */
    await file.mv(filename);   
  }
  catch(e) {
    console.log(e.message);
    filename = '';
  }
  
  return filename;
}


exports.createThumbnail = async function(src_filename, thumbnail_path) {
  var filename, ext, tn_filename, options, thumbnail;
  
  try {
    var fileinfo = await _fileNameParser(src_filename);
    filename = _allTrim(fileinfo.filename);
    ext = _allTrim(fileinfo.ext);
    tn_filename = thumbnail_path + '/' + filename + '.jpg';
        
    //-- Force thumbnail file format as JPEG --//
    options = {percentage: 30, jpegOptions: {force:true, quality:90}};
    //-- Note: 'thumbnail' is a buffer variable --// 
    thumbnail = await imageThumbnail(src_filename, options);    
    //-- Write the generated 'thumbnail' buffer to file --//
    fs.createWriteStream(tn_filename).write(thumbnail);
  }
  catch(e) {
    console.log(e.message);
    tn_filename = '';
  }
  
  return tn_filename;
}


async function _checkFileConversionResult(input_file, output_file) {
  var result = '';
  
  try {
    if (await _fileExist(output_file)) {
      await _deleteFile(input_file);
      result = output_file;  
    }
    else {
      console.log(`Unable to create HTML5 compatible audio file ${output_file}`);
      result = input_file;      
    }
  }
  catch(e) {
    console.log(e.message);
    result = input_file;    
  }
  
  return result;
} 


exports.convertAudioFile = async function(audio_converter, input_file) {
  var f_name, dirs, output_file;
  
  try {
    if (await _fileExist(input_file)) {
      var fileinfo = await _fileNameParser(input_file);
      f_name = _allTrim(fileinfo.filename);
      dirs = _allTrim(fileinfo.dirs);
      output_file = `${dirs}${f_name}.ogg`;

      //-- Note: To define a audio converter setting, the generic format is as follows:                                                 --//
      //--       audio_converter_with_full_path <optional options> '{input_file}' <optional options> '{output_file}' <optional options> --//
      //--       For example: /usr/bin/ffmpeg -i '{input_file}' '{output_file}'                                                         --//        
      audio_converter = audio_converter.replace(/{input_file}/g, input_file).replace(/{output_file}/g, output_file);
      
      //-- Creates a new shell and executes command 'audio_converter' --//
      var console_result = execSync(audio_converter, {timeout:120000});
      //console.log(console_result.toString());    // This line for debug only.
      //-- Command 'audio_converter' is executed successfully, then check the file conversion result. --//
      //-- Note: Key word 'await' can't be used within the 'exec' block directly, because it is not an async function.      --//
      //--       Therefore, a new async function '_checkFileConversionResult' is used for file conversion result checking.  --// 
      output_file = await _checkFileConversionResult(input_file, output_file);
    }
    else {
      console.log(`Input file ${input_file} doesn't exist.`);
      output_file = input_file;
    }
  }
  catch(e) {
    console.log(e.message);
    output_file = input_file;
  }
  
  return output_file;
}


exports.makeUrlAlive = function(webpage) {
  return webpage.replace(/(\b(https?|ftp|file):\/\/[\-A-Z0-9+&@#\/%?=~_|!:,.;]*[\-A-Z0-9+&@#\/%=~_|])/img, '<a href="$1">$1</a>');
}


exports.printHeader = function(title) {
  var html;
  
  title = (typeof(title) != 'string')? '' : title;
  
  html = `
  <!doctype html>
  <html>  
  <head>
    <title>${title}</title>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <meta http-equiv='Content-Type' content='text/html; charset=utf-8'> 
  </head>  
  `;
  
  return html;
}


async function _getDecoyCompanyName(conn) {
  var result;
  
  try {
    result = await _getSysSettingValue(conn, 'decoy_company_name');
    if (result == '') {
      result = _getGlobalValue('COMP_NAME');
    }     
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.getDecoyCompanyName = async function(conn) {
  var result;
  
  try {
    result = await _getDecoyCompanyName(conn);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.getDecoySiteCopyRight = async function(conn) {
  var company_name, year, result;
  
  try {
    company_name = await _getDecoyCompanyName(conn);
    year = new Date().getFullYear();
    
    result = `Copyright &copy; 2000-${year} ${company_name}`;    
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function _sqlInjectionDetect(str) {
  var result = false;
  
  //-- Clearly, this function is not suitable to check a message block --//
  //-- which is freely input by users.                                 --//
  if (str.match(/insert/gi) != null) {
    result = true;
  }
  else if (str.match(/update/gi) != null) {
    result = true;
  }
  else if (str.match(/delete/gi) != null) {
    result = true;
  }
  else if (str.match(/union/gi) != null) {
    result = true;
  }
  else if (str.match(/where/gi) != null) {
    result = true;
  }
  else if (str.match(/outer/gi) != null) {
    result = true;
  }
  else if (str.match(/inner/gi) != null) {
    result = true;
  }
  else if (str.match(/join/gi) != null) {
    result = true;
  }
  else if (str.match(/values/gi) != null) {
    result = true;
  }
  else if (str.match(/alter/gi) != null) {
    result = true;
  }
  else if (str.match(/create/gi) != null) {
    result = true;
  }
  else if (str.match(/between/gi) != null) {
    result = true;
  }
  else if (str.match(/distinct/gi) != null) {
    result = true;
  }
  else if (str.match(/drop/gi) != null) {
    result = true;
  }
  else if (str.match(/group/gi) != null) {
    result = true;
  }
  else if (str.match(/having/gi) != null) {
    result = true;
  }
  else if (str.match(/like/gi) != null) {
    result = true;
  }
    
  return result;
}


exports.sqlInjectionDetect = function(str) {
  return _sqlInjectionDetect(str);
}


function _antiXSScodeEmbed(str) {
  str = str.replace(/<script>/gi, '');
  str = str.replace(/<\/script>/gi, '');
  str = str.replace(/<script/gi, '');
  str = str.replace(/<\/script/gi, '');
  str = str.replace(/%3Cscript/gi, '');
  str = str.replace(/%3Escript/gi, '');
  str = str.replace(/<iframe/gi, '');
  str = str.replace(/3Ciframe/gi, '');
  str = str.replace(/<\/iframe/gi, '');
  str = str.replace(/%3Eiframe/gi, '');
  
  return str;
}


exports.antiXSScodeEmbed = function(str) {
  return _antiXSScodeEmbed(str);
}


exports.disableEmbedJavascript = function(text) {
  let result;
  
  try {
    result = text;
    result = result.replace(/\<script\>/gi, "<font color=red>");
    result = result.replace(/%3Cscript%3E/gi, "<font color=red>");
    result = result.replace(/\<script%3E/gi, "<font color=red>");
    result = result.replace(/%3Cscript\>/gi, "<font color=red>");
    result = result.replace(/\<script /gi, "<font color=red>");
    result = result.replace(/\%3Cscript%20/gi, "<font color=red>");
    result = result.replace(/\%3Cscript /gi, "<font color=red>");
    result = result.replace(/\<\/script\>/gi, "</font>");
    result = result.replace(/\<\/script%3E/gi, "</font>");
    result = result.replace(/%3C\/script%3E/gi, "</font>");
    result = result.replace(/%3C\/script\>/gi, "</font>");
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.informSystemAdmin = async function(conn, subject, mail_content) {
  var sql, data, mail_worker;
  var result = {ok: true, msg: ''};
  
  try {
    mail_worker = await telecom.getMailWorker(conn);
    
    if (mail_worker.email != null) {
      sql = `SELECT name, user_alias, email ` +
            `  FROM user_list ` +
            `  WHERE user_role = 2 ` +
            `    AND status = 'A'`;
            
      data = JSON.parse(await dbs.sqlQuery(conn, sql));
      
      for (var i = 0; i < data.length; i++) {
        //-- Note: User alias is a more secretive data, so it should not be put on email unless user name is blank. --//
        var this_admin = (_allTrim(data[i].name) != '')? data[i].name : data[i].user_alias;    
        var this_email = _allTrim(data[i].email);
        
        if (typeof(this_email) == 'string' && this_email != '') {
          var mail_body = `Hi ${this_admin}, \n\n` +
                          `${mail_content} \n\n` +
                          `Best Regards, \n` +
                          `Information Team.\n`;
          
          await telecom.sendEmail(mail_worker.smtp_server, mail_worker.port, mail_worker.email, this_email, mail_worker.m_user, mail_worker.m_pass, subject, mail_body);
        }          
      }      
    }
    else {
      result = {ok: false, msg: 'No email worker is found, unable to inform administrator via email.'};  
    }
  }
  catch(e) {
    console.log(e.message);
    result = {ok: false, msg: e.message};
  }
    
  return result;
}


exports.informMember = async function(conn, user_id, subject, mail_content) {
  var sql, data, mail_worker;
  var result = {ok: true, msg: ''};

  try {
    mail_worker = await telecom.getMailWorker(conn);
    
    if (mail_worker.email != null) {
      sql = `SELECT name, user_alias, email ` +
            `  FROM user_list ` +
            `  WHERE user_id = ? ` +
            `    AND status = 'A'`;
      
      param = [user_id];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      if (data.length > 0) {
        //-- Note: User alias is a more secretive data, so it should not be put on email unless user name is blank. --//
        var this_name = (_allTrim(data[i].name) != '')? data[i].name : data[i].user_alias;    
        var this_email = _allTrim(data[i].email);
        
        if (typeof(this_email) == 'string' && this_email != '') {
          var mail_body = `Hi ${this_name}, \n\n` +
                          `${mail_content} \n\n` +
                          `Best Regards, \n` +
                          `Information Team.\n`;
          
          await telecom.sendEmail(mail_worker.smtp_server, mail_worker.port, mail_worker.email, this_email, mail_worker.m_user, mail_worker.m_pass, subject, mail_body);          
        }
        else {
          result = {ok: false, msg: 'This user has no email address, unable to inform this guy via email.'};
        }
      }
      else {
        result = {ok: false, msg: 'Unable to find this user, operation is aborted.'};
      }
    }
    else {
      result = {ok: false, msg: 'No email worker is found, unable to inform member via email.'};      
    }
  }
  catch(e) {
    console.log(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;
}


function _sayCurrentTime() {
  var today, curr_time;
  
  try {
    today = new Date();
    curr_time = today.getFullYear() + "-" + _padLeft(today.getMonth() + 1, 2, "0") + "-" + _padLeft(today.getDate(), 2, "0") + " " + 
                _padLeft(today.getHours(), 2, "0") + ":" + _padLeft(today.getMinutes(), 2, "0") + ":" + _padLeft(today.getSeconds(), 2, "0");                        
  }
  catch(e) {
    throw e;
  }
  
  return curr_time;  
} 
 

exports.sayCurrentTime = function() {
  var today, curr_time;
  
  try {
    curr_time = _sayCurrentTime();    
  }
  catch(e) {
    throw e;
  }
  
  return curr_time;
}


function _stripSecondAway(date_time, type) {
  var dt_parts, time, time_parts, result;
  
  try {
    if (type == "DT") {        // Data type is DATETIME
      dt_parts = date_time.split(" ");
      time = _allTrim(dt_parts[1]);
      time_parts = time.split(":");    
      result = dt_parts[0] + " " + time_parts[0] + ":" + time_parts[1];
    }
    else {                     // Then assume data type is TIME  
      time = _allTrim(date_time);
      time_parts = time.split(":");    
      result = time_parts[0] + ":" + time_parts[1];      
    } 
  }
  catch(e) {
    //-- The last resort: garbage in, garbage out. :) --//
    result = date_time;
  }
  
  return result;
}


exports.getCurrentDateTime = async function(conn, options) {
  var sql, data, result;
  
  try {
    options = (typeof(options) != "object" || typeof(options) == "undefined")? {no_sec: false} : (typeof(options.no_sec) != "boolean")? {no_sec: false} : options;
    
    sql = `SELECT DATE_FORMAT(CURRENT_TIMESTAMP(), '%Y-%m-%d %H:%i:%s') AS cdt`;
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    result = data[0].cdt;
    
    if (options.no_sec) {
      result = _stripSecondAway(result, "DT");
    }
  }
  catch(e) {
    //-- The last resort --//
    result = _sayCurrentTime();
    
    if (options.no_sec) {
      result = _stripSecondAway(result, "DT");
    }
  }
  
  return result;
}


exports.getCurrentTime = async function(conn, options) {  
  var sql, data, result;
  
  try {
    options = (typeof(options) != "object" || typeof(options) == "undefined")? {no_sec: false} : (typeof(options.no_sec) != "boolean")? {no_sec: false} : options;
    
    sql = `SELECT DATE_FORMAT(CURRENT_TIME(), '%H:%i:%s') AS ct`;
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    result = data[0].ct;
    
    if (options.no_sec) {
      result = _stripSecondAway(result, "T");  
    } 
  }
  catch(e) {
    //-- The last resort --//
    var current_datetime = _sayCurrentTime();
    var datetime_parts = current_datetime.split(" ");
    result = _allTrim(datetime_parts[1]);
    
    if (options.no_sec) {
      result = _stripSecondAway(result, "T");
    }    
  }
  
  return result;
}


exports.setHoursLater = async function(conn, datetime, hour) {
  var sql, param, data, time_add, result;
  
  try {
    time_add = wev.padLeft(hour, 2, "0") + ":00:00";
    
    sql = `SELECT DATE_FORMAT(ADDTIME(?, ?), '%Y-%m-%d %H:%i:%s') AS end_datetime;`;
    param = [datetime, time_add];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = _stripSecondAway(data[0].end_datetime, "DT");    
  }
  catch(e) {
    //-- Last resort --//
    var dt_parts = datetime.split(" ");
    var time = _allTrim(dt_parts[1]);
    var time_parts = time.split(":");
    
    if (parseInt(time_parts[0], 10) + hour <= 23) {
      time_parts[0] = _padLeft(parseInt(time_parts[0], 10) + hour, 2, "0");       
    }
    else {
      time_parts[0] = "23";
    }
    
    time = time_parts[0] + ":" + time_parts[1];
    result = dt_parts[0] + " "  + time;
  }
  
  return result;
}


exports.base64Encode = function(u8) {
  return btoa(String.fromCharCode.apply(null, u8))
}


exports.base64Decode = function(str) {
  return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)))
}


exports.minifyJS = async function(js) {
  let options, buffer, result;
  
  try {
    options = {
      keep_fnames: true
    };
    
    buffer = await minify(js, options);
    result = buffer.code;     
  }
  catch(e) {
    // The last resort //
    result = js;
  }
  
  return result;
} 
