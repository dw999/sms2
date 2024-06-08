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

//#########################################################################################
// Program: generate_ssl_conf.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-12-20      DW              Generate the configuration file for web server
//                                               by using user given data in previous step.
// V2.0.00       2023-02-09      DW              Rewrite with Node.js. Note: Just handle Nginx
//                                               web server in this moment.
// V2.0.01       2023-04-04      DW              Remove 'https://' and port number to get DNS
//                                               name of the decoy and messaging sites before 
//                                               filling into the web server configuration 
//                                               template.
// V2.0.02       2023-04-26      DW              Handle web server configuration file for 
//                                               Ubuntu.   
//#########################################################################################

"use strict";
const fs = require('fs');
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');

var dir = '';  // Directory of installation files located.
var os = '';   // Operating system for SMS server.
var ws = '';   // Web server will be used by SMS server.
var param_ok = true;   // true = All passed parameters are OK, false = Otherwise.


process.argv.forEach((val, index) => {
  if (val.match(/os=/i)) {
  	var params = val.split("=");
  	var data = wev.allTrim(params[1]);
    if (data.toLowerCase() == 'centos' || data.toLowerCase() == 'ubuntu') {
      os = data.toLowerCase();
    } 
    else {
      console.log(`Invalid value of 'os' (${data}) is given, process is aborted now. It should be 'centos' or 'ubuntu'.\n`);
      param_ok = false;
    }
  }
  
  if (val.match(/ws=/i)) {
    var params = val.split("=");
    var data = wev.allTrim(params[1]);
    if (data.toLowerCase() == 'nginx' || data.toLowerCase() == 'apache') {
      // Remark: As at March 2023, it supports Nginx only.
      if (data.toLowerCase() == 'apache') {
        console.log(`Sorry, supporting web server of SMS 2.0 is Nginx only in this moment.`);
        console.log(`Apache web server will be added later. Process is aborted.\n`);
        param_ok = false;        
      }
      else {
        ws = data.toLowerCase();
      }
    }
    else {
      console.log(`Invalid value of 'ws' (${data}) is given, process is aborted now. It should be 'nginx' or 'apache'.\n`);
      param_ok = false;      
    }
  }
  
  if (val.match(/dir=/i)) {
    var params = val.split("=");
    var data = wev.allTrim(params[1]);
    
    if (data == '') {
      console.log(`Installation directory is missing, process is aborted now.\n`);
      param_ok = false;
    }
    else {
      dir = data;
    }
  }
});


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


async function _getWebServerConfigureParameters(conn) {
  var sql, data, idx;
  var result = {DECOY: '', MESSAGE: '', IP_1: '', IP_2: ''};
  
  try {
    //-- Step 1: Get DNS name of site(s) --//
    sql = `SELECT site_type, site_dns ` +
          `  FROM sites ` +
          `  WHERE status = 'A'`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));      
    
    for (var i = 0; i < data.length; i++) {
      var site_type = data[i].site_type;
      var site_dns = data[i].site_dns;
      
      if (site_type == "DECOY") {
        result.DECOY = await _extractDomainName(site_dns);
      }
      else if (site_type == "MESSAGE") {
        result.MESSAGE = await _extractDomainName(site_dns);
      }
    }
    
    //-- Step 2: Get local IP addresses --//
    sql = `SELECT ip_addr ` +
          `  FROM internal_ip ` +
          `  ORDER BY ip_addr`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));      
    
    idx = 1;
    for (var i = 0; i < data.length; i++) {
      var this_ip = data[i].ip_addr;
      
      if (idx == 1) {
        result.IP_1 = this_ip;
      }
      else if (idx == 2) {
        result.IP_2 = this_ip;
      }
      
      idx++;
    }          
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _writeToFile(file_name, file_content) {
  try {
    fs.createWriteStream(file_name).write(file_content);
  }
  catch(e) {
    throw e;
  }  
}


async function generateWebServerConfigurationFile() {
  var template = '';
  var ssl_conf = '';
  var decoy_site_server_name = '';
  var msg_site_server_name = '';
  var buffer = '';  
  var conn;
  var conf_params = {};
  var ok = true;
  var err_msg = '';

  try {
    if (!param_ok || os == '' || ws == '' || dir == '') {      
      var message = "Usage: generate_ssl_conf.js os=<os> ws=<ws> dir=<dir> \n\n" +
                    "where <os> = centos or ubuntu \n" +
                    "      <ws> = nginx or apache \n" +
                    "      <dir> = directory of installation files located"; 
      
      throw new Error(message);
    }
                
    conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
    conf_params = await _getWebServerConfigureParameters(conn);

    template = `${dir}/${ws}/${os}/sms-server.conf.template`;
    ssl_conf = `${dir}/${ws}/${os}/sms-server.conf`;
    
    if (await wev.fileExist(template)) {
      buffer = Buffer.from(fs.readFileSync(template)).toString();
      
      if (conf_params.DECOY != '' && conf_params.MESSAGE != '') {      
        buffer = buffer.replace(/{decoy_site_server_name}/g, conf_params.DECOY);
        buffer = buffer.replace(/{msg_site_server_name}/g, conf_params.MESSAGE);
      }      
      else {
        err_msg = "Not all required site DNS names are ready.";
        ok = false;
      }
            
      if (conf_params.IP_1 == '' && conf_params.IP_2 == '') {
        err_msg = "At least one local IP address must be given."; 
        ok = false;
      }
      else {
        if (conf_params.IP_1 != '') {
          buffer = buffer.replace(/{local_ip_01}/g, conf_params.IP_1);
        }
        
        if (conf_params.IP_2 != '') {
          buffer = buffer.replace(/{local_ip_02}/g, conf_params.IP_2);
        }
        else {
          buffer = buffer.replace(/server {local_ip_02}/g, "#server {local_ip_02}");
        }
      }
      
      if (ok) {
        //-- Create web server configuration file --//      
        await _writeToFile(ssl_conf, buffer);        
        //-- Create process seccess marker --//
        await _writeToFile("/tmp/generate_ssl_conf_ok", "OK");
      }
      else {
        console.log(`Error: ${err_msg}`);
      }
    }
    else {
      console.log(`Web server configuration template '${template}' is missing.`);
    }
  }
  catch(e) {
    console.log(e.message);
  }
  finally {
    await dbs.dbClose(conn);
  }
}


generateWebServerConfigurationFile();
