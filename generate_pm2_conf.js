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
// Program: generate_pm2_conf.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2023-03-24      DW              Generate the configuration file for PM2 to
//                                               handle the SMS 2.0 apps running.
// V1.0.01       2023-11-12      DW              Increse memory usage of the 2nd instance of
//                                               SMS server to 2048MB.
//#########################################################################################

"use strict";
const fs = require('fs');
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');

var dir = '';          // Directory of installation files located.
var param_ok = true;   // true = Passed parameter is OK, false = Otherwise.

process.argv.forEach((val, index) => {
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


async function _getPM2ConfigureParameters(conn) {
  var sql, data, idx;
  var result = {IP_1: '', IP_2: ''};
  
  try {
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


async function generatePM2ConfigurationFile() {
  var template = '';
  var pm2_conf = '';
  var buffer = '';  
  var conn;
  var conf_params = {};
  var ok = true;
  var err_msg = '';

  try {
    if (!param_ok || dir == '') {      
      var message = "Usage: generate_pm2_conf.js dir=<dir> \n\n" +
                    "where <dir> = directory of installation files located"; 
      
      throw new Error(message);
    }
    
    conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
    conf_params = await _getPM2ConfigureParameters(conn);
    
    template = `${dir}/sys/pm2-sms-server.json.template`;
    pm2_conf = `${dir}/sys/pm2-sms-server.json`;
    
    if (await wev.fileExist(template)) {
      buffer = Buffer.from(fs.readFileSync(template)).toString();
      
      if (conf_params.IP_1 == '' && conf_params.IP_2 == '') {
        err_msg = "At least one local IP address must be given."; 
        ok = false;
      }
      else {
        if (conf_params.IP_1 != '') {
          buffer = buffer.replace(/{local_ip_01}/g, conf_params.IP_1);
        }
        
        if (conf_params.IP_2 != '') {
          var app2_conf = `{\n` +
                          `      "name": "sms-server-02",\n` +
                          `      "script": "/www/sms2/smsserver.js",\n` +
                          `      "cwd" : "/www/sms2/",\n` + 
                          `      "args" : "ip=${conf_params.IP_2}",\n` +
                          `      "node_args": "--max-old-space-size=2048"\n` +
                          `    },`;
          
          buffer = buffer.replace(/{sms-server-02-instance}/g, app2_conf);
        }
        else {
          buffer = buffer.replace(/{sms-server-02-instance}/g, "");
        }
      }
      
      if (ok) {
        //-- Create PM2 configuration file --//      
        await _writeToFile(pm2_conf, buffer);        
        //-- Create process seccess marker --//
        await _writeToFile("/tmp/generate_pm2_conf_ok", "OK");
      }
      else {
        console.log(`Error: ${err_msg}`);
      }
    }
    else {
      console.log(`PM2 configuration template '${template}' is missing.`);
    }
    
  }
  catch(e) {
    console.log(e.message);
  }
  finally {
    await dbs.dbClose(conn);
  } 
}


generatePM2ConfigurationFile();
