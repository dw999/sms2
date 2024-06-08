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
// Program: remove_converter_setting.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-12-27      DW              Remove system setting 'audio_converter' as
//                                               user don't install FFmpeg audio converter.
// V2.0.00       2023-03-20      DW              Rewrite with Node.js.
//#########################################################################################

"use strict";
const wev = require('./lib/webenv_lib.js');
const dbs = require('./lib/db_lib.js');


async function removeAudioConverterSetting() {
  var conn, sql, param;
  
  try {
    conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
    
    sql = `DELETE FROM sys_settings ` +
          `  WHERE sys_key = ?`;
    param = ['audio_converter'];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    console.log(`Unable to delete system setting 'audio_converter', please do it manually.`);
    console.log(`Error: ${e.message}`);
  }
  finally {
    await dbs.dbClose(conn);
  }
}


removeAudioConverterSetting();

