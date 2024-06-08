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
// File name: db_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2022-04-12      DW              Database operation library for Node.js applications by using MariaDB native driver.
// V1.0.01       2022-08-24      DW              - Set MariaDB database connection timeout to 5000 ms. It decreases the chance to get 
//                                                 connection timeout error on heavy loading server.
//                                               - Implement database connection pool and related functions.  
// V1.0.02       2023-09-11      DW              Replace 'localhost' with '127.0.0.1' on function '_getConnConfig'. MariaDB connection
//                                               may fail as IPv6 is not activated when 'host' on connection profile is 'localhost'.  
//#################################################################################################################################

"use strict";
const mariadb = require("mariadb");
const wev = require('../lib/webenv_lib.js');


exports.selectCookie = function(option) {
  var result;
  
  if (typeof(option) == 'string') {
    option = wev.allTrim(option.toUpperCase());
  }
  
  switch (option) {
    case 'PDA':
      result = 'COOKIE_PDA';
      break;
      
    case 'MSG':
      result = 'COOKIE_MSG';
      break;  
    
    default:
      result = '';
  }
  
  return result;  
}


function _getConnConfig(cookie) {
  var result;
  
  switch (cookie) {
    case 'COOKIE_PDA':
      result = {
        host: '127.0.0.1',
        user: 'pdadmin',
        password: 'Yt83344Keqpkgw34',
        database: 'pdadb'
      };
      break;      
    
    case 'COOKIE_MSG':
      result = {
        host: '127.0.0.1',
        user: 'msgadmin',
        password: 'cPx634BzAr1338Ux',
        database: 'msgdb'
      };
      break;  
        
    default:
      result = null;
  }
  
  return result;  
}


async function _dbConnect(cookie) {
  var config, conn;

  try {  
    config = _getConnConfig(cookie);
  
    if (config != null) {
      conn = await mariadb.createConnection({
               host: config.host,
               user: config.user,
               password: config.password,
               database: config.database,
               connectTimeout: 5000    
             });
    }
    else {
      throw new Error(`Invalid database profile ${cookie}`);;
    }
  }
  catch (e) {
	  throw e;
	}

  return conn;  
}


exports.dbConnect = async function(cookie) {
  var conn;
  
  try {
    conn = await _dbConnect(cookie);
  }
  catch(e) {
    throw e;
  }
  
  return conn;
}


exports.dbClose = async function(conn) {
  try {
	  if (conn) {
      await conn.close();
    }
  }
  catch (e) {
    throw e;
  }
}


//-- Create a database connection pool --//
exports.createConnectionPool = function(cookie, limit) {
  var config, pool;

  try {
    if (typeof(limit) != 'number' || limit <= 0) {
      limit = 25;
    }

    config = _getConnConfig(cookie);

    if (config != null) {
      pool = mariadb.createPool({
        host: config.host, 
        user: config.user, 
        password: config.password,
        database: config.database,
        connectionLimit: limit,
        connectTimeout: 5000
      });
    }
    else {
      throw new Error(`Invalid connection profile ${cookie}`);
    }
  }
  catch(e) {
    throw e;
  }

  return pool;
} 


//-- Try to obtain a connection from a database pool --//
exports.getPoolConn = async function(pool, cookie) {    
  var conn;
  
  try {
    conn = await pool.getConnection();
  }
  catch(e) {
    //-- Note: If unable to get a connection from the pool, then try to create an individual --//
    //--       connection as the last resort, if 'cookie' is given.                          --//
    if (typeof(cookie) == 'string' && wev.allTrim(cookie) != '') {
      //-- The last resort --// 
      try {
        conn = await _dbConnect(cookie);
      }
      catch(e) {
        throw e;
      }
    }
    else {
      throw e;
    }
  }
  
  return conn;
} 


//-- Release a connection to a database pool --//
exports.releasePoolConn = function(conn) {
  var result = {ok: true, msg: ''};
  
  try {
    if (conn) {
      //-- Note: If the connection is obtained from a database pool, then --//
      //--       'conn.release' is a function. This property is missing   --//
      //--       for individual database connection, and it will return   --//
      //--       'undefined'.                                             --//
      if (typeof(conn.release) == 'function') {
        conn.release();   // release to pool
      }
      else {
        conn.close();     // close a connection 
      }    
    }
  }
  catch(e) {
    result = {ok: false, msg: e.message};
  }
  
  return result;
}


// 2022-04-19: JSON doesn't know how to handle BigInt data type, so that this internal function is 
// created to tackle this issue.
function _toJSON(data) {
  if (data !== undefined) {
    let intCount = 0, repCount = 0;
    
    const json = JSON.stringify(data, (_, v) => {
      if (typeof v === 'bigint') {
        intCount++;
        return `${v}#bigint`;
      }
      return v;
    });
    
    const res = json.replace(/"(-?\d+)#bigint"/g, (_, a) => {
      repCount++;
      return a;
    });
    
    if (repCount > intCount) {
      // You have a string somewhere that looks like "123#bigint";
      throw new Error(`BigInt serialization conflict with a string value.`);
    }
    
    return res;
  }  
}


exports.sqlQuery = async function(conn, sql, param) {
  try {
    var rows = await conn.query(sql, param);
    // Note: rows is an array
    return JSON.stringify(JSON.parse(_toJSON(rows)));   
  }
  catch(e) {
    throw e;
  }
}


exports.sqlExec = async function(conn, sql, param) {
  try {
    var record = await conn.query(sql, param);
    // Possible returned values of 'record' are {fieldCount, affectedRows, insertId, info, serverStatus, warningStatus, changedRows} for data insertion/update.
    // Note: 'record' is not an array.    
    return JSON.stringify(JSON.parse(_toJSON(record)));
  }
  catch(e) {
    throw e;
  }
}


exports.startTransaction = async function(conn) {
  var result = true;
  
  try {
    await conn.beginTransaction();
  }
  catch (err) {
    result = false;
  }
  
  return result;
}


exports.commitTransaction = async function(conn) {
  var result = true;
  
  try {
    await conn.commit();
  }
  catch (err) {
    result = false;
  }
  
  return result;
}


exports.rollbackTransaction = async function(conn) {
  var result = true;
  
  try {
    await conn.rollback();
  }
  catch (err) {
    result = false;
  }
    
  return result;  
}
