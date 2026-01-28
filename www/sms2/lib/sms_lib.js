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
// File name: sms_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2022-04-16      DW              Main function library of secure instant messaging system 2.0. 
// V1.0.01       2022-08-31      DW              Add an additional encryption layer (AES-256) for message sending and receiving.
// V1.0.02       2023-04-05      DW              Adjust size of button images as new button images are used to let users play in
//                                               dark mode.
// V1.0.03       2023-05-27      DW              Clear value of photo caption field as photo is uploaded successfully. 
// V1.0.04       2023-08-08      DW              Add a new function 'consoleLog' to show console message with date and time. 
// V1.0.05       2023-10-13      DW              - Use RSA encryption to protect client generated AES key in login process.
//                                               - Use client generated AES passphase to encrypt and decrypt uploading and downloading 
//                                                 messages sending to and received from the server, instead to use session code 
//                                                 stored on the cookie.
//                                               - Use RSA encryption to protect request-to-join function.
//                                               - Use RSA encryption to protect user creation functions (for all connection modes). 
// V1.0.06       2023-11-22      DW              Increase session AES passphase length from 32 to 128 characters. 
// V1.0.07       2023-11-26      DW              Incrase default RSA key length from 2048 to 4096 bits. 
// V1.0.08       2023-11-30      DW              - Use a constant "_key_len" to define AES passphase length within the module.
//                                               - Ensure AES passphase exist before send out message. If AES passphase is lost, force
//                                                 logout the user.   
// V1.0.09       2023-12-01      DW              If local AES passphase is lost, force logout user instead generate a new passphase
//                                               and upload to the server.  
// V1.0.10       2024-03-04      DW              Replace " and ' characters by “ and ‘ respectively on the quoted reply message, in
//                                               order to avoid syntax error on javascipt function.
// V1.0.11       2024-04-12      DW              Clear session AES key from RAM after used in client side for security measure. 
// V2.0.12       2024-03-21      DW              Use a post quantum computing era cryptographic method 'Crystals Kyber' to protect the 
//                                               login process.
// V1.0.13       2024-04-16      DW              Use 'Crystals Kyber' method to protect processes "request to join" and "user creation".
// V1.0.14       2024-06-13      DW              Swiping right in a message group will go to previous page, i.e. return to the message 
//                                               group(s) landing page.
// V1.0.15       2024-11-10      DW              Fix a bug on function 'sendFile' by loading session AES key as it is called and clear
//                                               the session key after used. 
// V1.0.16       2025-03-13      DW              Amend function 'showLoginPage' by compress JavaScript code block.
// V1.0.17       2025-03-18      DW              Compress JavaScript code block on functions 'showMessagePage', 'showDoSMSpage' and
//                                               'printRequestToJoinForm'. 
// V1.0.18       2025-05-30      DW              Use RSA encryption verification to check Crystals Kyber public key. It is the temporary
//                                               way to protect Kyber public key before Kyber Dilithium is implemented later. It is applied
//                                               on user login and request to join functions.
// V1.0.19       2025-06-11      DW              Disable the feature for swiping right in a message group will go to previous page, because
//                                               it is very annoying, and let message selection opeation on group page nearly impossible.
// V1.0.20       2025-06-24      DW              Include 'user_id' into session validation checking.
// V1.0.21       2025-08-19      DW              Fix a bug on javascript function 'sendSound' of Node.js function '_printMessagesDoSMSpage'. 
//                                               The error is caused by forgetting to load secure key before send out audio file.  
// V1.0.22       2025-12-04      DW              Add function 'isSessionValidEx'. It is the key part of a rolling key mechanism to prevent
//                                               and detect MITM attacking.
//#################################################################################################################################

"use strict";
//const fs = require('fs');
const unicodeSubstring = require('unicode-substring');
const unicodeStrLen = require('unicode-length');
const SimpleHashTable = require('simple-hashtable');
const dbs = require('../lib/db_lib.js');
const wev = require('../lib/webenv_lib.js');
const cipher = require('../lib/cipher_lib.js');
const telecom = require('../lib/telecom_lib.js');
const msglib = require('../lib/msg_lib.js');
//-- Define constants --//
const _decoy_company_name = (wev.getGlobalValue('COMP_NAME') != '')? wev.getGlobalValue('COMP_NAME') : "PDA Tools Corp.";
const _key_len = wev.getGlobalValue('AES_KEY_LEN');                   // AES-256 passphase length


async function _logSystemError(conn, user_id, detail_msg, brief_msg, browser_signature) {
  var sqlcmd, param, data, result;
  
  try {
    user_id = (typeof(user_id) === 'number' && !Number.isNaN(user_id))? parseInt(user_id, 10) : 0;
    detail_msg = wev.allTrim(detail_msg);
    brief_msg = wev.allTrim(brief_msg);
    browser_signature = (typeof(browser_signature) != "string")? '' :  wev.allTrim(browser_signature);
    
    sqlcmd = `INSERT INTO sys_error_log ` +
             `(user_id, brief_err_msg, detail_err_msg, log_time, browser_signature) ` +
             `VALUES ` +
             `(?, ?, ?, CURRENT_TIMESTAMP(), ?)`;
             
    param = [user_id, brief_msg, detail_msg, browser_signature];      
    data = await dbs.sqlExec(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (parseInt(data.affectedRows, 10) == 0) {
      var message = `No record is added to the system error log, please check for it.\n` +
                    `SQL: ` + sqlcmd + `\n` +
                    `user_id: ` + user_id.toString() + `\n` +
                    `brief_msg: ` + brief_msg + `\n` +
                    `detail_msg: ` + detail_msg + `\n` +
                    `browser_signature: ` + browser_signature; 
                     
      _consoleLog(message);
      result = false;
    }
    else {
      result = true;
    }        
  }
  catch(e) {
    _consoleLog(e.message);
    result = false;
  }
  
  return result;  
}


exports.logSystemError = async function(conn, user_id, detail_msg, brief_msg, browser_signature) {
  var open_conn, result;
  
  open_conn = (typeof(conn) == 'undefined' || conn == null)? true : false;
  
  try {
    if (open_conn) {
      conn = await dbs.dbConnect(dbs.selectCookie('MSG'));
    }
    
    result = _logSystemError(conn, user_id, detail_msg, brief_msg, browser_signature);
  }
  catch(e) {
    result = false;
  }
  finally {
    if (open_conn) {
      await dbs.dbClose(conn);
    }
  }
  
  return result;
}


exports.logSystemEvent = async function(msg_pool, user_id, detail_msg, brief_msg, browser_signature) {
  var conn, result;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    result = _logSystemError(conn, user_id, detail_msg, brief_msg, browser_signature);
  }
  catch(e) {
    result = false;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


function _consoleLog(message) {
  if (typeof(message) == "string") {
    console.log(wev.sayCurrentTime() + " " + message);
  }
  else {
    console.log(wev.sayCurrentTime());
    console.log(message);
  }  
}

exports.consoleLog = function(message) {
  _consoleLog(message);
}


async function _getDecoyCompanyName(conn) {
  var result;
  
  try {
    result = await wev.getSysSettingValue(conn, 'decoy_company_name');
    
    if (result == '') {
      result = _decoy_company_name;        // '_decoy_company_name' is a constant.
    }
  } 
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _getRsaPublicKey(conn, days) {
  let result = {id: null, public: null, algorithm: null};
  
  try {
    let key_obj = await cipher.getKeyPairRSA(conn, null, days);    		
		result = {id: key_obj.key_id, public: key_obj.public, algorithm: key_obj.algorithm};
	}
	catch(e) {
		_consoleLog(e.message);
	}
  
  return result;	
}


async function _kyberKeyExist(conn, kyber_id) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM kyber_keypair ` +
          `  WHERE key_id = ?`;
          
    param = [kyber_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (parseInt(data[0].cnt) > 0)? true : false; 
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _saveKyberKeyPair(conn, kyber_keypair) {
  let sql, param, kyber_id, stop_run, cnt;
  
  try {
    stop_run = false;
    cnt = 0;
    
    while (!stop_run) {
      kyber_id = cipher.generateTrueRandomStr("A", 64);
      
      if (!await _kyberKeyExist(conn, kyber_id)) {
        stop_run = true;
      }
      else {
        cnt++;
        
        if (cnt >= 3) {
          // The last resort. The length of 'timestr' is 14. //
          let currentdate = new Date();
          let timestr = currentdate.getFullYear().toString() 
              + ((currentdate.getMonth()+1 < 10)? '0' + (currentdate.getMonth()+1) : (currentdate.getMonth()+1)) 
              + currentdate.getDate().toString() 
              + currentdate.getHours().toString() 
              + currentdate.getMinutes().toString()
              + currentdate.getSeconds().toString();
              
          kyber_id = cipher.generateTrueRandomStr("A", 50) + timestr;
          stop_run = true;
        } 
      }
    }
            
    sql = `INSERT INTO kyber_keypair ` +
          `(key_id, public_key, private_key, add_datetime) ` + 
          `VALUES ` +
          `(?, ?, ?, CURRENT_TIMESTAMP())`;
              
    param = [kyber_id, kyber_keypair.pkey, kyber_keypair.skey];              
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
  
  return kyber_id;
}


async function _getKyberKeyPoolSize(conn, days) {
  let result, sql, param, data;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM kyber_keypair ` +
          `  WHERE DATEDIFF(NOW(), add_datetime) <= ?`;
          
    param = [days];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = parseInt(data[0].cnt, 10);          
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _pickKyberKeyInRandom(conn, days) {
  let result, sql, param, data, rnd_char;
  
  try {
    rnd_char = cipher.generateTrueRandomStr("A", 1);
    
    sql = `SELECT key_id, public_key ` +
          `  FROM kyber_keypair ` +
          `  WHERE key_id LIKE ? ` +
          `    AND DATEDIFF(NOW(), add_datetime) <= ?`;
          
    param = ['%'+rnd_char+'%', days];      
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      let idx = (data.length == 1)? 0 : Math.floor(Math.random() * data.length);
      result = {key_id: data[idx].key_id, pkey: data[idx].public_key};
    }
    else {
      result = {key_id: '', pkey: ''};
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}
 

async function _getKyberKeyData(conn) {
  let result, days, size, stop_run, cnt, kyber_obj, kyber_keypair, kyber_id, kyber_pkey;

  size = 50;
  days = 5;
  
  try {    
    if (await _getKyberKeyPoolSize(conn, days) < size) {
      kyber_keypair = await cipher.generateKyberKeyPairBase64();
      kyber_id = await _saveKyberKeyPair(conn, kyber_keypair);          
      result = {key_id: kyber_id, pkey: kyber_keypair.pkey};            
    }
    else {
      stop_run = false;
      cnt = 0;
      
      while (!stop_run) {
        kyber_obj = await _pickKyberKeyInRandom(conn, days);
        
        if (kyber_obj.key_id != '') {
          result = {key_id: kyber_obj.key_id, pkey: kyber_obj.pkey};
          stop_run = true;
        }
        else {
          cnt++;
          
          if (cnt >= 3) {
            kyber_keypair = await cipher.generateKyberKeyPairBase64();
            kyber_id = await _saveKyberKeyPair(conn, kyber_keypair);          
            result = {key_id: kyber_id, pkey: kyber_keypair.pkey};            
            stop_run = true;            
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


exports.showLoginPage = async function(msg_pool) {
  var conn, html, company_name, join_us, connect_mode, key_id, rsa_keys, public_pem, public_pem_b64, algorithm, algorithm_b64, public_sha256sum;
  
  html = '';
  company_name = '';
  join_us = '';
  connect_mode = 0;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG')); 
    
    company_name = await _getDecoyCompanyName(conn);
    connect_mode = parseInt(await wev.getSysSettingValue(conn, 'connection_mode'), 10);    

    if (connect_mode == 0 || connect_mode == 2) {
      join_us = `<a href='/request-to-join' class='ui-btn ui-btn-inline' data-ajax='false'>Join Us</a>`;
    }
    else {
      join_us = ``;
    }

    // Step 1: Obtain an existing RSA public key or generate a new RSA key pair. //
    // Note: key_obj.public, key_obj.private and key_obj.algorithm are in base64 //
    //       string format. Moreover, key_obj.public and key_obj.private are pem //
    //       of public key and private key respectively.                         //		
		let key_obj = await _getRsaPublicKey(conn, 5);
				
		if (key_obj.id == null) {
			algorithm = {
				// Name of the algorithm
				name: 'RSA-OAEP',
				// Length of the RSA key (modulus), in bits
				modulusLength: 4096,
				// Public exponent: always use this static value (equivalent to 65537)
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				// Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
				hash: 'SHA-256'
		  };
		  
		  rsa_keys = await cipher.generateRsaKeyPair(algorithm, true);
		  
		  // Note: The public key, private keys and algorithm object must be converted to base64 string before save to the database. //                                   // 
		  let rsa_key_strs = {public: '', private: '', algorithm: ''};
		  let pub_key_pem = await cipher.pemFromKey('public', rsa_keys.public);
		  let pri_key_pem = await cipher.pemFromKey('private', rsa_keys.private);
		  rsa_key_strs.public = cipher.convertObjectToBase64Str(pub_key_pem);
		  rsa_key_strs.private = cipher.convertObjectToBase64Str(pri_key_pem);
		  rsa_key_strs.algorithm = cipher.convertObjectToBase64Str(rsa_keys.algorithm);
		  
		  key_id = await cipher.addNewRsaKeyPair(conn, rsa_key_strs);
		  public_pem_b64 = rsa_key_strs.public;		  
		  algorithm_b64 = rsa_key_strs.algorithm;
		}
		else {
			key_id = key_obj.id;
			public_pem_b64 = key_obj.public;       // In base64 format
			algorithm_b64 = key_obj.algorithm;     // In base64 format
		}
		
		// Step 2: Generate a base64 encoded SHA256SUM of the public key in base64 format. i.e. It is the signature of the //
		//         public key.                                                                                             //
	  public_sha256sum = await cipher.digestData("SHA-256", public_pem_b64);
	  
	  // Step 3: Generate another RSA key pair for the public key signature verification. Encrypt "public_sha256sum" by //
	  //         the signed RSA private key (use for security verification later)                                       //
	  let sign_algorithm = {
			name: 'RSA-PSS',
			saltLength: 32,
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: 'SHA-256'
		};
	  
	  // Note: Since the private key of the signed key pair doesn't need to be converted into pem format, so that it can //
	  //       be set as non extractable to maintain the highest security level.                                         //
	  let sign_keypair = await cipher.generateSignKeyPair(sign_algorithm, false);
	  let sign_key = sign_keypair.private;
	  let verify_key = sign_keypair.public;
	  
	  let pub_pem_signature = await cipher.createSignature(sign_algorithm, sign_key, cipher.base64StringToArrayBuffer(public_sha256sum));
	  let pub_pem_signature_b64 = cipher.arrayBufferToBase64String(pub_pem_signature);
	  let verify_key_pem = await cipher.pemFromKey('public', verify_key);
	  let sign_algorithm_b64 = cipher.convertObjectToBase64Str(sign_algorithm);
		
		// Step 4: Convert the verification key pem strings into base64 format. Note: Key pem strings can't embed into 'html' directly or //
		//         they will cause syntax error on javascript due to the line-break characters.                                           //
		let verify_key_pem_b64 = cipher.convertObjectToBase64Str(verify_key_pem);
    
    // Step 5: Generate a Crystals Kyber key pair (it will be used to protect the RSA encrypted session key).  //
    let kyber_obj = await _getKyberKeyData(conn);
    let kyber_id = kyber_obj.key_id;
    let kyber_pkey_b64 = kyber_obj.pkey;  
    
    // Step 6: Create signature for the Crystals Kyber public key and sign it with the same RSA signing key pair. //
    //         Note: It will be used Crystals Dilithium later.                                                    //  
    let kyber_pkey_signature = await cipher.digestData("SHA-256", kyber_pkey_b64);
    let kyber_pem_signature = await cipher.createSignature(sign_algorithm, sign_key, cipher.base64StringToArrayBuffer(kyber_pkey_signature));
    let kyber_pem_signature_b64 = cipher.arrayBufferToBase64String(kyber_pem_signature);
    
    let kyber_module = cipher.getKyberClientModule();
    
    // Compress JavaScript code block //
    let js = `
    var aes_algorithm = "AES-GCM";
    var key = "";                 // AES-256 key generated at client side 
    var rolling_key = "";         // A rolling key generated at client side (it will be changed everytime it makes a new request to back-end server)     
    var algorithm_b64 = "${algorithm_b64}";    // The algorithm used by the RSA key pair generation
    var algorithm;
    var public_pem_b64 = "${public_pem_b64}";
    var public_pem;
    var public_key;               // The RSA public key imported from public_pem (from public_pem_b64) 
    var pub_pem_signature_b64 = "${pub_pem_signature_b64}";			  
    var pub_pem_signature;        // The sha256sum signature (encrypted) of the public key pem (i.e. public_pem)
    var kyber_pkey_b64 = "${kyber_pkey_b64}";     // The Crystals Kyber public key
    var kyber_pem_signature_b64 = "${kyber_pem_signature_b64}";  // The signature of the Crystals Kyber public key (base64 format)
    var kyber_pem_signature;                                     // The signature of the Crystals Kyber public key (binary format)
    var cs_kyber_pkey_signature;                                 // Client side generated SHA256SUM of the received Crystals Kyber public key pem
    var sign_algorithm_b64 = "${sign_algorithm_b64}";       // The algorithm used by the RSA public key signature verification 
    var sign_algorithm;            
    var verify_key_pem_b64 = "${verify_key_pem_b64}";
    var verify_key_pem;
    var verify_key;               // The key used to verify the RSA public key signature
    var cs_public_sha256sum;      // Client side generated SHA256SUM of the received public key pem (i.e. public_pem)                       
    var is_valid = false;         // true: RSA public key is valid, false otherwise.
    var is_ck_valid = false;      // true: Crystals Kyber public key is valid, false otherwise.
    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
  
    $(document).ready(function() {
      $('#username').focus();
    });

    async function prepareAESkey() {
      try {
        key = generateTrueRandomStr('A', ${_key_len});      // Defined on crypto-lib.js
        rolling_key = generateTrueRandomStr('A', getRandomInt(32, 64));      // Defined on crypto-lib.js
        
        algorithm = convertBase64StrToObject(algorithm_b64);
        public_pem = convertObjectToBase64Str(public_pem_b64);
        public_key = await importKeyFromPem('public', public_pem, algorithm, true, ['encrypt']);    // Defined on crypto-lib.js
                    
        sign_algorithm = convertBase64StrToObject(sign_algorithm_b64);
        verify_key_pem = convertObjectToBase64Str(verify_key_pem_b64);
        verify_key = await importKeyFromPem('public', verify_key_pem, sign_algorithm, true, ['verify']);    // Defined on crypto-lib.js
        
        // Verify RSA public key // 
        pub_pem_signature = base64StringToArrayBuffer(pub_pem_signature_b64);
        cs_public_sha256sum = await digestData('SHA-256', public_pem_b64);                      // In base64 format
        is_valid = await verifySignature(sign_algorithm, verify_key, pub_pem_signature, base64StringToArrayBuffer(cs_public_sha256sum));
        
        // Verify Crystals Kyber public key //
        kyber_pem_signature = base64StringToArrayBuffer(kyber_pem_signature_b64);
        cs_kyber_pkey_signature = await digestData('SHA-256', kyber_pkey_b64);
        is_ck_valid = await verifySignature(sign_algorithm, verify_key, kyber_pem_signature, base64StringToArrayBuffer(cs_kyber_pkey_signature));
        
        if (!is_valid) {
          throw new Error("Warning: The received RSA public key is invalid, login process cannot proceed! You may be under Man-In-The-Middle attack!");
        }
        
        if (!is_ck_valid) {
          throw new Error("Warning: The received Crystals Kyber public key is invalid, login process cannot proceed! You may be under Man-In-The-Middle attack!");
        }
      }
      catch(e) {
        throw e;
      }
      
      return key;				
    }
    
    async function goLogin() {
      try {
        key = await prepareAESkey();				  
  
        let enc_user = await aesEncryptJSON(aes_algorithm, key, $('#username').val());
        let enc_pass = await aesEncryptJSON(aes_algorithm, key, $('#password').val()); 
        let enc_roll = await aesEncryptJSON(aes_algorithm, key, rolling_key);

        
        let enc_key = await rsaEncrypt(algorithm, public_key, key);                       // Defined on crypto-lib.js
        // Step 1: Convert encrypted key from ArrayBuffer to Uint8Array //
        let enc_key_u8a = new Uint8Array(enc_key);
        // Step 2: Stringify the Uint8Array to a JSON format string //
        let enc_key_json = JSON.stringify(enc_key_u8a);
        // Step 3: Use the secret key of the Kyber object to encrypt the RSA encrypted session key by AES-256 encryption. //
        //         i.e. Use AES-256 with Kyber secret key as encryption key to encrypt the RSA encrypted session key once //
        //         more.                                                                                                  //
        let secret = await generateSharedCipherKey(kyber_pkey_b64);
        let ct = secret.ct;
        let skey = base64Decode(secret.sk);
        
        let enc_obj = await aesEncryptWithKeyJSON(aes_algorithm, skey, enc_key_json);
        let keycode_iv = enc_obj.iv;
        let keycode = enc_obj.encrypted;
                              
        // Store the generated AES key on browser local storage //
        if (is_iOS) {
          // iOS behavior is different from other platforms, so that it needs to put cross pages data to cookie as work-around. //
          Cookies.set("aes_key", key, {expires: 1});              // Defined on js.cookie.min.js    
          Cookies.set("rolling_key", rolling_key, {expires: 1});          
        }
        else {
          setLocalStoredItem("aes_key", key);                     // Defined on common_lib.js
          setLocalStoredItem("rolling_key", rolling_key);
        }
        
        // Clear the Kyber secret key and session AES key in RAM after used (precaution only) //
        skey = null;
        secret.sk = null;
        secret = null;
        aes_key = null;
        rolling_key = null;
        
        $('#kyber_ct').val(ct);  
        $('#keycode_iv').val(keycode_iv);                            
        $('#keycode').val(keycode); 															
        $('#cs_public_sha256sum').val(cs_public_sha256sum);	      // Send back to server for verification
        $('#aes_algorithm').val(aes_algorithm);
        $('#e_user').val(enc_user.encrypted);
        $('#iv_user').val(enc_user.iv);
        $('#e_pass').val(enc_pass.encrypted);
        $('#iv_pass').val(enc_pass.iv);
        $('#e_roll').val(enc_roll.encrypted);
        $('#iv_roll').val(enc_roll.iv);                        
        $('#username').val('');
        $('#password').val('');																																																														 																	
        $('#oper_mode').val('S');
        $('#frmLogin').submit();
      }
      catch(e) {
        console.log(e);				  							  
        alert(e);
      } 
    }`; 
    
    js = await wev.minifyJS(js);
    
    //-- Note: "data-ajax='false'" is very important to let all jQuery mobile forms to work correctly --//
    html = `
    <!doctype html>
    <html>
    <head>
      <title>Login</title>
      <meta name='viewport' content='width=device-width, initial-scale=1.0'>
      <meta http-equiv='Content-Type' content='text/html; charset=utf-8'> 

      <link rel='stylesheet' href='/js/jquery.mobile-1.4.5.min.css'>
      <link rel='shortcut icon' href='/favicon.ico'>
      <script src='/js/jquery.min.js'></script>
      <script src='/js/jquery.mobile-1.4.5.min.js'></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src='/js/crypto-lib.js'></script>               
      <script src='/js/common_lib.js'></script>
   
      <!-- Async function generateSharedCipherKey is defined here //-->    
      ${kyber_module}
                  
      <script>
        ${js}
      </script>
    </head>

    <body>
      <center>
      <form id='frmLogin' name='frmLogin' action='/go-login' method='post' data-ajax='false'>
      <input type=hidden id='oper_mode' name='oper_mode' value=''>   
      <input type=hidden id='keycode_iv' name='keycode_iv' value=''>         
      <input type=hidden id='keycode' name='keycode' value=''>
      <input type=hidden id='kyber_id' name='kyber_id' value='${kyber_id}'>
      <input type=hidden id='kyber_ct' name='kyber_ct' value=''>
      <input type=hidden id='key_id' name='key_id' value='${key_id}'>
      <input type=hidden id='cs_public_sha256sum' name='cs_public_sha256sum' value=''>    
      <input type=hidden id='aes_algorithm' name='aes_algorithm' value=''>        
      <input type=hidden id='e_user' name='e_user' value=''>
      <input type=hidden id='iv_user' name='iv_user' value=''>
      <input type=hidden id='e_pass' name='e_pass' value=''>
      <input type=hidden id='iv_pass' name='iv_pass' value=''>
      <input type=hidden id='e_roll' name='e_roll' value=''>
      <input type=hidden id='iv_roll' name='iv_roll' value=''>                  
      

      <div data-role='page'>
        <div data-role='header' style='overflow:hidden;' data-position='fixed' data-ajax='false'>
          <h1>Login</h1>
        </div>

        <div data-role='main' class='ui-content'>
          <table width=85% height=100% cellspacing=0 cellpadding=0>
          <thead></thead>
          <tbody>
            <tr>
              <td align=center valign=center>
                <br>
                <br>
                <br>
                <div style='float:center; background-color:#A9A9A9; padding:2px; width:100%'>
                  <div style='background-color:lightblue; padding:10;'>
                    <table width='95%' cellspacing=0 cellpadding=2>
                    <thead></thead>
                    <tbody>
                      <tr><td colspan=2 align=center><b>${company_name}</b></td></tr>
                      
                      <tr><td colspan=2>&nbsp;</td></tr>
                
                      <tr>
                        <td><b>Username:</b></td>
                        <td><input type=text id='username' name='username' maxlength=30 value='' autocomplete='off'></td>
                      </tr>

                      <tr>
                        <td><b>Password:</b></td>
                        <td><input type=password id='password' name='password' maxlength=255 value='' autocomplete='off'></td>
                      </tr>

                      <tr><td colspan=2>&nbsp;</td></tr>

                      <tr>
                        <td align=center colspan=2>
                          <button class='ui-btn ui-btn-inline' onClick='goLogin();'>Login</button>
                        </td>
                      </tr>

                      <tr><td colspan=2>&nbsp;</td></tr>
                    </tbody>
                    </table>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>  
          </table>
        </div>

        <div data-role='footer' data-position='fixed' data-tap-toggle='false'>
          <table width='100%' cellspacing=0 cellpadding=0>
          <thead></thead>
          <tbody>
            <tr>
              <td align=center>${join_us}</td>
            </tr>
          </tbody>
          </table>
        </div>
      </div>
      </form>
      </center>
    </body>
    </html>`; 
  } 
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
    
  return html;  
}


exports.checkClientSidePubKeySha256Sum = async function(msg_pool, key_id, cs_public_sha256sum) {
	let conn, pub_pem_b64, sha256sum, is_valid;
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
		
		let key_obj = await cipher.getKeyObjectRSA(conn, key_id);
		pub_pem_b64 = key_obj.public;		
		sha256sum = await cipher.digestData("SHA-256", pub_pem_b64);
				
		is_valid = (sha256sum == cs_public_sha256sum)? true : false; 		
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return is_valid;
}


async function _getKyberSecretKey(conn, kyber_id) {
  let skey, sql, param, data;
  
  try {
    sql = `SELECT private_key ` +
          `  FROM kyber_keypair ` +
          `  WHERE key_id = ?`;
          
    param = [kyber_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      skey = data[0].private_key;
    }
    else {
      throw new Error("Kyber key record is lost!"); 
    }      
  }
  catch(e) {
    throw e;
  }
  
  return skey;
}


exports.extractClientAESkey = async function(msg_pool, kyber_id, kyber_ct, aes_algorithm, key_id, keycode_iv, keycode) {
  let conn, private_pem_b64, private_pem, private_key, algorithm_b64, algorithm;
  let enc_keycode_obj, enc_keycode, aes_key, skey, ct, shared_key, keycode_json;
  
  try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));

    // Step 1: Get the Kyber shared key (it is used as key to encrypte 'keycode' by AES-256, and 'keycode' is encrypted //
    //         by RSA before.)                                                                                          //
    skey = wev.base64Decode(await _getKyberSecretKey(conn, kyber_id));
    ct = wev.base64Decode(kyber_ct);
    shared_key = await cipher.kyberDecap(ct, skey);  
    
    // Step 2: AES decrypt to obtain the RSA encrypted session key (which in JSON string format) //
    keycode_json = await cipher.aesDecryptWithKeyJSON(aes_algorithm, shared_key, keycode_iv, keycode); 
     
		// Step 3: RSA decryption to obtain the session key generated from client side                                   //
		// Note: Since 'keycode_json' is in JSON string format, we need to convert it into an object, then retrieve back //
		//       encrypted AES key data into a Uint8Array.                                                               //
		enc_keycode_obj = JSON.parse(keycode_json);
		enc_keycode = new Uint8Array(Object.keys(enc_keycode_obj).length);
		
		let idx = 0;
		for (const value in enc_keycode_obj) {
			enc_keycode[idx] = enc_keycode_obj[value];
			idx++;
		}
		
		let rsa_key_obj = await cipher.getPrivateKeyRSA(conn, key_id);
		private_pem_b64 = rsa_key_obj.private;
		algorithm_b64 = rsa_key_obj.algorithm;
		
		algorithm = cipher.convertBase64StrToObject(algorithm_b64);
		private_pem = cipher.convertBase64StrToObject(private_pem_b64);		
		private_key = await cipher.importKeyFromPem('private', private_pem, algorithm, false, ['decrypt']);
		
		aes_key = await cipher.rsaDecrypt(algorithm, private_key, enc_keycode);
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
  
  return aes_key;	
}


async function _getCurrentTimestamp(conn) {
  var sqlcmd, data, result;
  
  try {
    sqlcmd = `SELECT DATE_FORMAT(CURRENT_TIMESTAMP(), '%Y-%m-%d %H:%i:%s') AS time`;
    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);
    result = wev.allTrim(data[0].time);        
  }
  catch(e) {
    _consoleLog(e.message);
    result = '';
  }
  
  return result;  
}


async function _writeToLoginQueue(conn, algorithm, token_iv, token, add_time, seed, user_id, aes_key, rolling_key) {
  let sqlcmd, param, data, result;
    
  result = {ok: true, msg: ''};

  try {  
    sqlcmd = `INSERT INTO login_token_queue ` +
             `(algorithm, token_iv, token, token_addtime, token_seed, aes_key, rolling_key, status, user_id) ` +
             `VALUES ` +
             `(?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    param = [algorithm, token_iv, token, add_time, seed, aes_key, rolling_key, 'A', user_id];
    
    data = await dbs.sqlExec(conn, sqlcmd, param);
  }
  catch(e) {
    result = {ok: false, msg: e.message};
    _consoleLog(e.message);
  }
  
  return result;
}


async function _sendLoginMail(conn, user_id, to_mail, token, add_time) {
  let result, site_dns, email_worker, from_mail, from_user, from_pass, smtp_server, port, subject, body, login_url;
  
  try {  
    site_dns = await wev.getSiteDNS(conn, 'M');            
  
    if (site_dns != '') {
      subject = 'Your subscribed news list';
      login_url = site_dns + '/read_news?tk=' + token;  
      body = 'Please click the link below to access the latest news: \n\n' + login_url + '\n\nTimestamp: ' + add_time + '\n\n';
      email_worker = await telecom.getMailWorker(conn);  
      from_mail = email_worker.email;
    
      if (from_mail != null) {
        from_user = email_worker.m_user;
        from_pass = email_worker.m_pass;
        smtp_server = email_worker.smtp_server;
        port = parseInt(email_worker.port, 10);
            
        await telecom.sendEmail(smtp_server, port, from_mail, to_mail, from_user, from_pass, subject, body);        
        result = {ok: true, msg: ''};
      }
      else {
        result = {ok: false, msg: 'No email worker is defined, unable to send login email.'};
      }     
    }
    else {
      result = {ok: false, msg: 'Unable to get message site URL'};
    }
  }
  catch(e) {
    _consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;  
}


async function _sendMessageAccessLinkMail(conn, user_id, email, aes_key, rolling_key) {
  let login_status, message, algorithm, plaintext, token, token_iv, key, add_time, seed, result;
  
  login_status = 1;
  message = '';
  algorithm = 'AES-GCM';
  plaintext = '';
  token = '';
  result = {login_status: login_status, message: message}; 
  
  try {  
    add_time = await _getCurrentTimestamp(conn);            
    //seed = wev.generateRandomStr('A', 32);
    seed = cipher.generateTrueRandomStr('A', 32);               
    key = wev.allTrim(seed);
    
    plaintext = 'user_id=' + wev.allTrim(user_id.toString()) + '&seed=' + seed;
    let enc_obj = await cipher.aesEncryptBase64(algorithm, key, plaintext);
    // Note: token_iv and token are in base64 format //
    token_iv = enc_obj.iv;               
    token = enc_obj.encrypted;  

		if (token != '') {    
			//-- Keep in mind that the encrypted token is escaped, therefore, it must be unescaped the token before using. --//
			//-- Note: Value of 'token' contains no space character, but may contains '+' character(s). However, the token --//
			//--       contained '+' characters passes as parameter to a web page, Express.js will follow standard to      --//
			//--       unescape all '+' character(s) to space character(s) automatically. Then, if we escape the already   --//
			//--       unescaped token again, those space character(s) will become '%20'. Therefore, we must replace all   --//
			//--       '%20' phases on the escaped token to '+' character(s) before perform any operation.                 --//        
			token = escape(token);

			let this_result = await _writeToLoginQueue(conn, algorithm, token_iv, token, add_time, seed, user_id, aes_key, rolling_key);
			let ok = this_result.ok;
			let msg = this_result.msg;
		
			if (ok) {
				this_result = await _sendLoginMail(conn, user_id, email, token, add_time);
				ok = this_result.ok;
				msg = this_result.msg;
			
				if (!ok) {
					await _logSystemError(conn, user_id, msg, 'Unable to send login email');
					message = 'Unable to take you into authentication process (code #3), please try again later.';
					login_status = 0;     
					result = {login_status: login_status, message: message};
					_consoleLog(msg);                           
				}
			}
			else {
				await _logSystemError(conn, user_id, msg, 'Unable to save login queue record');
				message = 'Unable to take you into authentication process (code #2), please try again later.';
				login_status = 0;
				result = {login_status: login_status, message: message};
				_consoleLog(msg);              
			}
		}
		else {
			message = 'Unable to take you into authentication process (code #1), please try again later.';
			login_status = 0;      
			result = {login_status: login_status, message: message};
		}    
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


async function _buildLoginLink(conn, token) {
  var ok, msg, site_dns, login_url, result;
  
  ok = true;
  msg = '';
  login_url = '/';
  
  try {  
    site_dns = await wev.getSiteDNS(conn, 'M');           
  
    if (site_dns != '') {
      login_url = site_dns + '/read_news?tk=' + token;
    }
    else {
      msg = 'Unable to get message site URL';
      ok = false;    
    }  
  }
  catch(e) {
    msg = e.message;
    ok = false;
  }
  
  result = {ok: ok, msg: msg, login_url: login_url};
  
  return result;
}


async function _buildMessageAccessLink(conn, user_id, aes_key, rolling_key) {
  var message, algorithm, plaintext, token_iv, token, key, add_time, seed, login_url, result;
  
  message = '';
  algorithm = 'AES-GCM';
  plaintext = '';
  token_iv = '';
  token = '';
  login_url = '/';
  result = {login_status: 1, message: '', redirect_url: '/'};
  
  try {
    add_time = await _getCurrentTimestamp(conn);            
    seed = cipher.generateTrueRandomStr('A', 32);             
    key = wev.allTrim(seed);
    
    plaintext = 'user_id=' + user_id + '&seed=' + seed;
    let enc_obj = await cipher.aesEncryptBase64(algorithm, key, plaintext);
    // Note: token_iv and token are in base64 format //
    token_iv = enc_obj.iv;               
    token = enc_obj.encrypted;  

		if (token != '') {
			//-- Keep in mind that the encrypted token is escaped, therefore, it must be unescaped the token before using. --//
			//-- Note: Value of 'token' contains no space character, but may contains '+' character(s). However, the token --//
			//--       contained '+' characters passes as parameter to a web page, Express.js will follow standard to      --//
			//--       unescape all '+' character(s) to space character(s) automatically. Then, if we escape the already   --//
			//--       unescaped token again, those space character(s) will become '%20'. Therefore, we must replace all   --//
			//--       '%20' phases on the escaped token to '+' character(s) before perform any operation.                 --//  
			token = escape(token);

			let this_result = await _writeToLoginQueue(conn, algorithm, token_iv, token, add_time, seed, user_id, aes_key, rolling_key);
			let ok = this_result.ok;
			let msg = this_result.msg;

			if (ok) {
				this_result = await _buildLoginLink(conn, token);
				ok = this_result.ok;
				msg = this_result.msg;
				login_url = this_result.login_url;
				
				if (ok) {
					result = {login_status: 1, message: '', redirect_url: login_url};
				}
				else {
					await _logSystemError(conn, user_id, msg, 'Unable to build login link');
					message = 'Unable to take you into authentication process (code #4), please try again later.';
					result = {login_status: 0, message: message, redirect_url: '/'};            
				}
			}
			else {
				await _logSystemError(conn, user_id, msg, 'Unable to save login queue record');
				message = 'Unable to take you into authentication process (code #2), please try again later.';
				result = {login_status: 0, message: message, redirect_url: '/'};
			}                
		}
		else {
			message = 'Unable to take you into authentication process (code #1), please try again later.';
			result = {login_status: 0, message: message, redirect_url: '/'};            
		}
  }
  catch(e) {
    await _logSystemError(conn, user_id, e.message, 'Unexpected error: _buildMessageAccessLink');
    message = "Unable to take you into authentication process (code #0), please try again later.";
    result = {login_status: 0, message: message, redirect_url: '/'};    
  }
  
  return result;  
}


async function _beCracked(conn, user_id) {
  var sqlcmd, param, data, result;
 
  try {
    user_id = parseInt(user_id, 10);
 
    sqlcmd = `SELECT cracked ` +
             `  FROM user_list ` +
             `  WHERE user_id = ?`;
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    result = parseInt(data[0].cracked, 10);  
  }
  catch(e) {
    _consoleLog(e.message);
    result = 0;
  }
  
  return result;
  
}


async function _informAdminUnhappyUserIsCracked(conn, user) {
  var sqlcmd, data, subject, body, from_mail, from_user, from_pass, smtp_server, port, cracked_user; 
  var admins = [];
  
  try {
    sqlcmd = `SELECT user_name, user_alias, email ` +
             `  FROM user_list ` +
             `  WHERE user_role = 2 ` +
             `  AND status = 'A'`; 
    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      var name = data[i].user_name;
      var alias = data[i].user_alias;
      var email = data[i].email;
      var record = {name: name, alias: alias, email: email};
      admins.push(record);
    }

    if (admins.length > 0) {
      var worker = await telecom.getMailWorker(conn);
      from_mail = worker.email;
      from_user = worker.m_user;
      from_pass = worker.m_pass; 
      smtp_server = worker.smtp_server; 
      port = worker.port;
      subject = 'Cracking News';
      
      for (var i = 0; i < admins.length; i++) {
        var this_admin = (wev.allTrim(admins[i].alias) != '')? admins[i].alias : admins[i].name;
        var this_email = admins[i].email;
        
        body = `Hi ` + this_admin + `, \n\n` +
               `Please note that ` + user + ` has been cracked. Be careful. \n\n` +
               `Best regards, \n` +
               `Information Team.\n`;
               
        await telecom.sendEmail(smtp_server, port, from_mail, this_email, from_user, from_pass, subject, body);
      }
    } 
  }
  catch(e) {
    _consoleLog(e.message);
  }
}


async function _logCrackedEvent(conn, user_id) {
  var sqlcmd, param;
  
  user_id = parseInt(user_id, 10);
  
  try {
    sqlcmd = `UPDATE user_list ` +
             `  SET cracked = 1, ` +
             `  cracked_date = CURRENT_TIMESTAMP() ` +
             `  WHERE user_id = ?`;
    param = [user_id];             
    await dbs.sqlExec(conn, sqlcmd, param);
  }
  catch(e) {
    _consoleLog(e.message);
  }  
}


async function _logUnhappyLoginTime(conn, user_id, http_user_agent) {
  var sqlcmd, param, data;

  user_id = parseInt(user_id, 10);
  
  try {
    sqlcmd = `INSERT INTO unhappy_login_history ` +
             `(user_id, login_time, loc_longitude, loc_latitude, browser_signature) ` +
             `VALUES ` +
             `(?, CURRENT_TIMESTAMP(), 0, 0, ?)`;
             
    param = [user_id, http_user_agent];
    data = await dbs.sqlExec(conn, sqlcmd, param);
  }
  catch(e) {
    _consoleLog(e.message);
    await _logSystemError(conn, user_id, e.message, 'Unable to save unhappy login record', http_user_agent);
  }  
}


async function _informAdminSystemProblem(conn, user, subject, content) {
  var sqlcmd, data, body, from_mail, from_user, from_pass, smtp_server, port;
  var admins = [];
  
  try {
    sqlcmd = `SELECT user_name, user_alias, email ` +
             `  FROM user_list ` +
             `  WHERE user_role = 2 ` +
             `    AND status = 'A'`;
             
    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      var name = data[i].user_name;
      var alias = data[i].user_alias;
      var email = data[i].email;
      var record = {name: name, alias: alias, email: email};
      
      admins.push(record);
    }
    
    if (admins.length > 0) {
      var worker = await telecom.getMailWorker(conn);
      from_mail = worker.email;
      from_user = worker.m_user;
      from_pass = worker.m_pass; 
      smtp_server = worker.smtp_server; 
      port = worker.port;
      subject = (wev.allTrim(subject) == '')? 'System Problem' : subject; 
      
      for (var i = 0; i < admins.length; i++) {
        var this_admin = (wev.allTrim(admins[i].alias) != '')? admins[i].alias : admins[i].name;
        var this_email = admins[i].email;
        
        body = `Hi ` + this_admin + `, \n\n` +
              ((wev.allTrim(content) == '')? `Something unusual of this user <` + user + `> is found, please take a look. \n\n` : content + `\n\n`) +
              `Best regards, \n` +
              `Information Team.\n`;
        
        await telecom.sendEmail(smtp_server, port, from_mail, this_email, from_user, from_pass, subject, body);
      }      
    }             
  }
  catch(e) {
    _consoleLog(e.message);
  }
}


async function _isFirstUnhappyLogin(conn, user_id) {
  var sqlcmd, param, data, result;
  
  user_id = parseInt(user_id, 10);
  
  try {
    sqlcmd = `SELECT COUNT(*) AS cnt ` +
             `  FROM unhappy_login_history ` +
             `  WHERE user_id = ?`;
           
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);         
    data = JSON.parse(data);
    result = (data[0].cnt == 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function _markUserStatusAsUnhappy(conn, user_id) {
  var sqlcmd, param, data;

  user_id = parseInt(user_id, 10);  

  try {
    sqlcmd = `UPDATE user_list ` +
             `  SET status = 'U' ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    data = await dbs.sqlExec(conn, sqlcmd, param);         
  }
  catch(e) {
    await _logSystemError(conn, user_id, e.message, 'Unable to mark user as unhappy');
    throw e;
  }
}


async function _informRelatedGroupMembers(conn, user_id) {
  var sqlcmd, param, data, message;
  var msg_groups = [];
  
  message = 'I am very unhappy, please help.';

  try {
    //-- Find all message groups which this user involves --//
    sqlcmd = `SELECT group_id ` +
             `  FROM group_member ` +
             `  WHERE user_id = ?`;
    
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      msg_groups.push(data[i].group_id);
    }
    
    //-- Then send the message to all groups on behalf of this user --//
    for (var i = 0; i < msg_groups.length; i++) {
      var group_id = msg_groups[i];      
      await msglib.sendMessage(group_id, user_id, message, '', '', 0, '', '', '');
    }
  }
  catch(e) {
    await _logSystemError(conn, user_id, e.message, 'Unable to inform group members');
    throw e;    
  }
}


async function _informAllRelatedParties(conn, user_id, user) {
  var sqlcmd, param, data, subject, body, from_mail, from_user, from_pass, smtp_server, port;
  var inform_users = [];

  user_id = parseInt(user_id, 10);

  try {
    //-- Step 1: Get all non-administrative members who had communicated with the arrested user before --//
    sqlcmd = `SELECT DISTINCT b.user_name, b.user_alias, b.email ` +
             `  FROM group_member a, user_list b ` +
             `  WHERE a.user_id = b.user_id ` +
             `    AND a.group_id IN (SELECT DISTINCT group_id ` +
             `                         FROM group_member ` +
             `                         WHERE user_id = ?) ` +
             `    AND b.status = 'A' ` +
             `    AND b.user_role <= 1 ` + 
             `    AND a.user_id <> ?`;
             
    param = [user_id, user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
     
    for (var i = 0; i < data.length; i++) {
      var record = {name: data[i].user_name, alias: data[i].user_alias, email: data[i].email};
      inform_users.push(record);
    }
     
    //-- Step 2: Get all administrators --//
    sqlcmd = `SELECT user_name, user_alias, email ` +
             `  FROM user_list ` +
             `  WHERE user_role = 2 ` +
             `    AND status = 'A'`
              
    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);
     
    for (var i = 0; i < data.length; i++) {
      var record = {name: data[i].user_name, alias: data[i].user_alias, email: data[i].email};
      inform_users.push(record);
    }
     
    //-- Step 3: Send out email --//
    if (inform_users.length > 0) {
      var worker = await telecom.getMailWorker(conn);
      from_mail = worker.email;
      from_user = worker.m_user;
      from_pass = worker.m_pass; 
      smtp_server = worker.smtp_server; 
      port = worker.port;
      subject = 'Unhappy News'; 
       
      for (var i = 0; i < inform_users.length; i++) {
        var this_user = (wev.allTrim(inform_users.alias) != '')? inform_users.alias : inform_users.name;
        var this_email = inform_users.email;
         
        body = `Hi ` + this_user + `, \n\n` +
               user + ` is very unhappy now, be careful about it. \n\n` +
               `Best regards, \n` + 
               `Information Team.\n`;
                
        await telecom.sendEmail(smtp_server, port, from_mail, this_email, from_user, from_pass, subject, body);                
      }       
    }
  }
  catch(e) {
    await _logSystemError(conn, user_id, e.message, 'Unable to send warning email');
    throw e;        
  }
}


async function _selectSysAdminInCharge(conn) {
  var sqlcmd, data, result;
  
  try {
    sqlcmd = `SELECT a.user_id, count(*) AS cnt ` +
             `  FROM user_list a, group_member b ` +
             `  WHERE a.user_id = b.user_id ` +
             `    AND a.user_role = 2 ` +
             `    AND a.status = 'A' ` +
             `  GROUP BY a.user_id ` +
             `  ORDER BY cnt`;
  
    data = await dbs.sqlQuery(conn, sqlcmd);
    data = JSON.parse(data);
  
    if (data.length > 0) {
      //-- Note: Just need the first record. The rule is that who holds less group(s) will be selected out. --//
      result = parseInt(data[0].user_id, 10);
    }
    else {
      //-- Since table 'group_member' may be blank, therefore no administrator can be drawn out. So, we need --//
      //-- to try again to select an administrator. Usually, later joined administrator should hold less     --//
      //-- message groups.                                                                                   --//
      sqlcmd = `SELECT user_id ` +
               `  FROM user_list ` +
               `  WHERE user_role = 2 ` +
               `    AND status = 'A'` +
               `  ORDER BY user_id DESC`;
             
      data = await dbs.sqlQuery(conn, sqlcmd);
      data = JSON.parse(data);
    
      if (data.length > 0) {
        result = parseInt(data[0].user_id, 10);
      }  
      else {
        result = 0;
      }         
    }
  }
  catch(e) {
    _consoleLog(e.message);
    result = 0;
  }
  
  return result;
}


async function _isSoleGroupAdmin(conn, group_id, user_id) {
  var sqlcmd, param, data, cnt, result;
  var members = [];

  result = true;            // Assume he/she is the sole group administrator.
  
  try {
    //-- Note: System administrator have same rights of group administrator in a message group. Therefore, if it    --//
    //--       has at least one more system administrator as group member, the group still be considered with group --//
    //--       administrator even this system administrator is just ordinary member of the group.                   --//
    sqlcmd = `SELECT a.group_role, b.user_id ` +
             `  FROM group_member a, user_list b ` +
             `  WHERE a.user_id = b.user_id ` +
             `    AND a.group_id = ? ` +
             `    AND (a.group_role = '1' ` +
             `     OR b.user_role = 2) ` +
             `    AND a.user_id <> ? ` +
             `    AND b.status = 'A'`;
             
    param = [group_id, user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      if (data[i].group_role == '1') {
        //-- Another group administrator is found. --//
        result = false;
        break;
      }
      else {
        members.push(data[i].user_id);  
      }
    }  
    
    if (result == true && members.length > 0) {
      //-- If no another group administrator is found, promote the first found system administrator as group administrator. --//
      var this_user_id = members[0];
      
      sqlcmd = `UPDATE group_member ` +
               `  SET group_role = '1' ` +
               `  WHERE group_id = ? ` +
               `    AND user_id = ?`;
               
      param = [group_id, this_user_id];
      data = await dbs.sqlExec(conn, sqlcmd, param);         
      result = false;
    }           
  }
  catch(e) {
    _consoleLog(e.message);    
  }
    
  return result;  
}


async function _addSysAdminToGroup(conn, group_id, user_id) {
  var sql, param, data, result;
  
  result = {ok: true, msg: ''};  
  
  try {
    sqlcmd = `INSERT INTO group_member ` +
             `(group_id, user_id, group_role) ` +
             `VALUES ` +
             `(?, ?, '1')`;

    param = [group_id, user_id];
    data = await dbs.sqlExec(conn, sqlcmd, param);
  } 
  catch(e) {
    _consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;  
}


exports.loadGroupMeesagesForNewMember = async function(conn, group_id, user_id) {
  var sqlcmd, param, data, result;
  var miss_messages = [];
  
  result = {ok: true, msg: ''};
  
  try {
    //-- Step 1: Find out all missing messages of a group for the new member --//
    sqlcmd = `SELECT DISTINCT hex(a.msg_id) AS msg_id ` +
             `  FROM message a, msg_tx b ` +
             `  WHERE a.msg_id = b.msg_id ` +
             `    AND a.group_id = ? ` +
             `    AND b.receiver_id <> ?`;
             
    param = [group_id, user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      miss_messages.push(data[i].msg_id);      
    }
    
    //-- Step 2: Recreate message delivery transaction records for the new member --//
    for (var i = 0; i < miss_messages.length; i++) {
      var this_msg_id = miss_messages[i];
      
      sqlcmd = `INSERT INTO msg_tx ` +
               `(msg_id, receiver_id, read_status) ` +
               `VALUES ` +
               `(unhex(?), ?, 'U')`;
               
      param = [this_msg_id, user_id];
      data = await dbs.sqlExec(conn, sqlcmd, param);                     
    }         
  }
  catch(e) {
    _consoleLog(e.message);
    result = {ok: false, msg: 'Unable to load old messages for the new member. Error: ' + e.message};
  }
    
  return result;  
}


async function _kickOutFromGroup(conn, group_id, user_id) {
  var sqlcmd, param, msg;

  user_id = parseInt(user_id, 10);

  try {
    sqlcmd = `DELETE FROM group_member ` +
             `  WHERE group_id = ? ` +
             `    AND user_id = ?`;
             
    param = [group_id, user_id];
    await dbs.sqlExec(conn, sqlcmd, param);         
  }
  catch(e) {
    msg = 'Unable to kick an unhappy user (id = ' + user_id.toString() + ') from group (id = ' + group_id.toString() + '), take action immediately! Error: ' + e.message;
    await _logSystemError(conn, user_id, msg, 'Unable to kick unhappy user');
    _consoleLog(msg);
    throw e;
  }
}


async function _kickOut(conn, user_id) {
  var sqlcmd, param, msg;
  
  user_id = parseInt(user_id, 10);

  try {
    sqlcmd = `DELETE FROM group_member ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    await dbs.sqlExec(conn, sqlcmd, param);         
  }
  catch(e) {
    msg = 'Unable to kick an unhappy user (id = ' + user_id.toString() + '), take action immediately! Error: ' + e.message;
    await _logSystemError(conn, user_id, msg, 'Unable to kick unhappy user');
    _consoleLog(msg);
    throw e;
  }  
}


async function _kickOutFromMessageGroups(conn, user_id) {
  var sqlcmd, param, data, ok, msg, is_group_admin, sys_admin_id;
  var msg_groups = [];
  
  user_id = parseInt(user_id, 10);
  
  ok = true;
  msg = '';
  is_group_admin = false;
  
  try {
    //-- Step 1: Find all message groups which this user involves --//
    sqlcmd = `SELECT group_id, group_role ` +
             `  FROM group_member ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    for (var i = 0; i < data.length; i++) {
      var rec = {group_id: data[i].group_id, group_role: data[i].group_role};
      msg_groups.push(rec);
      //-- Check whether this user is administrator of at least one message group --//
      is_group_admin = (data[i].group_role == 1)? true : is_group_admin;
    }         
    
    //-- Step 2: If this user heads one or more group(s), find a system administrator to replace his/her position. Otherwise, just --//
    //--         kick him/her out from all the involved group(s).                                                                  --//
    if (msg_groups.length > 0 && is_group_admin) {
      //-- Select a system administrator who may need to take over those group(s) which have been headed by this guy. --//
      //-- Note: The worst situation is that all system administrators are arrested, then sys_admin_id will be 0. if  --//
      //--       it is the case, just kick that arrested guy from all the group(s), and let those group(s) operate    --//
      //--       without administrator. Hopefully, it would be fixed later manually.                                  --//
      sys_admin_id = await _selectSysAdminInCharge(conn);
    }
    
    if (is_group_admin && sys_admin_id > 0) {
      for (var i = 0; i < msg_groups.length; i++) {
        var this_group_id = msg_groups[i].group_id;
        var this_group_role = msg_groups[i].group_role;
      
        if (this_group_role == 1) {
          if (await _isSoleGroupAdmin(conn, this_group_id, user_id)) {
            var result = await _addSysAdminToGroup(conn, this_group_id, sys_admin_id);
            if (result.ok) {
              await loadGroupMeesagesForNewMember(conn, this_group_id, sys_admin_id); 
            }            
          }
        }
        
        await _kickOutFromGroup(conn, this_group_id, user_id);
      }
    }
    else {
      await _kickOut(conn, user_id);
    }
  }
  catch(e) {
    await _logSystemError(conn, user_id, e.message, 'Unable to kick out user');
    throw e;            
  }
}


async function _increaseLoginFailureCounter(conn, user_id) {
  var sqlcmd, param, data;
  
  user_id = parseInt(user_id, 10);
  
  try {
    //-- Note: MariaDB/MySQL specified SQL syntax is used in here --//
    sqlcmd = `UPDATE user_list ` +
             `  SET login_failed_cnt = IF(login_failed_cnt IS NULL, 1, login_failed_cnt + 1) ` + 
             `  WHERE user_id = ?`;
             
    param = [user_id];
    data = await dbs.sqlExec(conn, sqlcmd, param);         
  }
  catch(e) {
    _consoleLog(e.message);
  }
}


async function _logHackingHistory(conn, user_id, ip_addr) {
  var sqlcmd, param, data, cnt;
  
  user_id = parseInt(user_id, 10);
  ip_addr = (typeof(ip_addr) != 'string')? '' : ip_addr.trim();
  
  try {
    if (user_id > 0 && ip_addr != '') {
      //-- Step 1: Check whether hacking record of given user exists or not --//
      sqlcmd = `SELECT COUNT(*) AS cnt ` +
               `  FROM hack_history ` +
               `  WHERE user_id = ? ` +
               `    AND ipv4_addr = ?`;
               
      param = [user_id, ip_addr];         
      data = await dbs.sqlQuery(conn, sqlcmd, param);
      data = JSON.parse(data);
      cnt = data[0].cnt;
      
      //-- Step 2: If record of same hacker for same user has already existed, update attacking counter and last hacking --//
      //--          time. Otherwise, add a new hacking record for it.                                                    --//             
      if (cnt > 0) {
        sqlcmd = `UPDATE hack_history ` +
                 `  SET last_hack_time = CURRENT_TIMESTAMP(), ` +
                 `      hack_cnt = hack_cnt + 1 ` +
                 `  WHERE user_id = ? ` +
                 `    AND ipv4_addr = ?`;
                 
        param = [user_id, ip_addr];
        await dbs.sqlExec(conn, sqlcmd, param);         
      }
      else {
        sqlcmd = `INSERT INTO hack_history ` +
                 `(ipv4_addr, user_id, first_hack_time, last_hack_time, hack_cnt, ip_blocked) ` +
                 `VALUES ` +
                 `(?, ?, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), 1, 0)`;
                 
        param = [ip_addr, user_id]; 
        await dbs.sqlExec(conn, sqlcmd, param);         
      }
    }    
  }
  catch(e) {
    _consoleLog(e.message);
  }  
}


exports.authenticateLoginUser = async function(msg_pool, pda_pool, username, password, rolling_key, aes_key, http_user_agent, ip_addr) {
  var connh, connp, sqlcmd, param, data, user_id, happy_passwd, unhappy_passwd, email, status, connection_mode, login_status, message, redirect_url, result;
  var private_key;
  
  login_status = 1;
  message = '';
  redirect_url = '/';
  result = {ok: 1, msg: '', url: '/'};
      
  try {
    connh = await dbs.getPoolConn(msg_pool, 'COOKIE_MSG');
    connp = await dbs.getPoolConn(pda_pool, 'COOKIE_PDA'); 
        
    sqlcmd = `SELECT user_id, happy_passwd, unhappy_passwd, email, status ` +
             `  FROM user_list ` +
             `  WHERE user_name = ?`;
    param = [username];
    data = await dbs.sqlQuery(connh, sqlcmd, param);
    data = JSON.parse(data);

    if (data.length > 0) {
      user_id = parseInt(data[0].user_id, 10);
      happy_passwd = data[0].happy_passwd;
      unhappy_passwd = data[0].unhappy_passwd;
      email = data[0].email;
      status = data[0].status;
      
      //-- Get system defined connection mode --//
      connection_mode = parseInt(await wev.getSysSettingValue(connh, 'connection_mode'), 10);
      
      if (await cipher.isPasswordMatch(password, happy_passwd)) {
        switch (status) {
          case 'A':
            // Normal user //
            if (connection_mode == 0) {
              //-- Login in via email --//
              var sent_mail_result = await _sendMessageAccessLinkMail(connh, user_id, email, aes_key, rolling_key);
              login_status = sent_mail_result.login_status;
              message = sent_mail_result.message;
              
              if (login_status == 1) {
                var sess_object = await wev.createSessionRecord(connp, user_id, null, null, http_user_agent, ip_addr);
                redirect_url = '/pdatools?user=' + username + '&sess_code=' + sess_object.sess_code;
              }
              else {
                redirect_url = '/pdatools?user=' + username + '&sess_code=';
              }
              
              result = {ok: login_status, msg: message, url: redirect_url};
            }
            else if (connection_mode == 1) {
              //-- Login directly --//
              var login_object = await _buildMessageAccessLink(connh, user_id, aes_key, rolling_key);
              login_status = login_object.login_status;
              message = login_object.message;
              redirect_url = login_object.redirect_url;
              result = {ok: login_status, msg: message, url: redirect_url}; 
            }
            else if (connection_mode == 2) {
              //-- Login directly --//
              var login_object = await _buildMessageAccessLink(connh, user_id, aes_key, rolling_key);
              login_status = login_object.login_status;
              message = login_object.message;
              redirect_url = login_object.redirect_url;               
              result = {ok: login_status, msg: message, url: redirect_url};
            }
            else if (connection_mode == 3) {
              //-- Login in via email --//
              var sent_mail_result = await _sendMessageAccessLinkMail(connh, user_id, email, aes_key, rolling_key);
              login_status = sent_mail_result.login_status;
              message = sent_mail_result.message;
              
              if (login_status == 1) {
                var sess_object = await wev.createSessionRecord(connp, user_id, null, null, http_user_agent, ip_addr);
                redirect_url = '/pdatools?user=' + username + '&sess_code=' + sess_object.sess_code;
              }
              else {
                redirect_url = '/pdatools?user=' + username + '&sess_code=';
              }

              result = {ok: login_status, msg: message, url: redirect_url};              
            }
            else {
              //-- Value of system setting 'connection_mode' is invalid --//
              user_id = (typeof(user_id) == 'number' && Number.isSafeInteger(user_id))? user_id : 0;
              var brief_msg = `Invalid system setting`;
              var detail_msg = `Value of system setting 'connection_mode' is invalid. It is now ` + connection_mode.toString();
              await _logSystemError(connh, user_id, detail_msg, brief_msg, http_user_agent);
              _consoleLog(detail_msg);
              
              message = 'Authentication server is malfunction, please return later.';            
              login_status = 0;
              redirect_url = '/';
              result = {ok: login_status, msg: message, url: redirect_url};
            }            
            break;
          
          case 'D':
            // Deactivated user //
            message = 'Authentication server is down, please try again later.';
            login_status = 0;          
            redirect_url = '/';
            result = {ok: login_status, msg: message, url: redirect_url};            
            break;
            
          case 'U':
            // Arrested user may be cracked by force //
            if (await _beCracked(connh, user_id) == 0) {
              await _informAdminUnhappyUserIsCracked(connh, username);
              await _logCrackedEvent(connh, user_id);
            }                      
            await _logUnhappyLoginTime(connh, user_id, http_user_agent);
            
            login_status = 1;
            var sess_object = await wev.createSessionRecord(connp, user_id, null, null, http_user_agent, ip_addr);
            redirect_url = '/pdatools?user=' + username + '&sess_code=' + sess_object.sess_code;
            result = {ok: login_status, msg: message, url: redirect_url};            
            break;  
            
          default:
            // Invalid user status value //
            user_id = (typeof(user_id) == 'number' && Number.isSafeInteger(user_id))? user_id : 0;
            var brief_msg = `Invalid user status: ` + status;
            var detail_msg = `The system find that user status of ` + username + ` is abnormal, please take a look.`;
            await _logSystemError(connh, user_id, detail_msg, brief_msg, http_user_agent);            
            await _informAdminSystemProblem(connh, username, brief_msg, detail_msg);
            _consoleLog(detail_msg);

            message = "The server is under maintenance, please try again later.";
            login_status = 0;
            redirect_url = '/';
            result = {ok: login_status, msg: message, url: redirect_url};
        }
      }
      else if (await cipher.isPasswordMatch(password, unhappy_passwd)) {
        if (await _isFirstUnhappyLogin(connh, user_id)) {
          await _markUserStatusAsUnhappy(connh, user_id);
          if (connection_mode == 1) {
            await _informRelatedGroupMembers(connh, user_id);
          }
          else {
            //-- Note: Function '_informAllRelatedParties' must be run after function '_markUserStatusAsUnhappy'. Otherwise, warning email --//
            //--       will be sent to the guy who is arrested, if he/she is system administrator.                                         --//            
            await _informAllRelatedParties(connh, user_id, username);
          }
          //-- Note: Function '_kickOutFromMessageGroups' MUST be run after function '_informAllRelatedParties'. Otherwise, incorrect --//
          //--       result will be obtained.                                                                                         --//
          await _kickOutFromMessageGroups(connh, user_id);                     
        }
        
        await _logUnhappyLoginTime(connh, user_id, http_user_agent);
        login_status = 1;
        var sess_object = await wev.createSessionRecord(connp, user_id, null, null, http_user_agent, ip_addr);         
        redirect_url = '/pdatools?user=' + username + '&sess_code=' + sess_object.sess_code;             
        result = {ok: login_status, msg: message, url: redirect_url};     
      }
      else {
        //-- Invalid password --//
        await _increaseLoginFailureCounter(connh, user_id);
        await _logHackingHistory(connh, user_id, ip_addr);
        message = "Authentication server is out of order, please try again later.";
        login_status = 0;
        redirect_url = '/';
        result = {ok: login_status, msg: message, url: redirect_url}; 
      }
    }    
    else {
      //-- Invalid user --//
      message = "Unable to contact the authentication server, please try again later.";
      login_status = 0;     
      redirect_url = '/';
      result = {ok: login_status, msg: message, url: redirect_url}; 
    }
  }
  catch(e) {
    //-- Unexpected error --//    
    user_id = (typeof(user_id) == 'number' && Number.isSafeInteger(user_id))? user_id : 0;
    var brief_msg = 'Login process error';
    var detail_msg = e.message;
    await _logSystemError(connh, user_id, detail_msg, brief_msg, http_user_agent);
    _consoleLog(detail_msg);
    
    message = "Authentication server is very busy right now, please try again later.";
    login_status = 0;     
    redirect_url = '/';
    result = {ok: login_status, msg: message, url: redirect_url};     
  }
  finally {
    dbs.releasePoolConn(connh);
    dbs.releasePoolConn(connp);
  }
  
  return result;
}


async function _resolvePassParameters(decrypted) {
  var user_id, seed, result;
  
  user_id = 0;
  seed = '';
  
  var buffer = decrypted.split('&');
  for (var i = 0; i < buffer.length; i++) {
    var parts = buffer[i].split('=');
    var param_name = parts[0].trim();
    var param_data = parts[1].trim();
    
    if (param_name.match(/user_id/gi) != null) {
      user_id = parseInt(param_data, 10);
    }
    else if (param_name.match(/seed/gi) != null) {
      seed = param_data;
    }
  }
  
  result = {user_id: user_id, seed: seed};
  
  return result;
}


// Note: Time interval 'interval' is in MariaDB time format
async function _isTimeLimitPassed(conn, timestamp, interval) {  
  var sql, param, data, result;
  
  try {
    sql = `SELECT TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), ADDTIME(?, ?)) AS tdi`;
    param = [timestamp, interval];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));    
    result = (parseInt(data[0].tdi, 10) >= 0)? false : true;
  }
  catch(e) {
    _consoleLog(e.message);
    //-- Play safe, return true as any error is found. --//
    result = true;
  }
    
  return result;
}


exports.isTimeLimitPassed = async function(conn, timestamp, interval) {
  var result = _isTimeLimitPassed(conn, timestamp, interval);
}


async function _markLoginTokenStatus(conn, token, status) {
  var sqlcmd, param;
  
  try {
    sqlcmd = `UPDATE login_token_queue ` +
             `  SET status = ? ` +
             `  WHERE token = ?`;
             
    param = [status, token];
    await dbs.sqlExec(conn, sqlcmd, param);         
  }
  catch(e) {
    throw e;
  }
}


async function _markLoginTokenTimeout(conn, token) {
  try {
    await _markLoginTokenStatus(conn, token, 'T'); 
  }
  catch(e) {
    throw e;
  }
}


async function _markLoginTokenIsReady(conn, token) {
  try {
    await _markLoginTokenStatus(conn, token, 'R');
  }
  catch(e) {
    throw e;
  }
}


async function isTokenValid(conn, token) {
  let sqlcmd, param, data, user_id, algorithm, key, iv, encrypted, timestamp, status, decrypted, user_id_chk, seed, result;
  
  try {
    //-- Step 1: Get user id, encryption key and record timestamp for given token. --//
    //-- Note: Token stored in 'login_token_queue' is in escaped format.           --//
    sqlcmd = `SELECT user_id, algorithm, token_iv, token_seed, DATE_FORMAT(token_addtime, '%Y-%m-%d %H:%i:%s') AS token_addtime, status ` +
             `  FROM login_token_queue ` +
             `  WHERE token = ?`;
             
    param = [token];         
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      user_id = parseInt(data[0].user_id, 10);
      algorithm = data[0].algorithm;
      key = data[0].token_seed;
      iv = cipher.convertBase64IVtoIV(data[0].token_iv);
      timestamp = data[0].token_addtime;
      status = data[0].status;
    
      if (user_id > 0 && key.trim() != '' && timestamp.trim() != '' && status == 'A') {  
        //-- Step 2: Decrypt the login token to extract stored user id and the encryption key, then compare them with the data  --//
        //--         extracting from the database. Note: It must unescape passed token value before give it into the decryption --//
        //--         function, since it is the original value (format) when it is encrypted.                                    --//
        encrypted = cipher.base64StringToArrayBuffer(unescape(token));
        decrypted = await cipher.aesDecrypt(algorithm, key, iv, encrypted);
        
				let resolve_result = await _resolvePassParameters(decrypted);
				user_id_chk = parseInt(resolve_result.user_id, 10);
				seed = resolve_result.seed;
				
				if (user_id_chk != user_id || seed.trim() != key.trim()) {
					//-- Data is not matched, the token is fabricated. --//
					result = false;
				}
				else {
					if (await _isTimeLimitPassed(conn, timestamp, '0:15:0.0')) {      // Time limit of an authentication token is 15 minutes since it is created.        
						//-- Time limit assigned to the token has been passed --//
						await _markLoginTokenTimeout(conn, token);
						result = false;
					}
					else {
						//-- It is a valid token --//
						await _markLoginTokenIsReady(conn, token);      // Set login token status to 'R' (ready to be used).
						result = true;  
					}            
				}
      }
      else {
        //-- Login queue record has been used or contains invalid data --//
        result = false;        
      }
    }
    else {
      //-- Login queue with the given token is not found or invalid --//
      result = false;
    }
  }
  catch(e) {
    //-- Runtime error is found --//
    _consoleLog(e.message);
    result = false;    
  }
    
  return result; 
}


async function _selectSiteForVisitor(conn) {
  var sqlcmd, data, cnt, rows, stop_run, idx, max_cnt, result;
  var sites = []; 
  
  //-- Default value --//
  result = 'https://www.microsoft.com';
  
  try {
    sqlcmd = `SELECT site_url ` +
             `  FROM decoy_sites`;
    data = JSON.parse(await dbs.sqlQuery(conn, sqlcmd));
    
    for (var i = 0; i < data.length; i++) {
      sites.push(data[i].site_url);
    }         
    
    rows = sites.length;
    if (rows > 0) {
      stop_run = false;
      max_cnt = 0;
      
      while (!stop_run) {
        //-- Return a random number between 1 and 'rows + arbitrary' --//
        var arbitrary = Math.floor((Math.random() * rows * 2) + 1);
        cnt = Math.floor((Math.random() * (rows + arbitrary)) + 1);
        
        if (cnt >= 1 && cnt <= rows) {
          idx = cnt - 1;
          result = sites[idx];
          stop_run = true;
        }
        
        if (!stop_run) {
          max_cnt++;
          if (max_cnt >= 50) {
            stop_run = true;
          }    
        }
      }
    }
  }
  catch(e) {
    _consoleLog(e.message);
  }
    
  return result;
}


exports.selectSiteForHacker = async function(msg_pool) {
  var conn, url;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    url = _selectSiteForVisitor(conn);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return url;
} 


exports.loginAgent = async function(msg_pool, token) {
  var conn, url;
  
  url = '';
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
        
    //-- Note: token is now escaped --//
    if (await isTokenValid(conn, token)) {
      url = '/logon_agent?tk=' + token;
    }
    else {
      url = await _selectSiteForVisitor(conn); 
      
      if (url == '') {
        url = 'https://www.microsoft.com';
      }
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return url;
}


async function _getUserIdFromToken(conn, token) {
  let sqlcmd, param, data, user_id;
  
  try {
    //-- Note: Only status 'R' token will be extracted for security measure (Prevent attacker use old token to login to the system) --//
    sqlcmd = `SELECT user_id ` +
             `  FROM login_token_queue ` +
             `  WHERE token = ? ` +
             `    AND status = 'R'`;
    
    param = [token];
    data = JSON.parse(await dbs.sqlQuery(conn, sqlcmd, param));
    
    if (data.length > 0) {
      user_id = parseInt(data[0].user_id, 10);
    }
    else {
      user_id = 0;
    }
  }
  catch(e) {
    throw e;
  }
  
  return user_id;  
}


async function _getAESkeyFromToken(conn, token) {
  let sqlcmd, param, data, aes_key, rolling_key, result;
  
  try {
    //-- Note: Only status 'R' token will be extracted for security measure (Prevent attacker use old token to login to the system) --//
    sqlcmd = `SELECT aes_key, rolling_key ` +
             `  FROM login_token_queue ` +
             `  WHERE token = ? ` +
             `    AND status = 'R'`;
    
    param = [token];
    data = JSON.parse(await dbs.sqlQuery(conn, sqlcmd, param));
    
    if (data.length > 0) {
      aes_key = wev.allTrim(data[0].aes_key);
      rolling_key = wev.allTrim(data[0].rolling_key);
    }
    else {
			aes_key = '';
      rolling_key = '';
		}
    
    result = {
			aes_key: aes_key,
      rolling_key: rolling_key      
    };
  }
  catch(e) {
    throw e;
  }
  
  return result;  	
}


async function _setLoginTokenUsed(conn, token) {
  try {  
    await _markLoginTokenStatus(conn, token, 'U');
  }
  catch(e) {
    throw e;
  }
}


async function _setUserInformFlag(conn, user_id, flag) {
  var sqlcmd, param, result;
  
  result = {ok: true, msg: ''};
  
  try {
    sqlcmd = `UPDATE user_list ` +
             `  SET inform_new_msg = ? ` +
             `  WHERE user_id = ?`;
             
    param = [flag, user_id];
    await dbs.sqlExec(conn, sqlcmd, param);             
  }
  catch(e) {
    _consoleLog(e.message);
    result = {ok: false, msg: e.message};
  }
  
  return result;  
}


async function _deleteUserInformRecord(conn, user_id) {
  var sqlcmd, param, result;
  
  result = {ok: true, msg: ''};
  
  try {
    sqlcmd = `DELETE FROM new_msg_inform ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    await dbs.sqlExec(conn, sqlcmd, param);             
  }
  catch(e) {
    _consoleLog(e.message);
    result = {ok: false, msg: 'Unable to remove new message inform record(s). Error: ' + e.message};
  } 

  return result;  
}


async function _goLogonProcess(conn, user_id, aes_key, rolling_key, http_user_agent, ip_addr) {
  let ok, msg, sess_code, url, result;

  result = {ok: false, msg: '', user_id: 0, sess_code: '', url: ''};
  
  try {
    let sess_object = await wev.createSessionRecord(conn, user_id, aes_key, rolling_key, http_user_agent, ip_addr);
    sess_code = sess_object.sess_code;
    ok = sess_object.ok
    msg = sess_object.msg;
    
    if (ok) {
      url = `
      <!doctype html>
      <html>
        <head>
          <script type="text/javascript" src='/js/jquery.min.js'></script>
          <script type="text/javascript" src="/js/js.cookie.min.js"></script>
          <script type="text/javascript" src='/js/crypto-lib.js'></script>               
          <script type="text/javascript" src='/js/common_lib.js'></script>
                          
          <script>
            $(document).ready(function() {
              // -----------------------------------------------------------------------------------------------------//
              // Important Note:                                                                                      //
              // jQuery v2.1.4 can't handle async functions and the await syntax introduced in ECMAScript 2017 (ES8). // 
              // This is because that version of jQuery was released before async/await was a standard feature in     //
              // JavaScript environments. Here is a work-around method to encapsulate async/await logic within the    //
              // async function 'switchToLandingPage' and call it. This avoids top-level await issues.                //
              // -----------------------------------------------------------------------------------------------------//              
              switchToLandingPage();
            });
            
            async function switchToLandingPage() {
              await prepareRollingKey(${_key_len});     // Defined on crypto-lib.js              
              $("#frmLeap").submit();            
            }
          </script>
        </head>
        
        <body>
          <form id='frmLeap' name='frmLeap' action='/message' method='POST'>
            <input type=hidden id="roll_rec" name="roll_rec" value="">
            <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
            <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">   
          </form>        
        </body>        
      </html>`;
      
      result = {ok: true, msg: '', user_id: user_id, sess_code: sess_code, url: url};
    }
    else {
      result = {ok: false, msg: 'Unable to create session, please login again', user_id: 0, sess_code: '', url: '/'};
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;   
}


exports.finalizeLoginProcess = async function(msg_pool, token, http_user_agent, ip_addr) {
  var conn, user_id, keys, url, result;
  
  result = {ok: false, msg: '', user_id: 0, sess_code: '', url: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, 'COOKIE_MSG'); 
    
    //-- Only a token with status 'R' will be accepted. It prevents attacker to get in the system by using old token. --//
    user_id = await _getUserIdFromToken(conn, token);          
    
    if (user_id > 0) {
			keys = await _getAESkeyFromToken(conn, token);
      await _setLoginTokenUsed(conn, token);                      // Set token status to 'U' (used) now.
      await _setUserInformFlag(conn, user_id, 1);                 // Reset new message inform flag to 1. i.e. Accept new message inform.  
      await _deleteUserInformRecord(conn, user_id);
      result = await _goLogonProcess(conn, user_id, keys.aes_key, keys.rolling_key, http_user_agent, ip_addr);      
    }
    else {
      url = await _selectSiteForVisitor(conn);
      result = {ok: false, msg: '', user_id: 0, sess_code: '', url: url};
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;
}


async function _extendSessionValidTime(conn, sess_code) {
  var sql, param, sess_until;
  
  try {
    sess_until = await wev.setSessionValidTime();
    
    sql = `UPDATE web_session ` +
          `  SET sess_until = ? ` + 
          `  WHERE sess_code = ?`;
    
    param = [sess_until, sess_code];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    _consoleLog(e.message); 
  }  
}


async function _deleteSession(conn, sess_code) {
  var sql, param;
  
  try {
    sql = `DELETE FROM web_session ` + 
          `  WHERE sess_code = ?`;
          
    param = [sess_code];
    await dbs.sqlExec(conn, sql, param);       
  }
  catch(e) {
    _consoleLog(e.message);
  }
}


// 2025-12-04: This function will be phased out after rolling key mechanism is implemented and deplyed // 
exports.isSessionValid = async function(db_pool, user_id, sess_code, extend_session, conn_option) {
  var conn, sqlcmd, param, data, sess_until, sess_valid;
  
  sess_valid = false;
  
  try {
    //-- Notes: 1. This function will be used to check session located on database 'msgdb' or 'pdadb'. Therefore, if --//
    //--           'conn_option' is blank or undefined, then that would be no last resort to be provided as database --//
    //--           pool connection is failure.                                                                       --//
    //--        2. 'conn_option' is used as last resort as this function can't get a connection from the pool, and   --//
    //--           valid values of 'conn_option' are 'MSG' and 'PDA', others may cause runtime error.                --//           
    conn_option = (typeof(conn_option) != "string")? "" : dbs.selectCookie(conn_option);       
    conn = await dbs.getPoolConn(db_pool, conn_option);              
    
    sqlcmd = `SELECT TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), sess_until) AS timediff ` +
             `  FROM web_session ` +
             `  WHERE user_id = ? ` +
             `    AND sess_code = ? ` + 
             `    AND status = 'A'`;
                 
    param = [user_id, sess_code];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      sess_valid = (parseInt(data[0].timediff, 10) > 0)? true : false;
      
      if (sess_valid) {
        extend_session = (typeof(extend_session) == 'boolean')? extend_session : false;
        
        if (extend_session) {
          await _extendSessionValidTime(conn, sess_code);
        }        
      }
      else {
        await _deleteSession(conn, sess_code);
      }      
    }
    else {
      await _deleteSession(conn, sess_code);     // Session record may still exist.
      sess_valid = false;
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return sess_valid;
}


async function _isActiveSession(conn, user_id, sess_code) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), sess_until) AS timediff ` +
          `  FROM web_session ` +
          `  WHERE user_id = ? ` +
          `    AND sess_code = ? ` + 
          `    AND status = 'A'`;
                 
    param = [user_id, sess_code];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = (parseInt(data[0].timediff, 10) > 0)? true : false;
    }
    else {
      result = false;
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getSessionKeys(conn, user_id, sess_code) {
  let sql, param, data, result = {aes_key: '', rolling_key: ''};
  
  try {
    sql = `SELECT secure_key, rolling_key ` +
          `  FROM web_session ` +
          `  WHERE user_id = ? ` +
          `    AND sess_code = ? ` + 
          `    AND status = 'A'`;

    param = [user_id, sess_code];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      let aes_key = data[0].secure_key;
      let rolling_key = data[0].rolling_key;
      
      result = {aes_key: aes_key, rolling_key: rolling_key};
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _sessionRollingKeyExist(conn, sess_code, rolling_key) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM sess_roll_key ` +
          `  WHERE sess_code = ? ` + 
          `    AND rolling_key = ?`;      

    param = [sess_code, rolling_key];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = (parseInt(data[0].cnt, 10) > 0)? true : false; 
  }
  catch(e) {
    throw e;
  }
   
  return result; 
}


async function _saveNewRollingKey(conn, sess_code, rolling_key) {
  let sql, param;
  
  try {
    if (await _sessionRollingKeyExist(conn, sess_code, rolling_key)) {
      sql = `UPDATE sess_roll_key ` + 
            `  SET counter = counter + 1 ` +
            `  WHERE sess_code = ? ` + 
            `    AND rolling_key = ?`;      
    }
    else {
      sql = `INSERT INTO sess_roll_key ` +
            `(sess_code, rolling_key, counter) ` +
            `VALUES ` +
            `(?, ?, 1)`;
    }

    param = [sess_code, rolling_key];
    await dbs.sqlExec(conn, sql, param);          
  }
  catch(e) {
    throw e;
  }
}


async function _getNewRollingKeyCount(conn, sess_code, rolling_key) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT counter ` +
          `  FROM sess_roll_key ` +
          `  WHERE sess_code = ? ` + 
          `    AND rolling_key = ?`;      

    param = [sess_code, rolling_key];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = (data.length > 0)? parseInt(data[0].counter, 10) : 0; 
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.isSessionValidEx = async function(db_pool, user_id, sess_code, enc_roll_rec, extend_session, conn_option) {
  let conn, aes_key, cur_rolling_key, new_rolling_key, sess_valid;
    
  try {
    //-- Notes: 1. This function will be used to check session located on database 'msgdb' or 'pdadb'. Therefore, if --//
    //--           'conn_option' is blank or undefined, then that would be no last resort to be provided as database --//
    //--           pool connection is failure.                                                                       --//
    //--        2. 'conn_option' is used as last resort as this function can't get a connection from the pool, and   --//
    //--           valid values of 'conn_option' are 'MSG' and 'PDA', others may cause runtime error.                --//           
    conn_option = (typeof(conn_option) != "string")? "" : dbs.selectCookie(conn_option);         
    conn = await dbs.getPoolConn(db_pool, dbs.selectCookie(conn_option));
    
    if (user_id > 0 && sess_code != "") {
      if (await _isActiveSession(conn, user_id, sess_code)) {
        let keys = await _getSessionKeys(conn, user_id, sess_code);
        
        if (keys.aes_key != "" && keys.rolling_key != "") {
          aes_key = keys.aes_key;
          cur_rolling_key = keys.rolling_key;
                    
          let roll_rec_json = await cipher.aesDecryptJSON("AES-GCM", aes_key, enc_roll_rec.iv, enc_roll_rec.encrypted);                    
          let roll_rec = JSON.parse(roll_rec_json);
          let cs_sum = enc_roll_rec.digest;
          let ss_sum = await cipher.digestData("SHA-256", roll_rec_json);
          
          if (cur_rolling_key.trim() == roll_rec.cur_rolling_key.trim() && cs_sum.trim() == ss_sum.trim()) {
            new_rolling_key = roll_rec.new_rolling_key.trim();
            await _saveNewRollingKey(conn, sess_code, new_rolling_key);
            
            if (await _getNewRollingKeyCount(conn, sess_code, new_rolling_key) == 1) {    
              if (extend_session) { await _extendSessionValidTime(conn, sess_code); }
              sess_valid = true;
            }
            else {
              // Duplicated rolling key is found. May be the user session has been intercepted and the hacker try to use  //
              // old rolling key to infiltrate the system. The other possibility is the user clicking the browser refresh //
              // button. Either way, the session should be force ended due to security.                                   //   
              await _deleteSession(conn, sess_code); 
              sess_valid = false;                          
            }
          }  
          else {
            // Invalid rolling key is given. Hacker try to use invalid rolling key to infiltrate the system. The other //
            // possibility is network transmission error to corrupt rolling key, but the chance is quite low.          //  
            await _deleteSession(conn, sess_code);  
            sess_valid = false;
          }
        }
        else {
          await _deleteSession(conn, sess_code);   // Someting is wrong, delete session and let user login again.
          sess_valid = false;
        }
      }
      else {
        await _deleteSession(conn, sess_code);     // Session record may still exist.
        sess_valid = false;
      }
    }
    else {
      sess_valid = false;
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return sess_valid;
}


//-- For websocket connection request verification and websocket operations only --//
exports.checkSession = async function(msg_pool, user_id, sess_code, callback) {     // 'callback' is a function to return the result and error (if any) to the caller.
  var conn, sqlcmd, param, data, error, result;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    sqlcmd = `SELECT TIMESTAMPDIFF(second, CURRENT_TIMESTAMP(), sess_until) AS timediff ` +
             `  FROM web_session ` +
             `  WHERE user_id = ? ` +
             `    AND sess_code = ? ` + 
             `    AND status = 'A'`;
    
    param = [user_id, sess_code];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = (parseInt(data[0].timediff, 10) > 0)? true : false;
    }
    else {
      result = false;
    }    
  }
  catch(e) {
    _consoleLog(e.message);
    error = e.message;
    result = false;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  callback(error, result);
}


//-- This function is valid for MySQL and MariaDB only --//
async function isTableExist(conn, tablename) {
  var sqlcmd, param, data, result;
  
  try {
    sqlcmd = `SELECT COUNT(*) AS cnt ` +
             `  FROM information_schema.tables ` +
             `  WHERE table_schema = DATABASE() ` +
             `    AND table_name = ?`;
             
    param = [tablename];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);         
    
    if (parseInt(data[0].cnt, 10) == 1) {
      result = true;  
    }
    else {
      result = false;
    }
  }
  catch(e) {
    _consoleLog(e.message);
    result = false;
  }  
  
  return result;
}


async function extendSession(conn, sess_code) {
  var conx, sqlcmd, param, data, close_conx, session_period;
  
  try {
    //-- Note: Table 'sys_settings' is located on database 'msgdb' only, so it needs to ensure --//
    //--       to connect the right database.                                                  --//    
    if (await isTableExist(conn, 'sys_settings')) {
      conx = conn; 
      close_conx = false;
    }
    else {
      conx = await dbConnect('COOKIE_MSG');
      close_conx = true;
    }  
    
    //-- Step 1: Get system defined session period, if it can't be found, let it be 2 hours. --//
    var sys_value = await wev.getSysSettingValue(conx, 'session_period');
    session_period = (sys_value.trim() != '')? sys_value : '02:00:00';
    
    //-- Step 2: Extend session expiry time --//
    sqlcmd = `UPDATE web_session ` +
             `  SET sess_until = ADDTIME(CURRENT_TIMESTAMP(), ?) ` +
             `  WHERE sess_code = ?`;
               
    param = [session_period, sess_code];
    await dbs.sqlExec(conn, sqlcmd, param);
  }
  catch(e) {
    _consoleLog(e.message);
  }  
  finally {
    if (close_conx) {
      await dbs.dbClose(conx);
    }
  }
}


async function getUserIdFromSession(conn, sess_code) {
  var sqlcmd, param, data, user_id;
  
  try {
    sqlcmd = `SELECT user_id ` +
             `  FROM web_session ` +
             `  WHERE sess_code = ? ` +
             `    AND status = 'A'`;
             
    param = [sess_code];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      user_id = parseInt(data[0].user_id, 10);
    }
    else {
      throw new Error('Session does not exist, so that user ID cannot be determined.');
    }          
  }
  catch(e) {
    throw e;
  }
  
  return user_id;
}


async function getUserRole(conn, user_id) {
  var sqlcmd, param, data, user_role;
  
  user_role = 0;
  
  try {
    sqlcmd = `SELECT user_role ` +
             `  FROM user_list ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      user_role = parseInt(data[0].user_role, 10);
    }
    else {
      throw new Error('Invalid user ID is given, so that user role cannot be determined.');
    }         
  }
  catch(e) {
    throw e;
  }
  
  return user_role;  
}


exports.showMessagePage = async function(msg_pool, sess_code) {
  let conn, user_id, user_role, wspath, private_group_marker, telegram_id_input, connect_mode, create_user_account, panel, js, html;
  let msgrp = [];
    
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    await extendSession(conn, sess_code);   // Extend session period 
    user_id = await getUserIdFromSession(conn, sess_code);
    user_role = await getUserRole(conn, user_id);
    msgrp = await msglib.getMessageGroup(conn, user_id);
    //-- Construct websocket access path from DNS of messaging site. It will --//
    //-- be in format "wss://<your messaging site>/ws".                      --//        
    wspath = await wev.getSiteDNS(conn, 'M');
    if (wspath != '') {
      wspath = wspath.replace('https', 'wss') + '/ws';
    }
    else {
      throw new Error('Unable to find DNS of messaging site');
    }

    //-- Define web page components based on system settings and user role --//
    private_group_marker = `<img src='/images/lock.png' height='15px'>`;    
    telegram_id_input = (await telecom.telegramBotDefined(conn))? `<li><a href="javascript:editTelegramId(${user_id});" data-ajax="false">Telegram ID</a></li>` : ``;
    connect_mode = parseInt(await wev.getSysSettingValue(conn, 'connection_mode'), 10);
    create_user_account = (connect_mode == 1 || connect_mode == 3)? `<li><a href="javascript:createMsgUser();" data-ajax="false">Create User</a></li>` : ``;

    if (user_role < 2) {
      //-- Note: As panel is opened, it will scroll page content to top. To stop this default behavior, we set data-position-fixed="true" and --//
      //--       define CSS ".ui-panel.ui-panel-open" and ".ui-panel-inner" to make the inner part of the panel contents scroll independent   --//
      //--       from the main content page and avoid dual scrolling. Details please refer to URL below:                                      --//
      //--       https://stackoverflow.com/questions/22672236/jquery-mobile-panel-open-scrolls-page-to-the-top-how-to-change-this#22675170    --//     
      panel = `
      <div data-role="panel" data-position-fixed="true" data-position="left" data-display="overlay" id="setup">
        <div data-role="main" class="ui-content">
          <ul data-role="listview">
            <li data-role="list-divider" style="color:darkgreen;">Maintain Your Profile</li>
            <li><a href="javascript:editAlias(${user_id});" data-ajax="false">Alias</a></li>
					  <li><a href="javascript:editEmail(${user_id});" data-ajax="false">Email</a></li>
            ${telegram_id_input}
            <li><a href="javascript:editHappyPasswd(${user_id});" data-ajax="false">Happy Password</a></li>
					  <li><a href="javascript:editUnhappyPasswd(${user_id});" data-ajax="false">Unhappy Password</a></li>
            <li data-role="list-divider" style="color:darkgreen;">Message Group</li>
            <li><a href="javascript:addGroup();" data-ajax="false">Add Group</a></li>
            <li><a href="javascript:addPrivateGroup();" data-ajax="false">Add Private Group</a></li>
				  </ul>	
			  </div>
      </div>`;
    }
    else {
      panel = `
      <div data-role="panel" data-position-fixed="true" data-position="left" data-display="overlay" id="setup">
        <div data-role="main" class="ui-content">
          <ul data-role="listview">
            <li data-role="list-divider" style="color:darkgreen;">Maintain Your Profile</li>
            <li><a href="javascript:editAlias(${user_id});" data-ajax="false">Alias</a></li>
					  <li><a href="javascript:editEmail(${user_id});" data-ajax="false">Email</a></li>
            ${telegram_id_input}
            <li><a href="javascript:editHappyPasswd(${user_id});" data-ajax="false">Happy Password</a></li>
					  <li><a href="javascript:editUnhappyPasswd(${user_id});" data-ajax="false">Unhappy Password</a></li>
            <li data-role="list-divider" style="color:darkgreen;">Message Group</li>
            <li><a href="javascript:addGroup();" data-ajax="false">Add Group</a></li>
            <li><a href="javascript:addPrivateGroup();" data-ajax="false">Add Private Group</a></li>
					  <li><a href="javascript:deleteGroupByAdmin();" data-ajax="false">Delete Group</a></li>
					  <li data-role="list-divider" style="color:darkgreen;">System Administration</li>
            ${create_user_account}
            <li><a href="javascript:promoteUser();" data-ajax="false">Promote User</a></li>
            <li><a href="javascript:demoteUser();" data-ajax="false">Demote User</a></li>
            <li><a href="javascript:lockUser();" data-ajax="false">Lock/Unlock User</a></li>
            <li><a href="javascript:systemSetup();" data-ajax="false">System Settings</a></li>
					  <li><a href="javascript:doomEntireSystem();" data-ajax="false">Destroy System</a></li>
				  </ul>	
			  </div>
      </div>`;
    }
    
    // Compress javascript code block //
    js = `
    var message_scheduler_id;
    var myWebSocket = null;
    var wsPingServer = null;
    var wsOpenSocket = null;   
    var wsCheckTimeout = null;
    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
    var user_id = ${user_id};
    var sess_code = "";
    var aes_key = '';
    var is_reopen = false;
    
    function connectWebServer() {
      var ws = new WebSocket("${wspath}");
    
      function ping() {
        var packet = {type: 'cmd', content: 'ping'};
        ws.send(JSON.stringify(packet));
      }
      
      function checkTimeout() {
        var packet = {type: 'cmd', content: 'check_timeout'};
        ws.send(JSON.stringify(packet));
      }
      
      function reopenWebSocket() {                                    
        is_reopen = true; 
        myWebSocket = connectWebServer();
      }
    
      ws.onopen = function(e) {
        //-- Once the websocket has been opened, stop the websocket openning scheduler (if it is activated). --//  
        if (wsOpenSocket != null) {clearTimeout(wsOpenSocket)};
        //-- By default, WebSocket connection of Nginx reverse proxy server will be disconnected on 60 seconds (i.e. Timeout), so we --//
        //-- need to send something to the server to keep the connection open within this time interval continuously.                --//
        wsPingServer = setInterval(ping, 50000);                 // Ping the server every 50 seconds                    
        wsCheckTimeout = setInterval(checkTimeout, 300000);      // Check session timeout every 5 minutes
        
        if (is_reopen) {                                        
          //-- Refresh page as websocket is reconnected --//      
          is_reopen = false;
          refreshPage();
        }
      }
      
      ws.onmessage = function(e) {
        var packet = JSON.parse(e.data);
        var type = packet.type;            // Possible values are 'cmd' (command) and 'msg' (message).
        var content = packet.content;      // Note: 'content' is highly possible an object, not just plain text.

        if (type == 'msg') {
          if (content.op == 'msg_refresh') {
            refreshPage();
          }
        }
        else { 
          processCommand(content);
        }
      }
      
      ws.onclose = function(e) {
        clearInterval(wsPingServer);
        //-- Reopen websocket automatically within 100ms --//
        wsOpenSocket = setTimeout(reopenWebSocket, 100);
      }
      
      ws.onerror = function(e) {
        console.log('Error: ' + e.message);
      }
      
      return ws;
    }  

    $(document).on("pageshow", function(event) {
      //-- Open a websocket --//
      myWebSocket = connectWebServer();                         
    });

    async function refreshPage() {
      await prepareRollingKey(${_key_len});
      let roll_rec = document.getElementById("roll_rec").value;
      let iv_roll_rec = document.getElementById("iv_roll_rec").value;
      let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
          
      $.ajax({
        type: 'POST',
        url: '/check_new_message_count',
        dataType: 'json',
        data: {
          user_id: ${user_id},
          roll_rec: roll_rec,
          iv_roll_rec: iv_roll_rec,
          roll_rec_sum: roll_rec_sum
        },
        success: function(ret_data) {
          if (ret_data.length == 1 && typeof(ret_data[0].cmd) == "string") {
            let cmd = ret_data[0].cmd;
            
            if (cmd == "force_logout") {
              logout();
            }
            else if (cmd == "sess_expired") {
              alert("Session expired!");
              logout();
            }
            else if (cmd == "sess_verify_fail") {
              alert("Unable to verify your session status, please login again.");
              logout();
            }
            else if (cmd == "no_cookie") {
              window.location.href = "/";
            }
          }   
          else {
            refreshMessageCount(ret_data);
          }
        },
        error: function(xhr, ajaxOptions, thrownError) {
          //alert("Unable to refresh message home page. Error " + xhr.status + ": " + thrownError);
        }
      });              
    }

    function refreshMessageCount(ret_data) {
      var private_group_marker = "<img src='/images/lock.png' height='15px'>";

      for (var i = 0; i < ret_data.length; i++) {
        var rec = ret_data[i];          
        var this_group_id = parseInt(rec.group_id, 10);
        var this_group_name = rec.group_name;
        var this_group_type = parseInt(rec.group_type, 10);
        var this_unread_cnt = parseInt(rec.unread_cnt, 10);
        var this_marker = (this_group_type == 1)? private_group_marker : ''; 

        //-- Update unread message counter shown --//
        $('#grp_' + this_group_id).html(this_marker + this_group_name + "<br><font size='2pt'>New message: " + this_unread_cnt + "</font>");          
      }      
    }
    
    function processCommand(command) {
      var cmd_op = command.op;
      
      switch (cmd_op) {
        case 'pong':
          break;
      
        case 'sess_code':
          sess_code = command.content.trim();
          
          //-- Check whether session AES key exist or not. If it doesn't exist, generate it --//
          //-- and push a copy to back-end server before load up messages.                  --//
          //-- Note: This situation is none ideal, but it is the last resort to handle this --//
          //--       situation.                                                             --//
          let this_promise = new Promise((resolve, reject) => { 
            let renew_aes_key = false;
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
            if (typeof(aes_key) != "string" ) {
              renew_aes_key = true;  
            }
            else {
              aes_key = aes_key.trim();
              if (aes_key.length < ${_key_len}) {
                //-- AES passphase is too weak --//
                renew_aes_key = true;
              }
            }
            
            if (renew_aes_key) {
              //-- 2023-12-01: After consider security issue, it is too risky to upload new AES passphase to the --//
              //--             server without protection. So, if local AES passphase is lost, it should force    --//
              //--             logout the user.                                                                  --//  
              reject('0');
            
              //*****************************************************************************************************
              //aes_key = generateTrueRandomStr('A', ${_key_len});              // Defined on crypto-lib.js
              //if (is_iOS) {
              //  Cookies.set("aes_key", aes_key, {expires: 1});
              //}
              //else {
              //  setLocalStoredItem("aes_key", aes_key);
              //}
              //
              //-- Note: This section should be further enhance later to use RSA key exchange to protect --//
              //--       the push AES key. The current implementation doesn't secure enough.             --//   
              //$.ajax({
              //  type: 'POST',
              //  url: '/push_aes_key',
              //  dataType: 'html',
              //  data: {user_id: user_id, aes_key: aes_key},
              //  success: function(ret_data) {
              //    let result = JSON.parse(ret_data);
              //    
              //    if (result.ok == '1') {
              //      resolve('1');
              //	  }
              //    else {
              //      console.log("Unable to push AES key to server. Error: " + result.msg);
              //      reject('0');
              //	  }
              //  },
              //  error: function(xhr, ajaxOptions, thrownError) {
              //    console.log("Unable to push AES key to server. Error " + xhr.status + ": " + thrownError);
              //    reject('0');
              //  }
              //});
              //***********************************************************************************************
            }
            else {
              resolve('1');
            }                  
          });
          
          this_promise.catch((error) => {
            let msg = "Secure key is lost, system is going to log you out. Please login again.";
            alert(msg);
            logout();							  
          });
          
          break;
          
        case 'timeout':
          if (command.content == 'YES') {
            logout();
          }
          break;  

        case 'group_deleted':
          //-- A message group has been deleted, refresh whole page. --//
          goMessagePage();
          break; 
          
        case 'force_logout':
          logout();
          break;  
          
        default:
          //-- do nothing --//   
      }                             
    }
    
    async function readGroupMessage(group_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("g_id").value = group_id;
        document.getElementById("main_page").action = "/do_sms";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }
    
    async function editAlias(user_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("u_id").value = user_id;
        document.getElementById("main_page").action = "/edit_alias";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }
    
    async function editEmail(user_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("u_id").value = user_id;
        document.getElementById("main_page").action = "/edit_email";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }    
    }

    async function editTelegramId(user_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("u_id").value = user_id;
        document.getElementById("main_page").action = "/edit_tg_id";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }        
    }
    
    async function editHappyPasswd(user_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("u_id").value = user_id;
        document.getElementById("main_page").action = "/edit_happy_passwd";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }            
    }

    async function editUnhappyPasswd(user_id) {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("u_id").value = user_id;
        document.getElementById("main_page").action = "/edit_unhappy_passwd";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                
    }
    
    async function addGroup() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/add_group";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                    
    }
    
    async function addPrivateGroup() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/add_private_group";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                        
    }
    
    async function createMsgUser() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/create_msg_user";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                                
    }
    
    async function deleteGroupByAdmin() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/delete_group_by_admin";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                            
    }
    
    async function promoteUser() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/promote_user";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                                
    }
    
    async function demoteUser() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/demote_user";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                                    
    }
    
    async function lockUser() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/lock_user";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                                        
    }
    
    async function systemSetup() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/system_setup";
        document.getElementById("main_page").submit();
      }
      catch(e) {
        alert(e.message);
      }                                            
    }
    
    async function goMessagePage() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("main_page").action = "/message";
        document.getElementById("main_page").submit();      
      }
      catch(e) {
        alert(e.message);
      }
    }

    function logout() {
      window.location.href = '/logout_msg';
    }

    async function doomEntireSystem() {
      //-- It will nuke the site and destroy all data, use it with great care. --//
      if (confirm("Do you really want to destroy entire system?")) {
        if (confirm("Last chance! Really want to go?")) {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById("main_page").action = "/destroy_entire_system";
            document.getElementById("main_page").submit();          
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
    }`;
    
    js = await wev.minifyJS(js);
    
    html = `<!doctype html>
            <html>
            <head>
              <title>Message</title>
              <meta name='viewport' content='width=device-width, initial-scale=1.0'>
              <meta http-equiv='Content-Type' content='text/html; charset=utf-8'> 

              <style>
                .ui-panel.ui-panel-open {
                  position:fixed;
                }
    
                .ui-panel-inner {
                  position: absolute;
                  top: 1px;
                  left: 0;
                  right: 0;
                  bottom: 0px;
                  overflow: scroll;
                  -webkit-overflow-scrolling: touch;
                }    
              </style>

              <link rel='stylesheet' href='/js/jquery.mobile-1.4.5.min.css'>
              <link rel='shortcut icon' href='/favicon.ico'>
              <script src='/js/jquery.min.js'></script>
              <script src='/js/jquery.mobile-1.4.5.min.js'></script>
				      <script src="/js/js.cookie.min.js"></script>  
				      <script src='/js/crypto-lib.js'></script>
				      <script src="/js/common_lib.js"></script>
            
              <script>
                ${js}
              </script>
            </head>
              
            <body>
	            <!-- 
              Important: 'data-ajax="false"' must be set for links with dynamic content. Otherwise, unexpected result such as invalid javascript 
                         content and expired passed parameters value will be obtained.                                                           
              -->
              <div data-role="page" id="mainpage">
                ${panel}

	              <div data-role="header" style="overflow:hidden;" data-position="fixed">
		              <a href="#setup" data-icon="bars" class="ui-btn-left">Setup</a>					
			            <h1>SMS 2.0</h1>
			            <a href="javascript:logout()" data-icon="power" class="ui-btn-right" data-ajax="false">Quit</a>					
		            </div>	

		            <div data-role="main" class="ui-body-d ui-content">
                  <form id="main_page" name="main_page" action="" method="POST">
                    <input type=hidden id="roll_rec", name="roll_rec", value="">
                    <input type=hidden id="iv_roll_rec", name="iv_roll_rec", value="">   
                    <input type=hidden id="roll_rec_sum", name="roll_rec_sum", value="">
                    <input type=hidden id="g_id", name="g_id", value="">
                    <input type=hidden id="u_id", name="u_id", value="">
                  </form>                  
                  
                `; 
     
    if (msgrp.length > 0) {
      for (let i = 0; i < msgrp.length; i++) {
        let group_id = msgrp[i].group_id; 
        let group_name = msgrp[i].group_name;
        let group_type = parseInt(msgrp[i].group_type, 10);
        let group_role = msgrp[i].group_role;
        let unread_cnt = parseInt(msgrp[i].unread_cnt, 10);
        //let this_link = `/do_sms?g_id=` + group_id;
        let this_marker = (group_type == 1)? private_group_marker : ``;
        
        //html += `<a href="` + this_link + `" id="grp_` + group_id + `" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">` + this_marker + group_name + `<br><font size="2pt">New message: ` + unread_cnt + `</font></a>`;     
        // Note: it will turn HTTP method of '/do_sms' from 'GET' to 'POST' //   
        html += `<a href="" onClick="readGroupMessage(${group_id});" id="grp_${group_id}" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">${this_marker}${group_name}<br><font size="2pt">New message: ${unread_cnt}</font></a>`;  
      }
      
      html += `</div>`;
    }
    else {
      html += `<p><a href="javascript:addGroup();" data-role="button" data-ajax="false">Add Group</a></p>
               <p><a href="javascript:addPrivateGroup();" data-role="button" data-ajax="false">Add Private Group</a></p>`;
    }           
                              
    html += `	  </div>
              </div>
            </body>
            </html>`;     
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getUserAlias(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT user_alias ` + 
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = data[0].user_alias;
    }
    else {
      throw new Error(`Unable to get alias of user ${user_id} by unknown reason`);
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.getProfileData = async function(msg_pool, user_id, sess_code, option) {
	let conn, data, algorithm, aes_key, enc_obj, enc_data, result;
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
		
		aes_key = await msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
		algorithm = "AES-GCM"
		
		if (option == "alias") {
		  data = await _getUserAlias(conn, user_id);			  
			enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, data);						
			result = {ok: '1', msg: '', algorithm: algorithm, iv: enc_obj.iv, data: enc_obj.encrypted};
		}
		else if (option == "email") {
			data = await _getUserEmail(conn, user_id);
			enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, data);
			result = {ok: '1', msg: '', algorithm: algorithm, iv: enc_obj.iv, data: enc_obj.encrypted};			
		}
		else if (option == "tg_id") {
			data = await _getUserTelegramId(conn, user_id);
			enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, data);
			result = {ok: '1', msg: '', algorithm: algorithm, iv: enc_obj.iv, data: enc_obj.encrypted};			
		}
		else {
			throw new Error(`Invalid option ${option} is given`); 
		}		
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return result;
}


async function _printUserProfileJavascriptSection(conn, sess_code, option) {
  let html;

  try {
    await extendSession(conn, sess_code);   // Extend session period 
  
	  html = `
	  <!doctype html>
	  <html>  
	  <head>
	    <title>${option}</title>
	    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
	    <meta http-equiv='Content-Type' content='text/html; charset=utf-8'> 
	  </head>
	    
		<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
		<link rel="shortcut icon" href="/favicon.ico">
		<script src="/js/jquery.min.js"></script>
		<script src="/js/jquery.mobile-1.4.5.min.js"></script>
		<script src="/js/js.cookie.min.js"></script>  
		<script src='/js/crypto-lib.js'></script>	  
	  <script src="/js/common_lib.js"></script>    
	  
	  <script>
	    var option = "${option}";
	    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
	    var algorithm = "AES-GCM";
	    var aes_key = "";
				        
	    async function showProfileDataInForm(option, algorithm, iv, enc_data) {
	      let data = "";
	    
	      try {
	        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
	        	        
	        if (option == "alias") {
	          data = await aesDecryptBase64(algorithm, aes_key, iv, enc_data);
	          $('#alias').val(data);
				  }
				  else if (option == "email") {
				    data = await aesDecryptBase64(algorithm, aes_key, iv, enc_data);
				    $('#email').val(data);
				  }
				  else if (option == "tg_id") {				  
            data = await aesDecryptBase64(algorithm, aes_key, iv, enc_data);				    
				    $('#tg_id').val(data);
				  }
          
          // Clear aes_key from RAM after used //
          aes_key = '';
			  }
			  catch(e) {
			    console.log(e);
			    alert("Error is found, operation is aborted. Error: " + e);
			    goHome();
			  }	    
		  }
	    	    
	    async function getUserProfileData(option) {
				var key_ready = true;
				aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
				if (typeof(aes_key) != "string") {
					key_ready = false;
			  }
			  else {
			    aes_key = aes_key.trim();
			    if (aes_key.length < ${_key_len}) {
			      key_ready = false;
				  }
			  }
										
				if (!key_ready) {
					alert("Secure key is lost, operation is aborted.");
          goHome(); 
			  }
			  else {
          await prepareRollingKey(${_key_len});
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
        					
			    if (option == "alias" || option == "email" || option == "tg_id") {	
						//-- Note: Due to asynchronous nature of javascript execution, it needs to use a  --//
						//--       promise to ensure the data is received from the server before the form --//
						//--       is displayed.                                                          --//                      
						let this_promise = new Promise((resolve, reject) => {                  			          
					    $.ajax({
					      type: 'POST',
					      url: '/get_profile_data',
					      dataType: 'html',
					      data: {
                  option: option, 
                  roll_rec: roll_rec,
                  iv_roll_rec: iv_roll_rec,
                  roll_rec_sum: roll_rec_sum
                },
					      success: function(ret_data) {
					        let result = JSON.parse(ret_data);
                  
					        if (result.ok == '1') {						
					          resolve(result);         // Note: 'result.data' is encrypted by 'aes_key' on server side.
								  }
					        else {
					          let err_msg = "";
                    
                    if (result.msg == "session_expired" || result.msg == "session_check_failure" || result.msg == "invalid_session") {
                      err_msg = result.msg;
                    }
                    else {
                      err_msg = "Unable to get data. Error: " + result.msg;
                    } 
                    
					          console.log(err_msg);   
					          reject(new Error(err_msg));
								  }
							  },
							  error: function(xhr, ajaxOptions, thrownError) {
							    let err_msg = "Unable to get data. Error " + xhr.status + ": " + thrownError
							    console.log(err_msg);
		              reject(new Error(err_msg));
		            }
						  });
					  });
					  
					  this_promise.then((rec) => {
							showProfileDataInForm(option, rec.algorithm, rec.iv, rec.data);
					  }).catch((error) => {            
              if (error.message.match(/session_expired/g)) {
                alert("Session expired!");
                window.location.href = "/logout_msg";
              } 
              else if (error.message.match(/session_check_failure/g)) {
                alert("Session checking failure, please login again.");
                window.location.href = "/logout_msg";
              } 
              else if (error.message.match(/invalid_session/g)) {
                window.location.href = "/";
              }
              else {
					      alert(error.message);
					      goHome();
              }							  
					  });
				  }
				}	    
		  }
	    
			$(document).on("pageshow", function(event) {          
				getUserProfileData(option);
			});	    
	    	    	    	    
	    async function saveAlias() {
	      let new_alias = $('#alias').val();
	      
	      if (new_alias.trim() == '') {
	        alert("Alias should not be blank");
	        document.getElementById("alias").focus();
	      } 
	      else {
          try {
            let key_ready = true;
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
            if (typeof(aes_key) != "string") {
              key_ready = false;
            }
            else {
              aes_key = aes_key.trim();
              if (aes_key.length < ${_key_len}) {
                key_ready = false;
              }
            }
            
            if (key_ready) {	        
              let enc_obj = await aesEncryptJSON(algorithm, aes_key, new_alias);		        
              $('#algorithm').val(algorithm);
              $('#iv').val(enc_obj.iv);
              $('#e_alias').val(enc_obj.encrypted);
              $('#alias').val('');
            
              // Clear aes_key from RAM after used //
              aes_key = null;

              await prepareRollingKey(${_key_len});            
              document.getElementById("oper_mode").value = 'S';
              document.getElementById("frmEditProfile").action = '/confirm_edit_alias';
              document.getElementById("frmEditProfile").submit();
            }
            else {
              alert("Secure key is lost, operation is aborted");
              goHome();
            }
          }
          catch(e) {
            alert(e.message);
          }
	      }
	    }
	    
	    async function saveEmail() {
	      let this_email = $('#email').val();        
	      
	      if (this_email.trim() == "") {
	        alert("Email is a compulsory data which must be given");
	        document.getElementById("email").focus();
	      }
	      else {
          try {
            let key_ready = true;
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
            if (typeof(aes_key) != "string") {
              key_ready = false;
            }
            else {
              aes_key = aes_key.trim();
              if (aes_key.length < ${_key_len}) {
                key_ready = false;
              }
            }
            
            if (key_ready) {	        
              let enc_obj = await aesEncryptJSON(algorithm, aes_key, this_email);		        
              $('#algorithm').val(algorithm);
              $('#iv').val(enc_obj.iv);
              $('#e_email').val(enc_obj.encrypted);
              $('#email').val('');
  
              // Clear aes_key from RAM after used //
              aes_key = null;
              
              await prepareRollingKey(${_key_len});    
              document.getElementById("oper_mode").value = 'S';
              document.getElementById("frmEditProfile").action = '/confirm_edit_email';
              document.getElementById("frmEditProfile").submit();
            }
            else {
              alert("Secure key is lost, operation is aborted");
              goHome();				  
            }    
          }
          catch(e) {
            alert(e.message);
          }    
	      }
	    }
	    
	    async function saveHappyPasswd() {
	      let this_passwd = allTrim(document.getElementById("happy_passwd").value);
	      let this_passwd_rt = allTrim(document.getElementById("happy_passwd_rt").value);
	      
	      if (this_passwd.length < 8) {
	        alert("Password length is too short");
	        document.getElementById("happy_passwd").focus();
	        return false;
	      }
	      
	      if (this_passwd != this_passwd_rt) {
	        alert("New happy password is not match, try again");
	        document.getElementById("happy_passwd").focus();
	        return false;
	      }
	      else {
          try {
            let key_ready = true;
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
            if (typeof(aes_key) != "string") {
              key_ready = false;
            }
            else {
              aes_key = aes_key.trim();
              if (aes_key.length < ${_key_len}) {
                key_ready = false;
              }
            }
            
            if (key_ready) {	        
              let enc_obj = await aesEncryptJSON(algorithm, aes_key, this_passwd);		        
              $('#algorithm').val(algorithm);
              $('#iv').val(enc_obj.iv);
              $('#e_happy_passwd').val(enc_obj.encrypted);
              $('#happy_passwd').val('');
              $('#happy_passwd_rt').val('');
  
              // Clear aes_key from RAM after used //
              aes_key = null;
            
              await prepareRollingKey(${_key_len});
              document.getElementById("oper_mode").value = 'S';
              document.getElementById("frmEditProfile").action = "/confirm_edit_happy_passwd";
              document.getElementById("frmEditProfile").submit();   
            }
            else {
              alert("Secure key is lost, operation is aborted");
              goHome();				  				  
            }    
          }
          catch(e) {
            alert(e.message);
          }         
	      }      
	    }
	    
	    async function saveUnhappyPasswd() {
	      let this_passwd = allTrim(document.getElementById("unhappy_passwd").value);
	      let this_passwd_rt = allTrim(document.getElementById("unhappy_passwd_rt").value);
	      
	      if (this_passwd.length < 8) {
	        alert("Password length is too short");
	        document.getElementById("unhappy_passwd").focus();
	        return false;
	      }
	      
	      if (this_passwd != this_passwd_rt) {
	        alert("New unhappy password is not match, try again");
	        document.getElementById("unhappy_passwd").focus();
	        return false;
	      }
	      else {
          try {
            let key_ready = true;
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
            if (typeof(aes_key) != "string") {
              key_ready = false;
            }
            else {
              aes_key = aes_key.trim();
              if (aes_key.length < ${_key_len}) {
                key_ready = false;
              }
            }
            
            if (key_ready) {	        
              let enc_obj = await aesEncryptJSON(algorithm, aes_key, this_passwd);		        
              $('#algorithm').val(algorithm);
              $('#iv').val(enc_obj.iv);
              $('#e_unhappy_passwd').val(enc_obj.encrypted);
              $('#unhappy_passwd').val('');
              $('#unhappy_passwd_rt').val('');
  
              // Clear aes_key from RAM after used //
              aes_key = null;
              
              await prepareRollingKey(${_key_len});    
              document.getElementById("oper_mode").value = 'S';
              document.getElementById("frmEditProfile").action = "/confirm_edit_unhappy_passwd";
              document.getElementById("frmEditProfile").submit();   
            }
            else {
              alert("Secure key is lost, operation is aborted");
              goHome();				  				  
            }    
          }
          catch(e) {
            alert(e.message);
          }         
	      }            
	    }
	    
	    async function saveTelegramID() {
	      let this_tg_id = allTrim(document.getElementById("tg_id").value);
	      let ok = true;
	      
	      if (this_tg_id != "") {
	        if (isNaN(this_tg_id)) {
	          alert("Telegram ID is a numeric data.");
	          document.getElementById("tg_id").focus();
	          ok = false;
	        }
	      }
	
	      if (ok) {
	        let key_ready = true;
	        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
	        if (typeof(aes_key) != "string") {
	          key_ready = false;
				  }
				  else {
				    aes_key = aes_key.trim();
				    if (aes_key.length < ${_key_len}) {
				      key_ready = false;
						}
				  }
	        
	        if (key_ready) {	        
		        let enc_obj = await aesEncryptJSON(algorithm, aes_key, this_tg_id);		        
		        $('#algorithm').val(algorithm);
		        $('#iv').val(enc_obj.iv);
		        $('#e_tg_id').val(enc_obj.encrypted);
		        $('#tg_id').val('');

            // Clear aes_key from RAM after used //
            aes_key = null;
		        
            await prepareRollingKey(${_key_len});    
		        document.getElementById("oper_mode").value = 'S';
		        document.getElementById("frmEditProfile").action = '/confirm_edit_tg_id';
		        document.getElementById("frmEditProfile").submit();
				  }
				  else {
				    alert("Secure key is lost, operation is aborted");
				    goHome();				  				  
				  }        
	      }      
	    }
      
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frmEditProfile").action = '/message';
          document.getElementById("frmEditProfile").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
	  </script>    
	  `;
  }
  catch(e) {
		throw e;
	}

  return html;    
}


function _editUserAliasForm(user_id) {
  var html;
  
  html = `
  <form id="frmEditProfile" name="frmEditProfile" action="" method="post">
  <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
  <input type=hidden id="iv" name="iv" value="">
  <input type=hidden id="e_alias" name="e_alias" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">    
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page" id="config_page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Alias</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="alias">Alias:</label>
      <input type="text" id="alias" name="alias" value="" maxlength=64>
      <br>
      <a href="#" data-role="button" id="save" onClick="saveAlias();">Save</a>
    </div>
  </div>
  </form>  
  `;
  
  return html;
}


exports.printEditAliasForm = async function(msg_pool, user_id, sess_code) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));   
    html = await _printUserProfileJavascriptSection(conn, sess_code, 'alias');
    html += _editUserAliasForm(user_id);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}
 

async function _getUserEmail(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT email ` + 
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = data[0].email;
    }
    else {
      throw new Error(`Unable to get email of user ${user_id} by unknown reason`);
    }          
  }
  catch(e) {
    throw e;    
  }
  
  return result;
}


function _editEmailForm(user_id) {
  var html;
  
  html = `
  <form id="frmEditProfile" name="frmEditProfile" action="" method="post">
  <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
  <input type=hidden id="iv" name="iv" value="">  
  <input type=hidden id="e_email" name="e_email" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">    
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
  
  <div data-role="page" id="config_page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Email</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="email">Email:</label>
      <input type="email" id="email" name="email" value="" maxlength=256>
      <br>
      <a href="#" data-role="button" id="save" onClick="saveEmail();">Save</a>
    </div>
  </div>
  </form>  
  `;
  
  return html;  
}


exports.printEditEmailForm = async function(msg_pool, user_id, sess_code) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = await _printUserProfileJavascriptSection(conn, sess_code, "email");
    html += _editEmailForm(user_id);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getUserTelegramId(conn, user_id) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT tg_id ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = wev.allTrim(data[0].tg_id);
    }
    else {
      throw new Error('Unable to get Telegram ID with unknown reason');
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function _editTelegramIdForm(user_id, tg_bot, client_device_info) {
  var bot_link, warning_html, bot_add_html, html;
    
  if (client_device_info.os.name != 'iOS' && client_device_info.os.name != 'Android') {
    warning_html = `
    <font color='red'><b>Warning:</b> This process must be setup on smart devices, such as smartphone or tablet, which support Telegram.</font>
    <br>
    <br>
    `;
  }
  else {
    warning_html = '';
  }
  
  if (tg_bot.bot_username != '') {
    bot_link = `https://t.me/${tg_bot.bot_username}`;
    
    bot_add_html = `
    <b>Step 1: Add SMS notification bot to your Telegram app.</b>
    <br>
    Click 'Add SMS notification bot' => Click Send Message => Click Start
    <br>
    <a href="${bot_link}">Add SMS notification bot</a>
    <br>
    <br>    
    `;    
  }
  else {
    bot_add_html = `
    It seems that Telegram notification bot doesn't exist,
    please go to next step directly. However, Telegram notification
    is not possible as notification bot doesn't exist. Please report
    this issue to system administrator.
    <br>
    <br>    
    `;    
  }
    
  html = `
  <form id="frmEditProfile" name="frmEditProfile" action="" method="post">
  <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
  <input type=hidden id="iv" name="iv" value="">  
  <input type=hidden id="e_tg_id" name="e_tg_id" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">   
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
     
  <div data-role="page" id="config_page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Telegram ID</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      ${warning_html}
      Here is setup for the system to notify you new message via Telegram.
      <br>
      <br>    
  `;
  
  html += bot_add_html;
  
  html += `
      <b>Step 2: Get and input your Telegram ID.</b>
      <br>
      Click 'Check my Telegram ID' => Click Send Message => Click Start to get
      your Telegram ID, then input your Telegram ID to the field below, and save it.
      <br>
      <a href="https://telegram.me/userinfobot">Check my Telegram ID</a>
      <br>
      <br>      
      <label for="tg_id">Telegram ID:</label>
      <input type="text" id="tg_id" name="tg_id" value="" maxlength=128>
      <br>
      <a href="#" data-role="button" id="save" onClick="saveTelegramID();">Save</a>
    </div>
  </div>
  </form>        
  `;
  
  return html;
}


exports.printEditTelegramIdForm = async function(msg_pool, user_id, sess_code, client_device_info) {
  var conn, tg_bot, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    tg_bot = await telecom.getTelegramBotProfile(conn);
    
    html = await _printUserProfileJavascriptSection(conn, sess_code, "tg_id");;
    html += _editTelegramIdForm(user_id, tg_bot, client_device_info);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


function _editHappyPasswdForm(user_id) {
  var html;
  
  html = `
  <form id="frmEditProfile" name="frmEditProfile" action="" method="post">
  <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
  <input type=hidden id="iv" name="iv" value="">  
  <input type=hidden id="e_happy_passwd" name="e_happy_passwd" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">    
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page" id="config_page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Happy Password</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="happy_passwd">New Happy Password (8 characters or more):</label>
      <input type="password" id="happy_passwd" name="happy_passwd" maxlength=256>
      <label for="happy_passwd_rt">Retype New Happy Password:</label>
      <input type="password" id="happy_passwd_rt" name="happy_passwd_rt" maxlength=256>    
      <br>
      <a href="#" data-role="button" id="save" onClick="saveHappyPasswd();">Save</a>
    </div>
  </div>
  </form>    
  `;
  
  return html;
}


exports.printEditHappyPasswdForm = async function(msg_pool, user_id, sess_code) {
  var conn, html;
  
  try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
    html = await _printUserProfileJavascriptSection(conn, sess_code, "happy_passwd");
    html += _editHappyPasswdForm(user_id);        
  }
  catch(e) {
    throw e;
  }
  finally {
		dbs.releasePoolConn(conn);
	}
  
  return html;
}


function _editUnhappyPasswdForm(user_id) {
  var html;
  
  html = `
  <form id="frmEditProfile" name="frmEditProfile" action="" method="post">
  <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
  <input type=hidden id="iv" name="iv" value="">  
  <input type=hidden id="e_unhappy_passwd" name="e_unhappy_passwd" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value=""> 
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">     
  
  <div data-role="page" id="config_page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Unhappy Password</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="unhappy_passwd">New Unhappy Password (8 characters or more):</label>
      <input type="password" id="unhappy_passwd" name="unhappy_passwd" maxlength=256>
      <label for="unhappy_passwd_rt">Retype New Unhappy Password:</label>
      <input type="password" id="unhappy_passwd_rt" name="unhappy_passwd_rt" maxlength=256>    
      <br>
      <a href="#" data-role="button" id="save" onClick="saveUnhappyPasswd();">Save</a>
    </div>
  </div>
  </form>    
  `;
  
  return html;  
}


exports.printEditUnhappyPasswdForm = async function(msg_pool, user_id, sess_code) {
  var conn, html;
  
  try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
    html = await _printUserProfileJavascriptSection(conn, sess_code, "unhappy_passwd");
    html += _editUnhappyPasswdForm(user_id);        
  }
  catch(e) {
    throw e;
  }
  finally {
		dbs.releasePoolConn(conn);
	}
  
  return html;  
}


function _printAddGroupJavascriptSection(sess_code) {
  var html;
  
  html = `
	<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
	<link rel="shortcut icon" href="/favicon.ico">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/jquery.mobile-1.4.5.min.js"></script>
  <script src="/js/crypto-lib.js"></script>
  <script src="/js/common_lib.js"></script>    

  <script>
    var idx = 0;
   
    $(document).on("pagecreate", function() {
      for (i = 1; i <= 5; i++) {
        addMember(); 
      }    
    });
        
    function addMember() {
      idx++;
      
      $("#member_section").each(
        function() {
          var id = "member_" + idx;
          var row = "<tr id='row_" + idx + "'><td><input type='text' id='" + id + "' name='" + id + "'/></td></tr>";
          //-- Note: jQuery mobile API function ".enhanceWithin()" will apply default CSS settings to dynamically added objects --//
          $(this).append(row).enhanceWithin();
        }
      );      
    }
        
    function deleteMember() {
      if (idx > 1) {
        $("#row_" + idx).remove();
        idx--;
      }
    }
    
    async function createGroup() {
      if (dataSetOk()) {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frmAddGrp").action = "/confirm_add_group";
          document.getElementById("frmAddGrp").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    }
    
    function dataSetOk() {
      var this_group_name = allTrim(document.getElementById("group_name").value);
      if (this_group_name == "") {
        alert("Group name is compulsory");
        document.getElementById("group_name").focus();
        return false;
      }

      //-- Note: As checkbox object 'auto_delete' is unchecked, it's value will not passed to the server as form is submitted. --//
      //--       Therefore, we need another variable 'msg_auto_delete' to pass data to the back-end.                           --//
      var is_checked = document.getElementById("auto_delete").checked;
      if (is_checked) {
        document.getElementById("msg_auto_delete").value = 1;
      }
      else {
        document.getElementById("msg_auto_delete").value = 0;
      }
      
      var count = 0;    
      for (i = 1; i <= idx; i++) {
        if (document.getElementById("member_" + i) != null) {
          var member = allTrim(document.getElementById("member_" + i).value);
          if (member != "") {
            count++;  
          }
        }
      }
      
      if (count == 0) {
        alert("You should invite at least one person to create a message group");
        return false;
      }
      
      return true;
    }
    
    async function goHome() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("frmAddGrp").action = '/message';
        document.getElementById("frmAddGrp").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }    
  </script>  
  `;
  
  return html; 
}


function _printAddGroupForm(user_id, group_name) {
  var html;
  
  html = `
  <form id="frmAddGrp" name="frmAddGrp" action="" method="post">
  <input type=hidden id="oper_mode" name="oper_mode" value="">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="msg_auto_delete" name="msg_auto_delete" value="">
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Add Group</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="group_name">Group name:</label>
      <input type="text" id="group_name" name="group_name" value="${group_name}">

      <label for="auto_delete" style="width:60%; display:inline">Clear messages periodically:</label>
      <input type="checkbox" data-role="flipswitch" id="auto_delete" name="auto_delete" value="" checked>
      
      <table id="member_section" width=100% cellpadding=0 cellspacing=0>
      <thead>
        <tr><td>Who will be invited (alias):</td></tr>
      </thead>
      <tbody>
        <!-- Rows will be added dynamically //-->
      </tbody>  
      </table>
            
      <table width=100%>
      <thead><tr><td colspan=3></td></tr></thead>
      <tbody>
      <tr>  
        <td align=left width=35%><a href="#" data-icon="plus" data-role="button" data-ajax="false" onClick="addMember();">More</a></td>
        <td></td>
        <td align=right width=35%><a href="#" data-icon="minus" data-role="button" data-ajax="false" onClick="deleteMember();">Less</a></td>
      </tr>
      </tbody>
      </table>
      
      <br>
      <input type="button" id="save" name="save" value="Create" onClick="createGroup();">            
    </div>
  </div>  
  </form>    
  `;
  
  return html;
}


exports.printAddGroupForm = async function(user_id, group_name, sess_code) {
  var html;
  
  try {
    html = wev.printHeader('Add Group');
    html += _printAddGroupJavascriptSection(sess_code);
    html += _printAddGroupForm(user_id, group_name);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printAddPrivateGroupJavascriptSection(sess_code) {
  var html;
  
  html = `
	<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
	<link rel="shortcut icon" href="/favicon.ico">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/jquery.mobile-1.4.5.min.js"></script>
  <script src="/js/common_lib.js"></script>
  <script src="/js/crypto-lib.js"></script>    

  <script>
    $(document).on("pagecreate", function() {
      $("#group_name").focus();
      $("#input_grp").show();
    });
    
    //-- Define event handler of checkbox 'auto_delete' --//
    $(function() {
      $("#auto_delete").on('change', function() {
        if (this.checked) {
          $("#input_grp").show();
        }
        else {
          $("#input_grp").hide();
        }
      })      
    });    

    async function createGroup() {
      try {
        let this_group_name = allTrim(document.getElementById("group_name").value);
        if (this_group_name == "") {
          alert("Group name is compulsory");
          document.getElementById("group_name").focus();
          return false;
        }
        
        let this_member = allTrim(document.getElementById("member").value);
        if (this_member == "") {
          alert("Person to be invited is compulsory");
          document.getElementById("member").focus();
          return false;        
        }
        
        let is_checked = document.getElementById("auto_delete").checked;
        if (is_checked == false) {
          document.getElementById("auto_delete").value = 0;
          document.getElementById("delete_after").value = 0;
        }
        else {
          document.getElementById("auto_delete").value = 1;
          let da = parseInt(document.getElementById("delete_after").value, 10);
          if (isNaN(da) || (da < 1 || da > 30)) {
            document.getElementById("delete_after").value = 1;
          }
        }

        await prepareRollingKey(${_key_len});        
        document.getElementById("oper_mode").value = "S";
        document.getElementById("frmAddPgrp").action = "/confirm_add_private_group";
        document.getElementById("frmAddPgrp").submit();
      }
      catch(e) {
        alert(e.message);
        return false;
      }
    }    
    
    async function goHome() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("frmAddPgrp").action = '/message';
        document.getElementById("frmAddPgrp").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }        
  </script>  
  `;
  
  return html;
}


function _printAddPrivateGroupForm(user_id, group_name, auto_delete, member) {
  var html, checked;
  
  checked = (auto_delete == 1)? 'checked' : '';
  
  html = `
  <form id="frmAddPgrp" name="frmAddPgrp" action="" method="post">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Add Private Group</h1>
    </div>
    
    <div data-role="main" class="ui-content">
      <label for="group_name">Group name:</label>
      <input type="text" id="group_name" name="group_name" value="${group_name}">
      <label for="member">Who is invited (alias):</label>      
      <input type="text" id="member" name="member" value="${member}">
      <label for="auto_delete">Auto delete read message:</label>
      <input type="checkbox" data-role="flipswitch" id="auto_delete" name="auto_delete" value="${auto_delete}" ${checked}>
      <br>
      <div id="input_grp">
        <label for="delete_after" id="lbl_delete_after">Delete after read (minute):</label>
        <input type="range" id="delete_after" name="delete_after" value="1" min="1" max="30">
      </div>
      <br>
      <input type="button" id="save" name="save" value="Create" onClick="createGroup();">
    </div>
  </div>  
  </form>  
  `;
  
  return html;
}


exports.printAddPrivateGroupForm = async function(user_id, group_name, auto_delete, member, sess_code) {
  let html;
  
  try {
    html = wev.printHeader('Add Private Group');
    html += _printAddPrivateGroupJavascriptSection(sess_code);
    html += _printAddPrivateGroupForm(user_id, group_name, auto_delete, member);
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


function _printDeleteGroupByAdminJavascriptSection() {
  let html;
  
  html = `
	<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
	<link rel="shortcut icon" href="/favicon.ico">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/jquery.mobile-1.4.5.min.js"></script>
  <script src="/js/common_lib.js"></script>    
  <script src="/js/crypto-lib.js"></script>

  <script>
    async function deleteGroups(cnt) {
      var select_cnt = 0;
    
      for (idx = 1; idx <= cnt; idx++) {
        if (document.getElementById("group_id_" + idx).checked) {
          select_cnt++;
        }
      }
      
      if (select_cnt == 0) {
        alert("You must select at least one message group to proceed");
        return false;
      }
      else {
        var question = '';
        
        if (select_cnt == 1) {
          question = "Are you sure to delete selected message group?";
        }
        else {
          question = "Are you sure to delete selected message groups?";
        }
        
        if (confirm(question)) {
          await prepareRollingKey(${_key_len});
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frm_delete_group").action = '/confirm_delete_group_by_admin';
          document.getElementById("frm_delete_group").submit();
        }
      }      
    }    
    
    async function goHome() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("frm_delete_group").action = '/message';
        document.getElementById("frm_delete_group").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }            
  </script>  
  `;
  
  return html;
}


function _printDeleteGroupByAdminForm(user_id, groups) {
  let html, cnt;
  
  html = `
  <form id="frm_delete_group" name="frm_delete_group" action="" method="post">
  <input type=hidden id="u_id" name="u_id" value="${user_id}">
  <input type=hidden id="oper_mode" name="oper_mode" value="">
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page">
    <div data-role="header" style="overflow:hidden;" data-position="fixed">  
			<a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
			<h1>Delete Group</h1>
    </div>
  
    <div data-role="main" class="ui-content">
      <b>Select group(s) to delete:</b>
      <br>
      <table width=100% cellpadding=1 cellspacing=1>
      <thead>
        <tr><td></td></tr>
      </thead>
      <tbody>          
  `;

  cnt = 0;
  for (let i = 0; i < groups.length; i++) {
    let this_group_id = groups[i].group_id;
    let this_group_name = groups[i].group_name;
    
    cnt++;
    html += `
    <tr style="background-color:lightyellow">
      <td>
        <input type="checkbox" id="group_id_${cnt}" name="group_id_${cnt}" value="${this_group_id}"><label for="group_id_${cnt}">${this_group_name} (id: ${this_group_id})</label>
      </td>
    </tr>    
    `;  
  }
  
  if (cnt > 0) {
    html += `
        </tbody>  
        </table>
      </div>  
      
      <div data-role="footer" data-position="fixed">
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr><td></td></tr>
        </thead>
        <tbody>        
          <tr><td align=center><input type="button" id="save" name="save" value="Delete" onClick="deleteGroups(${cnt});"></td></tr>
        </tbody>  
      </div>  
    </div>
    </form>    
    `;
  }
  else {
    html += `
        <tr style="background-color:lightyellow">
          <td>No message group is available to be deleted</td>
        </tr>
        </tbody>  
        </table>
      </div>  
    </div> 
    </form>   
    `;
  }
  
  return html;
}


exports.printDeleteGroupByAdminForm = async function(msg_pool, user_id) {
  let conn, html;
  let groups = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    groups = await msglib.getAllMessageGroups(conn);
            
    html = wev.printHeader('Delete Group By Admin');
    html += _printDeleteGroupByAdminJavascriptSection();
    html += _printDeleteGroupByAdminForm(user_id, groups);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
} 


function _printCreateUserJavascriptSesction() {
  let html;
  
  html = `
	<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
	<link rel="shortcut icon" href="/favicon.ico">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/jquery.mobile-1.4.5.min.js"></script>
	<script src="/js/js.cookie.min.js"></script>  
  <script src="/js/crypto-lib.js"></script>
  <script src="/js/common_lib.js"></script>
  
  <script>
    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
    var algorithm = "AES-GCM";
    var aes_key = "";
    var enc_obj;
  
    async function goCreateUserAccount() {
      if (dataSetValid()) {
        var key_ready = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
        if (typeof(aes_key) != "string") {
          key_ready = false;
        }
        else {
          aes_key = aes_key.trim();
          if (aes_key.length < ${_key_len}) {
            key_ready = false;
				  }
        }
                
        if (key_ready) { 
          try {      
            //-- Generate new rolling key --//
            await prepareRollingKey(${_key_len});
          
            //-- Encrypt data before send to the back-end server --//
            $('#algorithm').val(algorithm);
             
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#name').val());
            $('#iv_name').val(enc_obj.iv);
            $('#e_name').val(enc_obj.encrypted);
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#user').val());
            $('#iv_user').val(enc_obj.iv);
            $('#e_user').val(enc_obj.encrypted);
  
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#alias').val());
            $('#iv_alias').val(enc_obj.iv);
            $('#e_alias').val(enc_obj.encrypted);
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#email').val());
            $('#iv_email').val(enc_obj.iv);
            $('#e_email').val(enc_obj.encrypted);
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#happy_passwd1').val());
            $('#iv_happy_passwd').val(enc_obj.iv);
            $('#e_happy_passwd').val(enc_obj.encrypted);
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, $('#unhappy_passwd1').val());
            $('#iv_unhappy_passwd').val(enc_obj.iv);
            $('#e_unhappy_passwd').val(enc_obj.encrypted);
  
            // Clear aes_key from RAM after used //
            aes_key = null;
                      
            //-- Remove content of all clear text data --//
            $('#name').val('');
            $('#user').val('');
            $('#alias').val('');
            $('#email').val('');
            $('#happy_passwd1').val('');
            $('#happy_passwd2').val('');
            $('#unhappy_passwd1').val('');
            $('#unhappy_passwd2').val('');
          
            //-- Note: DON'T use JQuery '$' symbol to refer the form 'frm_add_user'. Otherwise, abnormal behavior  --//
            //--       will be obtained after form is submitted. The weird behavior is that the form seems to be   --//
            //--       submitted successfully, i.e. The back-end server receive all the emitted data successfully, --//
            //--       however, the web browser still stuck on the form before submission. Therefore, it can't     --//
            //--       response the resultant web page return from the server. The cause of this issue is still    --//
            //--       unknown, and it seems to relate to back-end technology used. It is OK if Perl CGI is used   --//
            //--       on the back-end server, but it has problem if back-end server use Express.js.               --//  
            //--                                                                                                   --//
            //--       Finally, the reason of the above problem is found. It is due to the old jQuery library, it  --//
            //--       is too old to understand 'async/await' syntax, and so the error.                            --//            
            document.getElementById("oper_mode").value = 'S';
            document.getElementById("frm_add_user").action = '/confirm_create_msg_user';
            document.getElementById("frm_add_user").submit();
          }
          catch(e) {
            alert(e.message);
          }         
			  }
			  else {
			    alert("Secure key is lost, operation cannot proceed.");
			    goHome();
			  }       
      }
    }
    
    function dataSetValid() {
      var name = allTrim($('#name').val());
      var user = allTrim($("#user").val());
      var alias = allTrim($("#alias").val());
      var happy_pw1 = $("#happy_passwd1").val();
      var happy_pw2 = $("#happy_passwd2").val();
      var unhappy_pw1 = $("#unhappy_passwd1").val();
      var unhappy_pw2 = $("#unhappy_passwd2").val();

      if (name == "") {
        alert("User's name is compulsory");
        $('#name').focus();
        return false;
      }

      if (user == "") {
        alert("Login username is compulsory");
        $('#user').focus();
        return false;
      }
      
      if (alias == "") {
        alert("Alias is compulsory");
        $('#alias').focus();
        return false;        
      }
      
      if (happy_pw1.length < 8) {
        alert("Happy password must contain 8 characters or more");
        $('#happy_passwd1').focus();
        return false;
      }
      else {
        if (happy_pw1 != happy_pw2) {
          alert("Happy password is not match");
          $('#happy_passwd2').focus();
          return false;
        }
      }
            
      if (unhappy_pw1.length < 8) {
        alert("Unhappy password must contain 8 characters or more");
        $('#unhappy_passwd1').focus();
        return false;
      }
      else {
        if (unhappy_pw1 != unhappy_pw2) {
          alert("Unhappy password is not match");
          $('#unhappy_passwd2').focus();
          return false;
        }
      }
      
      if (happy_pw1 == unhappy_pw1) {
        alert("Happy password must be different from unhappy password");
        $('#happy_passwd1').focus();
        return false;        
      }
            
      return true;
    }
    
    async function goHome() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("frm_add_user").action = '/message';
        document.getElementById("frm_add_user").submit();                 
      }
      catch(e) {
        alert(e.message);
      }
    }
    
    async function goCreateUser() {
      try {
        await prepareRollingKey(${_key_len});
        document.getElementById("frm_add_user").action = '/create_msg_user';
        document.getElementById("frm_add_user").submit();                 
      }
      catch(e) {
        alert(e.message);
      }    
    }
  </script>  
  `;
  
  return html;
}


function _printCreateUserForm() {
  let red_dot, html;
  
  red_dot = "<font color='red'>*</font>";
  
  html = `
  <form id="frm_add_user" name="frm_add_user" action="" method="post">
  <input type=hidden id="oper_mode" name="oper_mode" value="">
  <input type=hidden id="algorithm" name="algorithm" value="">
  <input type=hidden id="iv_name" name="iv_name" value="">  
  <input type=hidden id="e_name" name="e_name" value="">
  <input type=hidden id="iv_user" name="iv_user" value="">
  <input type=hidden id="e_user" name="e_user" value="">
  <input type=hidden id="iv_alias" name="iv_alias" value="">
  <input type=hidden id="e_alias" name="e_alias" value="">
  <input type=hidden id="iv_email" name="iv_email" value="">
  <input type=hidden id="e_email" name="e_email" value="">
  <input type=hidden id="iv_happy_passwd" name="iv_happy_passwd" value="">
  <input type=hidden id="e_happy_passwd" name="e_happy_passwd" value="">
  <input type=hidden id="iv_unhappy_passwd" name="iv_unhappy_passwd" value="">
  <input type=hidden id="e_unhappy_passwd" name="e_unhappy_passwd" value="">
  <input type=hidden id="roll_rec" name="roll_rec" value="">
  <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
  <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
  <div data-role="page">
    <div data-role="header" data-position="fixed" data-tap-toggle="false">
      <a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
      <h1>Create User</h1>
    </div>
    
    <div data-role="main" class="ui-body-d ui-content">
      <label for="name">User's name ${red_dot}:</label>
      <input type=text id="name" name="name" value="" maxlength=256>
      <label for="user">Login username ${red_dot}:</label>
      <input type=text id="user" name="user" value="" maxlength=64>
      <label for="alias">Alias ${red_dot}:</label>
      <input type=text id="alias" name="alias" value="" maxlength=256>
      <label for="email">Email address:</label>
      <input type=text id="email" name="email" value="" maxlength=256>
      Happy password (input twice) ${red_dot}:   
      <div data-role="controlgroup">
        <input type=password id="happy_passwd1" name="happy_passwd1" value="" maxlength=256>
        <input type=password id="happy_passwd2" name="happy_passwd2" value="" maxlength=256>
      </div>      
      Unhappy password (input twice) ${red_dot}:
      <div data-role="controlgroup">
        <input type=password id="unhappy_passwd1" name="unhappy_passwd1" value="" maxlength=256>
        <input type=password id="unhappy_passwd2" name="unhappy_passwd2" value="" maxlength=256>
      </div>
      <br>
      <input type=button id="save" name="save" value="Create" data-icon="plus" onClick="goCreateUserAccount();">
      <br>
      <b>Remarks:</b><br>
      <table width=100% cellspacing=0 cellpadding=0>
      <thead></thead>
      <tbody>
        <tr>
          <td valign=top>1.&nbsp;</td>
          <td valign=top>Input items with ${red_dot} are compulsory that they must be filled.</td>
        </tr>
        <tr>
          <td valign=top>2.&nbsp;</td>
          <td valign=top>All passwords must contain 8 characters or more.</td>
        </tr>                
        <tr>
          <td valign=top>3.&nbsp;</td>
          <td valign=top>Please give user's email address (if you know it) even it is not a compulsory data.</td>
        </tr>        
      </tbody>
      </table>
    </div>
  </div>
  </form>  
  `;
  
  return html;
}


exports.printCreateUserForm = async function() {
  let html;
  
  try {
    html = wev.printHeader('Create User');
    html += _printCreateUserJavascriptSesction();
    html += _printCreateUserForm();
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printActionOptionForm(message) {
  let html;
  
  try {
    html = `
    <form id="frm_add_user" name="frm_add_user" action="" method="post">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">

    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goHome();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Create User</h1>
      </div>
      
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td colspan=2><b>${message}</b></td>
          </tr>
          <tr>
            <td>&nbsp;</td>
          </tr>
          <tr>
            <td colspan=2>Do you want to create more account?</td>
          </tr>
          <tr>
            <td width=50% align=center>
              <input type=button id="btn_yes" name="btn_yes" value="Yes" onClick="goCreateUser();">
            </td>  
            <td width=50% align=center>
              <input type=button id="btn_no" name="btn_no" value="No" onClick="goHome();">
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>      
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printActionOptionForm = async function(message) {
  let html;
  
  try {
    html = wev.printHeader('Create User');
    html += _printCreateUserJavascriptSesction();
    html += _printActionOptionForm(message);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.checkNewMessageCount = async function(msg_pool, user_id, sess_code) {
  var conn;
  var result = [];  
      
  try {
    user_id = parseInt(user_id, 10);        
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));    
    await extendSession(conn, sess_code);   // Extend session period 
    result = await msglib.getMessageGroup(conn, user_id);       
  }
  catch(e) {
    _consoleLog(e.message);
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return result;  
}


async function getUserRole(conn, user_id) {
  var sqlcmd, param, data, result;
  
  result = 0;
  
  try {
    sqlcmd = `SELECT user_role ` +
             `  FROM user_list ` +
             `  WHERE user_id = ?`;
             
    param = [user_id];
    data = await dbs.sqlQuery(conn, sqlcmd, param);
    data = JSON.parse(data);
    
    if (data.length > 0) {
      result = parseInt(data[0].user_role, 10);
    }
    else {
      throw new Error('Invalid user ID is given.');
    }         
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


async function getMessageBlockSize(conn) {
  var block_size, result;

  try {
    block_size = parseInt(await wev.getSysSettingValue(conn, 'msg_block_size'), 10);
    result = (block_size <= 0)? 30 : block_size;
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


async function _printStyleDoSMSpage() {
  var html = '';
  
  try {
    html = `
    <!doctype html>
    <html>
    <head>
      <title>Message</title>
      <meta name='viewport' content='width=device-width, initial-scale=1.0'>
      <meta http-equiv='Content-Type' content='text/html; charset=utf-8'> 

      <style>
        .s_message {
          width:100%;
          height:60px;
          max-height:200px;
        }
        
        .ui-panel.ui-panel-open {
          position:fixed;
        }
        
        .ui-panel-inner {
          position: absolute;
          top: 1px;
          left: 0;
          right: 0;
          bottom: 0px;
          overflow: scroll;
          -webkit-overflow-scrolling: touch;
        }    
      </style>`;
  }
  catch(e) {
    throw e;  
  }
  
  return html;
}


exports.updateSessionSecureKey = async function(msg_pool, user_id, sess_code, aes_key) {
	let conn, sql, param, data, result;
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
		
		sql = `UPDATE web_session ` + 
		      `  SET secure_key = ? ` +
		      `  WHERE user_id = ? ` +
		      `    AND sess_code = ? ` +
		      `    AND status = 'A'`;
		      
		param = [aes_key, user_id, sess_code];
		data = JSON.parse(await dbs.sqlExec(conn, sql, param));      
		
		if (parseInt(data.affectedRows, 10) >= 1) {
			result = {ok: "1", msg: ""};
		}
		else {
			result = {ok: "0", msg: `No such session record. sess_code = ${sess_code}`};
		}
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return result;
}

                                        
async function _printJavascriptDoSMSpage(conn, m_site_dns, wspath, group_id, user_id, update_token, msg_width, indentation, my_msg_colour, rv_msg_colour, rows_limit, top_id, m_params) {
  let login_url, message_url, logout_url, d_site_dns, spaces, space3, first_msg_id, first_msg_date, last_msg_date, js, html;
  
  try {
    html = ``;
    
    d_site_dns = await wev.getSiteDNS(conn, 'D');
    login_url = `${d_site_dns}/`;
    
    message_url = `${m_site_dns}/message`;
    logout_url = `${m_site_dns}/logout_msg`;

    spaces = '&nbsp;'.repeat(8);
    space3 = '&nbsp;'.repeat(3); 
    first_msg_id = m_params.f_m_id;       // The first message ID must be kept, or else it will cause error later.
    first_msg_date = '';
    last_msg_date = '';
    rows_limit = (parseInt(rows_limit, 10) > 0)? rows_limit : 30;
    //-- Note: JSON stringify turn 'm_params' from object into string. However, it keeps the syntax of object. --//
    //--       Therefore, when it embeds on the 'html' below, it's type is object, not string. (from the point --//
    //--       of view of local javascript engine to interpret 'html')                                         --//    
    m_params = JSON.stringify(m_params);       
    
    js = `
    var update_token = "${update_token}";
    var scheduler_id;        
    var op_flag = '';   // op_flag must be initialised to avoid file uploading problem
    var op_user_id;
    var op_msg;
    var group_id = ${group_id};
    var user_id = ${user_id};
    var first_msg_id = "${first_msg_id}";
    var first_msg_date = "${first_msg_date}";
    var last_msg_date = "${last_msg_date}";
    var rows_limit = ${rows_limit};
    var m_params = ${m_params};
    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
    var sess_code = '';            // Session code.
    var aes_key = '';              // AES key is used to encrypt uploaded messages and decrypt received messages.
    var load_message = false;      // Messages loading control flag          
    //-- Below variables are websocket related --//
    var myWebSocket = null;
    var wsPingServer = null;
    var wsOpenSocket = null;   
    var wsCheckTimeout = null;
    var is_reopen = false;

    function connectWebServer() {
      var ws = new WebSocket("${wspath}");
    
      function ping() {
        var packet = {type: 'cmd', content: 'ping'};
        ws.send(JSON.stringify(packet));
      }
      
      function checkTimeout() {
        var packet = {type: 'cmd', content: 'check_timeout'};
        ws.send(JSON.stringify(packet));
      }
                
      function reopenWebSocket() {                                    
        is_reopen = true; 
        myWebSocket = connectWebServer();
      }
    
      ws.onopen = function(e) {
        //-- Once the websocket has been opened, stop the websocket openning scheduler (if it is activated). --//  
        if (wsOpenSocket != null) {clearTimeout(wsOpenSocket)};
        //-- By default, WebSocket connection of Nginx reverse proxy server will be disconnected on 60 seconds (i.e. Timeout), so we --//
        //-- need to send something to the server to keep the connection open within this time interval continuously.                --//
        wsPingServer = setInterval(ping, 50000);                 // Ping the server every 50 seconds                    
        wsCheckTimeout = setInterval(checkTimeout, 300000);      // Check session timeout every 5 minutes
        
        if (is_reopen) {                                        
          //-- Refresh page as websocket is reconnected --//      
          is_reopen = false;
          checkMessage();
        }
      }
      
      ws.onmessage = function(e) {
        var packet = JSON.parse(e.data);
        var type = packet.type;            // Possible values are 'cmd' (command) and 'msg' (message).
        var content = packet.content;      // Note: 'content' is highly possible an object, not just plain text.
        
        if (type == 'msg') {
          if (content.op == 'msg_refresh') {
            var refresh_group_id = content.group_id;
            
            if (refresh_group_id == group_id) {                            
              // Note: The ultimate solution is to get new message(s) via websocket, and update it on user screen in here. 
              //       i.e. Use 'content' to feed in message(s). However, for a temporary workaround. I put checkMessage() 
              //       here to get new message(s).  
              checkMessage();
            }
          }
        }
        else { 
          processCommand(content);
        }
      }
      
      ws.onclose = function(e) {
        clearInterval(wsPingServer);
        //-- Reopen websocket automatically within 100ms --//
        wsOpenSocket = setTimeout(reopenWebSocket, 100);
      }
      
      ws.onerror = function(e) {
        console.log('Error: ' + e.message);
      }
      
      return ws;
    }          
    
    function processCommand(command) {
      var cmd_op = command.op;
                
      switch (cmd_op) {
        case 'pong':
          break;
      
        case 'sess_code':
          sess_code = command.content.trim();
          
          if (load_message) {   
            //-- Check whether session AES key exist or not. If it doesn't exist, abort operation. --//
            let this_promise = new Promise((resolve, reject) => {                  
              let aes_key_lost = false;
              aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
              if (typeof(aes_key) != "string" ) {
                aes_key_lost = true;  
              }
              else {
                aes_key = aes_key.trim();
                if (aes_key.length < ${_key_len}) {
                  //-- AES passphase is too weak --//
                  aes_key_lost = true;
                }
              }
              
              if (aes_key_lost) {
                reject('0');
              }
              else {
                resolve('1');
              }                  
            });
            
            this_promise.then((result) => {
              //-- Load up group messages --//
              goLoadMessage();
              load_message = false;
            }).catch((error) => {
              let msg = "Secure key is lost, system is going to log you out. Please login again.";
              alert(msg);
              logoutSMS();							  
            });
          }
          
          break;
          
        case 'timeout':
          if (command.content.trim() == 'YES') {
            logoutSMS();
          }
          break;  
        
        case 'group_deleted':
          let deleted_group_id = command.group_id;
          
          if (deleted_group_id == group_id) {
            goHome();
          }
          
          break;
          
        case 'force_logout':
          logoutSMS();
          break;
          
        default:
          //-- do nothing --//   
      }                             
    }
    
    //function logout() {
      //window.location.href = '/logout_msg';
      //window.location.href = "${logout_url}";
    //}

    $(document).on("pageinit", function() {
      $(function() {
        $('html,body').animate({scrollTop: $('#page_end').offset().top}, 500);
      })
    });
  
    $(document).on("pagecreate", function() {      
      $('#btn_msg_send').hide();
      $('#reply_row').hide();
      $('#file_upload').hide();
      $('#go_camera').hide();
      $('#go_file').hide();
      $('#go_audio').hide();
    });
    
    $(document).on("pagecreate", function() {
      //-- Define event handlers for the message input textarea object --//
      $('#s_message').click(
        function() {                  
          $(this).keyup();          
        }
      );
                  
      $('#s_message').keyup(
        function() {
          var slen = $(this).val().length;
          if (slen > 0) {            
            $('#btn_msg_send').show();
            $('#btn_attach_file').hide();
            $('#btn_audio_input').hide();
          }
          else {
            $('#btn_msg_send').hide();
            $('#btn_attach_file').show();
            $('#btn_audio_input').show();            
          }
        }
      );
      
      $('#btn_msg_send').on("click", function(event){
        if ($(this).is("[disabled]")) {
          event.preventDefault();
        }
      });      
    });
    
    $(document).on("pageshow", function(event) {          
      //-- Once it enters this module, instruct to load messages and this is the control flag. --// 
      load_message = true;
      //-- Open a websocket --//
      myWebSocket = connectWebServer();
    });
    
    //-- Swipe right in a message group will go to previous page, i.e. the message group(s) landing page. --//
    //-- 2025-06-11 DW: Disable it because it is very annoying --//
    /*
    $(function() {
      $('#dosms').on("swiperight", swiperightHandler);
      
      function swiperightHandler(event) {
        goHome();
      }
    });
    */
            
    //-- Store initial values on local storage of the web browser --//
    if (is_iOS) {
      //-- iOS behavior is different from other platforms, so that it needs to put cross pages data to cookie as work-around. --//
      Cookies.set("g_id", group_id, {expires: 1});              // Defined on js.cookie.min.js    
      Cookies.set("u_id", user_id, {expires: 1});
      Cookies.set("m_id", first_msg_id, {expires: 1});
    }
    else {
      setLocalStoredItem("g_id", group_id);                     // Defined on common_lib.js
      setLocalStoredItem("u_id", user_id);
      setLocalStoredItem("m_id", first_msg_id);
    }
                                          
    function clearLocalData() {
      if (is_iOS) {
        Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
        Cookies.remove("u_id");
        Cookies.remove("m_id");
        Cookies.remove("top_id");
      }
      else {
        deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
        deleteLocalStoredItem("u_id");                             
        deleteLocalStoredItem("m_id");                             
        deleteLocalStoredItem("top_id");                                   
      }      
    }
    
    function logoutSMS() {
      clearLocalData();
      window.location.href = "${logout_url}";
    }
    
    function goHome() {
      clearLocalData();
      switchToPage("frmLeap", "${message_url}", ${_key_len});
    }
        
    //function runScheduler() {
    //  scheduler_id = setInterval(checkMessage, 2000);          
    //}
    
    function checkMessage() {
      $.ajax({
        type: 'POST',
        url: '/check_message_update_token',
        dataType: 'html',
        data: {group_id: ${group_id}, user_id: ${user_id}},
        success: function(ret_data) {
          var result = JSON.parse(ret_data);                  // Note: Return data is in JSON format.
          var mg_status = result.mg_status;
          var new_token = allTrim(mg_status.update_token);
          if (update_token != new_token) {
            if (new_token == "expired") {
              //-- Session is expired, go to login page --//
              alert("Session expired!");
              logoutSMS();                
            }
            else if (new_token == "group_deleted") {
              //-- Message group has been deleted by someone, go to message group main page now. --//
              goHome();
              //clearLocalData();
              //window.location.href = "${message_url}";                                  
            }
            else if (new_token == "user_locked") {
              //-- User has been locked, force logout him/her immediately. --//
              logoutSMS();      
            }
            else if (new_token == "not_group_member") {
              //-- User has been kicked from the group, redirect him/her to message group main page immediately. --//
              goHome();
              //clearLocalData();
              //window.location.href = "${message_url}"; 
            }              
            else if (new_token == "error") {
              var err_msg = mg_status.error;
              //-- System error is found, show user what is wrong. --//
              alert("Unable to check new message. Error: " + err_msg);
              //logoutSMS(); 
            }
            else {
              //-- If message update token has been changed, refresh message section to pull in new message(s). --//
              //-- '0' means get all unread messages, '1' means to get the last sent message.                   --// 
              loadNewMessages(${group_id}, ${user_id}, 0);
              update_token = new_token;                
            }
          }
        },
        error: function(xhr, ajaxOptions, thrownError) {
          //alert("Unable to pull in new message. Error " + xhr.status + ": " + thrownError);
        }
      });      
    }
            
    function stopScheduler() {
      clearInterval(scheduler_id);
    }
    
    async function sendMessage(group_id, user_id) {
      group_id = parseInt(group_id, 10);
      user_id = parseInt(user_id, 10);
    
      let ta = document.getElementById("s_message");      
      let content = allTrim(ta.value);
      
      if (content.length > 0) {
        //-- Get the AES key to encrypt the sending message --//
        let key_ready = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");				  
        if (typeof(aes_key) != "string") {
          key_ready = false;
        }            
        else {
          aes_key = aes_key.trim();
          if (aes_key.length < ${_key_len}) {
            key_ready = false;
          }
        }
        
        if (key_ready) {
          //-- Prepare a new rolling key --//                  
          await prepareRollingKey(${_key_len});               // Defined on crypto-lib.js
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;
          
          //-- Encrypt the message with AES-256 before send it out --//
          let algorithm = "AES-GCM";
          let enc_msg_obj = await aesEncryptJSON(algorithm, aes_key, content);
          let msg_iv = enc_msg_obj.iv;
          let encrypted_msg = enc_msg_obj.encrypted;
          let enc_op_msg_obj = await aesEncryptJSON(algorithm, aes_key, op_msg);
          let op_iv = enc_op_msg_obj.iv;
          let encrypted_op_msg = enc_op_msg_obj.encrypted;   
                        
          //-- Change button image from 'send.png' to 'yellow_flash.jpg' --//
          $('#btn_msg_send').attr('src', '/images/yellow_flash.jpg');        
          $('#btn_msg_send').attr("disabled", "disabled");     
        
          // Clear AES key from RAM after used //
          aes_key = null;
                              
          $.ajax({
            type: 'POST',
            url: '/send_message',
            dataType: 'html',
            data: {
              roll_rec: roll_rec,
              iv_roll_rec: iv_roll_rec,
              roll_rec_sum: roll_rec_sum,
              group_id: group_id, 
              sender_id: user_id, 
              algorithm: algorithm, 
              msg_iv: msg_iv, 
              message: encrypted_msg, 
              op_flag: op_flag, 
              op_user_id: 
              op_user_id, 
              op_iv: op_iv, 
              op_msg: encrypted_op_msg
            },
            success: function(ret_data) {
              let result = JSON.parse(ret_data);              // Note: Return data is in JSON format.
              let new_token = allTrim(result.mg_status.update_token);                        
              
              if (new_token == "error") {
                alert("Unable to send message!");
              }
              else if (new_token == "expired") {
                alert("Session expired, please login again.");
                logoutSMS();
              }
              else if (new_token == "invalid") {
                logoutSMS();
              }
              else {
                ta.value = "";
                //-- Refresh message section --//
                //-- '0' means get all unread messages, '1' means to get the last sent message. --//
                loadNewMessages(${group_id}, ${user_id}, 1);
                update_token = new_token;
                noReply();
              }
              
              $('#s_message').click();
              $('#btn_msg_send').hide();
              $('#btn_msg_send').removeAttr("disabled");
              $('#btn_msg_send').attr('src', '/images/send.png');                
              $('#btn_attach_file').show();
              $('#btn_audio_input').show();                            
            },
            error: function(xhr, ajaxOptions, thrownError) {
              alert("Unable to send message. Error " + xhr.status + ": " + thrownError);
              $('#btn_msg_send').removeAttr("disabled");
              $('#btn_msg_send').attr('src', '/images/send.png');
              noReply();
            }          
          });
        }
        else {
          alert("The secure key is lost, the system is going to log you out.");
          logoutSMS();
        }
      }
      else {
        alert("Empty message won't be sent");
      }
    }
    
    async function autoDeleteSetup(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/auto_delete_setup";
        document.getElementById("frmLeap").submit();
      }
      catch(e) {
        alert(e.message);
      }    
    }
    
    async function changeGroupName(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/change_group_name";
        document.getElementById("frmLeap").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }

    async function listGroupMember(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/list_group_member";
        document.getElementById("frmLeap").submit();
      }
      catch(e) {
        alert(e.message);
      }
    }
        
    async function quitMessageGroup(group_id, user_id) {
      if (confirm("Do you really want to exit?")) {
        try {
          await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
          
          document.getElementById("g_id").value = group_id;
          document.getElementById("member_id").value = user_id;
          document.getElementById("frmLeap").action = "/exit_group";
          document.getElementById("frmLeap").submit();        
        }
        catch(e) {
          alert(e.message);
        }
      }      
    }
    
    async function addGroupMember(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/add_group_member";
        document.getElementById("frmLeap").submit();
      }
      catch(e) {
        alert(e.message);
      }    
    }
    
    async function deleteGroupMember(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/delete_group_member";
        document.getElementById("frmLeap").submit();      
      }
      catch(e) {
        alert(e.message);
      }
    }  
    
    async function promoteGroupMember(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/promote_group_member";
        document.getElementById("frmLeap").submit();      
      }
      catch(e) {
        alert(e.message);
      }    
    }
    
    async function demoteGroupAdmin(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/demote_group_admin";
        document.getElementById("frmLeap").submit();      
      }
      catch(e) {
        alert(e.message);
      }        
    }
    
    async function informMember(group_id) {
      try {
        await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
        
        document.getElementById("g_id").value = group_id;
        document.getElementById("frmLeap").action = "/inform_member";
        document.getElementById("frmLeap").submit();      
      }
      catch(e) {
        alert(e.message);
      }            
    }
    
    async function deleteThisGroup(group_id) {
      if (confirm("Do you want to delete this message group?")) {
        if (confirm("Last chance! Really want to delete this group?")) {
          try {
            await prepareRollingKey(${_key_len});        // Defined on crypto-lib.js
            
            document.getElementById("g_id").value = group_id;
            document.getElementById("frmLeap").action = "/delete_group";
            document.getElementById("frmLeap").submit();      
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
    }
    
    function replyMessage(msg_id, sender_id, sender, msg_30) {
      op_flag = 'R';
      op_user_id = sender_id;
      msg_30 = msg_30.replace(/¡/g, "'");      // Note: All single quote characters on msg_30 are converted to '¡' before passed in here.
      op_msg = msg_30;
      let html = "<font color='#0081FE' size='2px'><b>" + sender + "</b></font><br>" + op_msg;
      $('#reply_msg_area').html(html);
      $('#reply_row').show();    
    }
    
    function noReply() {
      op_flag = '';
      op_user_id = 0;
      op_msg = '';
      $('#reply_msg_area').html('');
      $('#reply_row').hide();          
    }
    
    async function forwardMessage(group_id, msg_id) {
      try {
        await prepareRollingKey(${_key_len});
        $('#from_group_id').val(group_id);
        $('#msg_id').val(msg_id);
        
        document.getElementById('frmLeap').action = "/forward_message";
        document.getElementById('frmLeap').submit();
      }
      catch(e) {
        alert(e.message);
      }
    }

    function showTextInputPanel() {
      $('#text_send').show();
      $('#file_upload').hide();
      $('#go_camera').hide();
      $('#go_file').hide();
      $('#go_audio').hide();
    }
    
    function attachFile() {
      $('#text_send').hide();
      $('#file_upload').show();
      $('#go_camera').hide();
      $('#go_file').hide();
      $('#go_audio').hide();
    }
    
    function openCamera() {
      $('#text_send').hide();
      $('#file_upload').hide();
      $('#go_camera').show();
      $('#go_file').hide();
      $('#go_audio').hide();
      $('#photo').click();
    }
    
    function selectFileToUpload() {
      $('#text_send').hide();
      $('#file_upload').hide();
      $('#go_camera').hide();
      $('#go_file').show();
      $('#go_audio').hide();      
      $('#ul_file').click();      
    }
    
    async function sendPhoto(group_id, user_id) {
      let send_button_status = $('#btn_send_photo').attr("disabled");
      if (send_button_status == "disabled") {
        return false;
      }
                      
      let image_name = allTrim($('#photo').val());   
      if (image_name != "") {   
        let key_ready = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");				  
        if (typeof(aes_key) != "string") {
          key_ready = false;
        }            
        else {
          aes_key = aes_key.trim();
          if (aes_key.length < ${_key_len}) {
            key_ready = false;
          }
        }
        
        if (key_ready) {
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
                 
          let image = $('#photo').prop('files')[0];
          //-- Encode uploaded file name to handle Chinese characters --// 
          image.name = unescape(encodeURIComponent(image.name));               
          //-- Encrypt 'caption' and 'op_msg' before send the data set to the server --//  
          let algorithm = "AES-GCM";                   
          let this_caption = allTrim($('#caption').val());
          this_caption = (typeof(this_caption) == "string")? this_caption : '';
          op_msg = (typeof(op_msg) == "string")? op_msg : '';              
          let enc_caption_obj = await aesEncryptJSON(algorithm, aes_key, this_caption);
          let caption_iv = enc_caption_obj.iv;
          let enc_caption = enc_caption_obj.encrypted;
          let enc_op_msg_obj = await aesEncryptJSON(algorithm, aes_key, op_msg);
          let op_iv = enc_op_msg_obj.iv;
          let enc_op_msg = enc_op_msg_obj.encrypted;
            
          let form_data = new FormData();
          form_data.append('roll_rec', roll_rec);
          form_data.append('iv_roll_rec', iv_roll_rec);
          form_data.append('roll_rec_sum', roll_rec_sum);          
          form_data.append('group_id', group_id);
          form_data.append('sender_id', user_id);
          form_data.append('ul_ftype', 'photo');
          form_data.append('ul_file', image);
          form_data.append('algorithm', algorithm);
          form_data.append('caption_iv', caption_iv);
          form_data.append('caption', enc_caption);
          form_data.append('op_flag', op_flag);
          form_data.append('op_user_id', op_user_id);
          form_data.append('op_iv', op_iv);
          form_data.append('op_msg', enc_op_msg);
          //-- Change button image from 'send.png' to 'files_uploading.gif' --//
          $('#btn_send_photo').attr('src', '/images/files_uploading.gif');
          //-- Then disable it to prevent upload a photo twice --//
          $('#btn_send_photo').attr("disabled", "disabled");

          // Clear aes_key from RAM after used //
          aes_key = '';
        
          $.ajax({
            type: 'POST',
            url: '/upload_files',
            dataType: 'text',
            cache: false,
            contentType: false,
            processData: false,
            data: form_data,
            success: function(response) {
              var new_token = response;
              
              switch (new_token) {
                case 'error': 
                  alert("Error is found as file upload.");
                  $('#btn_send_photo').removeAttr("disabled");
                  $('#btn_send_photo').attr('src', '/images/send.png');
                  break;
                
                case 'invalid':
                  logoutSMS();
                  break;
                  
                case 'sess_expired':
                  alert("Session expired");
                  logoutSMS();
                  break;
                  
                case 'hacking':
                  alert("Don't try to hack the system, you are blacklisted!");
                  logoutSMS();
                  break;
                                      
                default:    
                  //-- Refresh message section (just load the last sent message only) --//
                  //-- '0' means get all unread messages, '1' means to get the last sent message. --//
                  loadNewMessages(${group_id}, ${user_id}, 1);
                  update_token = new_token;                        
                  $('#btn_send_photo').removeAttr("disabled");
                  $('#btn_send_photo').attr('src', '/images/send.png');
                  $('#caption').val("");
                  showTextInputPanel();
                  noReply();                
                  //-- Inform other group members to refresh message via WebSocket --//
                  informGroupMembersToRefresh(group_id, user_id);                                
              }
            },
            error: function(xhr, ajaxOptions, thrownError) {
              alert("Unable to upload photo. Error " + xhr.status + ": " + thrownError);
              $('#btn_send_photo').removeAttr("disabled");
              $('#btn_send_photo').attr('src', '/images/send.png');
            }                    
          });
        }
        else {
          alert("The secure key is lost, the system is going to log you out.");
          logoutSMS();            
        }
      }
      else {
        alert("Please take a photo before click the send button");
      }
    }
    
    async function sendFile(group_id, user_id) {
      let send_button_status = $('#btn_send_file').attr("disabled");
      if (send_button_status == "disabled") {
        return false;
      }
      
      let file_name = allTrim($('#ul_file').val());   
      if (file_name != "") {
        let key_ready = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");				  
        if (typeof(aes_key) != "string") {
          key_ready = false;
        }            
        else {
          aes_key = aes_key.trim();
          if (aes_key.length < ${_key_len}) {
            key_ready = false;
          }
        }
        
        if (key_ready) {
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
                           
          let ul_file = $('#ul_file').prop('files')[0];
          //-- Encode uploaded file name to handle Chinese characters --// 
          ul_file.name = unescape(encodeURIComponent(ul_file.name));       
          //-- Encrypt 'caption' and 'op_msg' before send the data set to the server, even 'caption' --//
          //-- is blank in this case.                                                                --//  
          let algorithm = "AES-GCM";                   
          op_msg = (typeof(op_msg) == "string")? op_msg : '';     
          let enc_caption_obj = await aesEncryptJSON(algorithm, aes_key, '');   // Caption is always blank in this case
          let caption_iv = enc_caption_obj.iv;
          let enc_caption = enc_caption_obj.encrypted;
          let enc_op_msg_obj = await aesEncryptJSON(algorithm, aes_key, op_msg);
          let op_iv = enc_op_msg_obj.iv;
          let enc_op_msg = enc_op_msg_obj.encrypted;
                                       
          let form_data = new FormData();
          form_data.append('roll_rec', roll_rec);
          form_data.append('iv_roll_rec', iv_roll_rec);
          form_data.append('roll_rec_sum', roll_rec_sum);
          form_data.append('group_id', group_id);
          form_data.append('sender_id', user_id);
          form_data.append('ul_ftype', 'file');
          form_data.append('ul_file', ul_file);            
          form_data.append('algorithm', algorithm);
          form_data.append('caption_iv', caption_iv);
          form_data.append('caption', enc_caption);
          form_data.append('op_flag', op_flag);
          form_data.append('op_user_id', op_user_id);
          form_data.append('op_iv', op_iv);
          form_data.append('op_msg', enc_op_msg);
          //-- Change button image from 'send.png' to 'files_uploading.gif' --//
          $('#btn_send_file').attr('src', '/images/files_uploading.gif');
          //-- Then disable it to prevent upload a file twice --//
          $('#btn_send_file').attr("disabled", "disabled");

          // Clear aes_key from RAM after used //
          aes_key = null;
        
          $.ajax({
            type: 'POST',
            url: '/upload_files',
            dataType: 'text',
            cache: false,
            contentType: false,
            processData: false,
            data: form_data,
            success: function(response) {
              var new_token = response;
              
              switch (new_token) {
                case 'error': 
                  alert("Error is found as file upload.");
                  $('#btn_send_file').removeAttr("disabled");
                  $('#btn_send_file').attr('src', '/images/send.png');
                  break;
                
                case 'hacking':
                  alert("Don't try to hack the system, you are blacklisted!");
                  logoutSMS();
                  break;

                case 'invalid':
                  logoutSMS();
                  break;
                  
                case 'sess_expired':
                  alert("Session expired");
                  logoutSMS();
                  break;
                  
                default:    
                  //-- Refresh message section (just load the last sent message only) --//
                  //-- '0' means get all unread messages, '1' means to get the last sent message. --//
                  loadNewMessages(${group_id}, ${user_id}, 1);
                  update_token = new_token;                        
                  $('#btn_send_file').removeAttr("disabled");
                  $('#btn_send_file').attr('src', '/images/send.png');
                  showTextInputPanel();
                  noReply();                
                  //-- Inform other group members to refresh message via WebSocket --//
                  informGroupMembersToRefresh(group_id, user_id);                                
              }
            },
            error: function(xhr, ajaxOptions, thrownError) {
              alert("Unable to upload file. Error " + xhr.status + ": " + thrownError);
              $('#btn_send_file').removeAttr("disabled");
              $('#btn_send_file').attr('src', '/images/send.png');
            }                    
          });
        }
        else {
          alert("The secure key is lost, the system is going to log you out.");
          logoutSMS();                        
        } 
      }
      else {
        alert("Please select a file before click the send button");
      }
    }
    
    function hasGetUserMedia() {
      return !!(navigator.mediaDevices &&
        navigator.mediaDevices.getUserMedia);
    }
    
    function audioInput() {
      if (hasGetUserMedia()) {
        $('#text_send').hide();
        $('#file_upload').hide();
        $('#go_camera').hide();
        $('#go_file').hide();
        $('#go_audio').show();
        $('#sound').click();
      }
      else {
        alert("Your web browser doesn't support audio input.");
      }
    }
    
    async function sendSound(group_id, user_id) {
      let send_button_status = $('#btn_send_sound').attr("disabled");
      if (send_button_status == "disabled") {
        return false;
      }
      
      let file_name = allTrim($('#sound').val());   
      if (file_name != "") {
        let key_ready = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");				  
        if (typeof(aes_key) != "string") {
          key_ready = false;
        }            
        else {
          aes_key = aes_key.trim();
          if (aes_key.length < ${_key_len}) {
            key_ready = false;
          }
        }
      
        if (key_ready) {       
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
                
          let sound = $('#sound').prop('files')[0];
          
          //************
          // Note: Sending sound track via smartphone, it keeps to upload the first recorded sound track.
          //       This problem must be solved later.
          // 
          // Useful URL:
          // 1. https://developer.mozilla.org/en-US/docs/Web/API/File_API/Using_files_from_web_applications
          // 2. https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input/file
          // 3. https://web.dev/articles/media-recording-audio
          
          //var soundElement = document.getElementById("sound");
          //soundElement.addEventListener("change", soundFileHandler, "false");
          
          /*          
          function soundFileHandler() {
            console.log("see me?");
          
            var filelist = this.files;
            
            // Note: If it is tested ok, the sound file uploading operation must be moved in here. // 
                        
            for (var i = 0; i < filelist.length; i++) {
              var fname = filelist[i].name;
              var fsize = filelist[i].size;
              var ftype = filelist[i].type;
              
              console.log(fname + ', ' + fsize + ', ' + ftype);              
            }
          }

          $('#btn_send_sound').removeAttr("disabled");
          $('#btn_send_sound').attr('src', '/images/send.png');
          
          return false;
          */             
          //************
          
          //-- Encode uploaded file name to handle Chinese characters --// 
          sound.name = unescape(encodeURIComponent(sound.name));    
                                          
          //-- Encrypt 'caption' and 'op_msg' before send the data set to the server, even 'caption' --//
          //-- is blank in this case.                                                                --//  
          let algorithm = "AES-GCM";                   
          op_msg = (typeof(op_msg) == "string")? op_msg : '';              
          let enc_caption_obj = await aesEncryptJSON(algorithm, aes_key, '');
          let caption_iv = enc_caption_obj.iv;
          let enc_caption = enc_caption_obj.encrypted;
          let enc_op_msg_obj = await aesEncryptJSON(algorithm, aes_key, op_msg);
          let op_iv = enc_op_msg_obj.iv;
          let enc_op_msg = enc_op_msg_obj.encrypted;
          
          // Clear aes_key from RAM after used //
          aes_key = '';
                                       
          let form_data = new FormData();
          form_data.append('roll_rec', roll_rec);
          form_data.append('iv_roll_rec', iv_roll_rec);
          form_data.append('roll_rec_sum', roll_rec_sum);          
          form_data.append('group_id', group_id);
          form_data.append('sender_id', user_id);
          form_data.append('ul_ftype', 'sound');
          form_data.append('ul_file', sound);              
          form_data.append('algorithm', algorithm);
          form_data.append('caption_iv', caption_iv);
          form_data.append('caption', enc_caption);
          form_data.append('op_flag', op_flag);
          form_data.append('op_user_id', op_user_id);
          form_data.append('op_iv', op_iv);
          form_data.append('op_msg', enc_op_msg);
          //-- Change button image from 'send.png' to 'files_uploading.gif' --//
          $('#btn_send_sound').attr('src', '/images/files_uploading.gif');
          //-- Then disable it to prevent upload a file twice --//
          $('#btn_send_sound').attr("disabled", "disabled");
        
          $.ajax({
            type: 'POST',
            url: '/upload_files',
            dataType: 'text',
            cache: false,
            contentType: false,
            processData: false,
            data: form_data,
            success: function(response) {
              let new_token = response;
              
              switch (new_token) {
                case 'error': 
                  alert("Error is found as file upload.");
                  $('#btn_send_sound').removeAttr("disabled");
                  $('#btn_send_sound').attr('src', '/images/send.png');
                  break;
                
                case 'invalid':
                  logoutSMS();
                  break;
                                  
                case 'sess_expired':
                  alert("Session expired");
                  logoutSMS();
                  break;
                
                case 'hacking':
                  alert("Don't try to hack the system, you are blacklisted!");
                  logoutSMS();
                  break;
                                  
                default:    
                  //-- Refresh message section (just load the last sent message only) --//
                  //-- '0' means get all unread messages, '1' means to get the last sent message. --//
                  loadNewMessages(${group_id}, ${user_id}, 1);
                  update_token = new_token;                        
                  $('#btn_send_sound').removeAttr("disabled");
                  $('#btn_send_sound').attr('src', '/images/send.png');
                  showTextInputPanel();
                  noReply();                
                  //-- Inform other group members to refresh message via WebSocket --//
                  informGroupMembersToRefresh(group_id, user_id);                                
              }
            },
            error: function(xhr, ajaxOptions, thrownError) {
              alert("Unable to upload sound file. Error " + xhr.status + ": " + thrownError);
              $('#btn_send_sound').removeAttr("disabled");
              $('#btn_send_sound').attr('src', '/images/send.png');
            }                    
          });
        }
        else {
          alert("The secure key is lost, the system is going to log you out.");
          logoutSMS();                                
        }      
      }
      else {
        alert("Please record a sound file before click the send button");
      }      
    }
    
    //-------------------------------------------------------------------------------------------------------//    
    async function goLoadMessage() {
      await prepareRollingKey(${_key_len});    // Defined on crypto-lib.js
      
      let roll_rec = document.getElementById("roll_rec").value;
      let iv_roll_rec = document.getElementById("iv_roll_rec").value;
      let roll_rec_sum = document.getElementById("roll_rec_sum").value;
      
      $.ajax({
        type: 'POST',
        url: '/load_message',
        dataType: 'html',
        data: {
          roll_rec: roll_rec,
          iv_roll_rec: iv_roll_rec,
          roll_rec_sum: roll_rec_sum,
          group_id: group_id, 
          user_id: user_id, 
          m_params: JSON.stringify(m_params)
        },
        success: function(ret_data) {
          var result = JSON.parse(ret_data);              // Note: Return data is in JSON format.                
          var new_token = allTrim(result.update_token);
          var msg_list = result.message;               
          
          if (new_token == 'error') {
            alert("Unable to load message. Error is found.");
          }
          else if (new_token == 'logout') {
            alert(msg_list[0]);
            logoutSMS();          
          }
          else if (new_token == 'expired') {
            alert("Session expired, please login again.");
            logoutSMS();                    
          }
          else if (new_token == 'invalid') {
            logoutSMS();                              
          }
          else {         
            showMessages(msg_list);
            update_token = new_token;
          }
        },
        error: function(xhr, ajaxOptions, thrownError) {
          alert("Unable to load message. Error " + xhr.status + ": " + thrownError);
        }          
      });
    }
    
    async function showMessages(msg_list) {
      first_msg_id = (msg_list.length > 0)? msg_list[0].msg_id : '';
      first_msg_date = (msg_list.length > 0)? msg_list[0].s_date : '';
      last_msg_date = (msg_list.length > 0)? msg_list[msg_list.length - 1].s_date : ''; 
    
      var blank_line = "<tr style='height:8px;'><td></td></tr>"; 
      var new_msg_start = 'W';            // 'W' = Wait for new message (if any), 'S' = New message has been met and new message seperator line been shown. 
      //-- Refresh 'Read More' button --//
      var read_more = (msg_list.length >= rows_limit && msg_list[0].msg_id != '${top_id}')? "<img id='btn_load_more' src='/images/readmore.png' height='50px' onClick='loadPrevMessages(group_id, user_id);'><br>" : '';
      $('#read_more').html("<td align=center valign=center>" + read_more + "</td>");
      
      //-- Get the AES key to decrypt the feeding messages --//
      aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");				  
      
      var prv_s_date = '';
      for (var i = 0; i < msg_list.length; i++) {
        var rec = msg_list[i];
      
        var this_msg_id = rec.msg_id;
        var this_is_my_msg = rec.is_my_msg;
        var this_user_color = (rec.user_status == 'A')? '#8B0909' : '#A4A5A5';
        var is_member = (!rec.is_member)? "(Non member)" : '';
        var this_sender_id = rec.sender_id;
        var this_sender = rec.sender;
        var this_sender = "<font color='" + this_user_color + "' size='2px'><b>" + this_sender + " " + is_member + "</b></font>";
        var this_s_date = rec.s_date;
        var this_s_time_12 = rec.s_time_12;
        var this_from_now = rec.from_now;
        var this_week_day = rec.week_day;
        var this_message = await aesDecryptBase64(rec.algorithm, aes_key, rec.iv, rec.message);      // Defined on crypto-lib.js
        var this_fileloc = rec.fileloc;
        var this_file_link = (rec.file_link != '' && rec.message != '')? rec.file_link + '<br>' : rec.file_link;
        var this_op_flag = rec.op_flag;
        var this_op_user = rec.op_user;
        var this_op_msg = await aesDecryptBase64(rec.algorithm, aes_key, rec.op_iv, rec.op_msg);
        var this_msg_time = "<font color='#31B404' size='2px'>" + this_s_time_12 + "</font>";
        var is_new_msg = rec.is_new_msg;
        // Process " and ' characters on 'this_msg_30' to avoid syntax error //
        var this_msg_30 = processQuotationMarks(await aesDecryptBase64(rec.algorithm, aes_key, rec.msg_30_iv, rec.msg_30));    // Used for message replying
        var fw_header = '';
        var re_header = '';
        var this_tr = '';
        
        if (this_file_link.match(/audio controls/gi)) {
          this_file_link += '<br>';
        }
                    
        //-- If it is reply or forward message, process it here --//
        if (this_op_flag == 'R') {
          re_header = "<table width='100%' cellspacing=2 cellpadding=6>" +
                      "<tr>" +
                      "  <td style='border-left: 5px solid #0180FF;'>" +
                      "    <font color='#0081FE' size='2px'><b>" + this_op_user + "</b></font><br>" + this_op_msg +
                      "  </td>" +
                      "</tr>" +
                      "</table>";  
        }
        else if (this_op_flag == 'F') {
          fw_header = "<font color='#298A09' size='2px'>Forwarded message<br>From <b>" + this_op_user + "</b><br></font>";
        }  
      
        //-- Show date --//
        if (prv_s_date != this_s_date) {
          var date_tr = "<tr style='background-color:#D9D9D8'><td align=center>" + this_s_date + "</td></tr>" + blank_line;
          $('#msg_table').append(date_tr).enhanceWithin();
          prv_s_date = this_s_date;
        }
        
        //-- Show new message seperation marker --//
        if (is_new_msg && new_msg_start == 'W') {
          var new_msg_tr = "<tr id='new_msg' style='background-color:#F5A8BD'><td align=center>New Message(s) Below</td></tr>" + blank_line;
          $('#msg_table').append(new_msg_tr).enhanceWithin();
          new_msg_start = 'S'; 
        }
      
        if (this_is_my_msg) {
          var delete_link = "<a href=\\"javascript:deleteMessage('" + this_msg_id + "');\\">Delete</a>";
          var reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
          var forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
      
          this_tr = "<tr id='row_" + this_msg_id + "'>" +
                    "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                    "  <td width='100%'>" +
                    "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                    "    <tr>" +
                    "      <td width='${indentation}%'></td>" +
                    "      <td width='${msg_width}%' style='background-color:${my_msg_colour}; word-wrap:break-word;'>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + delete_link + " ${space3} " + reply_link + " ${space3} " + forward_link + "</td>" +
                    "    </tr>" +
                    "    </table>" +
                    "  </td>" +
                    "</tr>";            
        }
        else {
          var reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
          var forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
        
          this_tr = "<tr id='row_" + this_msg_id + "'>" +
                    "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                    "  <td width='100%'>" +
                    "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                    "    <tr>" + 
                    "      <td width='${msg_width}%' style='background-color:${rv_msg_colour}; word-wrap:break-word;'>" + this_sender + "<br>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + reply_link + " ${space3} " + forward_link + "</td>" +
                    "      <td width='${indentation}%'></td>" +
                    "    </tr>" +
                    "    </table>" +
                    "  </td>" +
                    "</tr>";            
        }
        
        $('#msg_table').append(this_tr).enhanceWithin();  
        this_tr = "<tr id='blankline_" + this_msg_id + "' style='height:8px;'><td></td></tr>";
        $('#msg_table').append(this_tr).enhanceWithin();
      }      
      
      // Clear aes_key from RAM after used //
      aes_key = '';
      
      //-- Seek to last message --//            
      $('html, body').animate({scrollTop: $('#page_end').offset().top}, 500);                                      
    }
    
    function getMessageIdListFromOtherSenders() {
      var result = '';
      var buffer = new Array();
      var omid_list = document.querySelectorAll('[id^="omid_"]');
      for (var i = 0; i < omid_list.length; ++i) {
        buffer[i] = omid_list[i].value; 
      }
      result = buffer.join('|');
      
      return result;
    }
    
    function informGroupMembersToRefresh(group_id, user_id) {
      if (typeof(myWebSocket) != 'undefined' && myWebSocket != null) {
        let packet = {type: 'msg', content: {op: 'msg_refresh', group_id: group_id, user_id: user_id}};
        myWebSocket.send(JSON.stringify(packet));
      }
      else {
        console.log("Websocket handler is lost!");
      }
    }
    
    async function loadNewMessages(group_id, user_id, last_sent_msg_only) {
      await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
      let roll_rec = document.getElementById("roll_rec").value;
      let iv_roll_rec = document.getElementById("iv_roll_rec").value;
      let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
      let omid_list = getMessageIdListFromOtherSenders();
      
      //-- Note: Boolean value sent to back-end application will be changed to string automatically. Therefore, don't send --//
      //--       boolean value to back-end directly, but rather convert it to different type of value which can be sent to --//
      //--       back-end safely, such as numeric value. For example, 0 for the false, and 1 for the true.                 --//                                                               --//  
      
      $.ajax({
        type: 'POST',
        url: '/pull_new_message',
        dataType: 'json',
        data: {
          roll_rec: roll_rec,
          iv_roll_rec: iv_roll_rec,
          roll_rec_sum: roll_rec_sum,
          group_id: group_id, 
          receiver_id: user_id, 
          last_sent_msg_only: last_sent_msg_only, 
          omid_list: omid_list
        },
        success: function(ret_data) {              
          var valid_ret_data = false;
          if (Array.isArray(ret_data)) {
            if (ret_data.length > 0) {
              valid_ret_data = true;
            } 
          } 
          
          if (valid_ret_data) {            
            if (ret_data[0].msg_status == "error") {
              alert(ret_data[0].message);
            }    
            else if (ret_data[0].msg_status == "expired") {
              alert(ret_data[0].message);
              logoutSMS();
            }           
            else if (ret_data[0].msg_status == "hacking") {
              alert(ret_data[0].message);
              logoutSMS();            
            }           
            else if (ret_data[0].msg_status == "invalid") {
              logoutSMS();
            }           
            else {
              if (ret_data[0].msg_status == "deleted") {
                hideMessageDeletedByOtherSender(ret_data);
              }
              else {
                addMessageRow(ret_data, last_sent_msg_only);
              }
              
              //-- Inform other group members to refresh message via WebSocket --//
              informGroupMembersToRefresh(group_id, user_id);
            }
          }
        },
        error: function(xhr, ajaxOptions, thrownError) {
          alert("Unable to draw new message(s). Error " + xhr.status + ": " + thrownError);
        }             
      });      
    }
    
    function hideMessageDeletedByOtherSender(ret_data) {
      for (var i = 0; i < ret_data.length; i++) {
        var rec = ret_data[i];          
        var this_msg_id = rec.msg_id;

        $('#row_' + this_msg_id).hide();
        $('#blankline_' + this_msg_id).hide();
        $('#omid_' + this_msg_id).remove();
      }      
    }
    
    async function addMessageRow(ret_data, last_sent_msg_only) {
      last_sent_msg_only = parseInt(last_sent_msg_only, 10);
    
      aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
    
      for (var i = 0; i < ret_data.length; i++) {
        var rec = ret_data[i];          
        var this_msg_id = rec.msg_id;
        var this_is_my_msg = rec.is_my_msg;
        var this_user_color = '#8B0909';
        if (allTrim(rec.user_status) != "A") {this_user_color = '#A4A5A5';}
        var is_member = '';
        if (parseInt(rec.is_member, 10) == 0) {is_member = "(Non member)";}
        var this_sender_id = rec.sender_id;
        var this_sender = "<font color='" + this_user_color + "' size='2px'><b>" + rec.sender + " " + is_member + "</b></font>";
        var this_s_date = rec.s_date;
        var this_s_time_12 = rec.s_time_12;
        var this_from_now = rec.from_now;
        var this_week_day = rec.week_day;
        var this_message = await aesDecryptBase64(rec.algorithm, aes_key, rec.iv, rec.message);      // Defined on crypto-lib.js
        var this_fileloc = rec.fileloc;
        var this_file_link = (rec.file_link != '' && rec.message != '')? rec.file_link + '<br>' : rec.file_link;
        var this_op_flag = rec.op_flag;
        var this_op_user = rec.op_user;            
        var this_op_msg = await aesDecryptBase64(rec.algorithm, aes_key, rec.op_iv, rec.op_msg); 
        var show_time = this_s_time_12;
        //if (this_from_now != "") {show_time = this_from_now;}
        var this_msg_time = "<font color='#31B404' size='2px'>" + show_time + "</font>";
        var is_new_msg = rec.is_new_msg;
        // Process " and ' characters on 'this_msg_30' to avoid syntax error //
        var this_msg_30 = processQuotationMarks(await aesDecryptBase64(rec.algorithm, aes_key, rec.msg_30_iv, rec.msg_30));   // Used for message replying
        var this_tr = '';
        var re_header = "";
        var fw_header = "";
        
        if (this_file_link.match(/audio controls/gi)) {
          this_file_link = this_file_link + "<br>";
        }
        
        //-- If it is reply or forward message, process it here. --//
        if (this_op_flag == 'R') {
          re_header = "<table width='100%' cellspacing=2 cellpadding=6>" +
                      "<tr>" +
                      "  <td style='border-left: 5px solid #0180FF;'>" +
                      "    <font color='#0081FE' size='2px'><b>" + this_op_user + "</b></font><br>" + this_op_msg +
                      "  </td>" +
                      "</tr>" +
                      "</table>";
        }
        else if (this_op_flag == 'F') {
          fw_header = "<font color='#298A09' size='2px'>Forwarded message<br>From <b>" + this_op_user + "</b><br></font>";
        }
                
        if (last_msg_date != this_s_date) {
          var date_tr = "<tr style='background-color:#D9D9D8'><td align=center>" + this_s_date + "</td></tr>";
          $('#msg_table').append(date_tr).enhanceWithin();
          if (last_sent_msg_only == 1) {
            var blank_tr = "<tr style='height:8px;'><td></td></tr>";
            $('#msg_table').append(blank_tr).enhanceWithin(); 
          }
          last_msg_date = this_s_date
        }
            
        if (this_is_my_msg) {
          var delete_link = "<a href=\\"javascript:deleteMessage('" + this_msg_id + "');\\">Delete</a>";
          var reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
          var forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
      
          this_tr = "<tr id='row_" + this_msg_id + "'>" +
                    "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                    "  <td width='100%'>" +
                    "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                    "    <tr>" +
                    "      <td width='${indentation}%'></td>" +
                    "      <td width='${msg_width}%' style='background-color:${my_msg_colour}; word-wrap:break-word;'>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + delete_link + " ${space3} " + reply_link + " ${space3} " + forward_link + "</td>" +
                    "    </tr>" +
                    "    </table>" +
                    "  </td>" +
                    "</tr>";
        }
        else {
          var reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
          var forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
        
          this_tr = "<tr id='row_" + this_msg_id + "'>" +
                    "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                    "  <td width='100%'>" +
                    "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                    "    <tr>" + 
                    "      <td width='${msg_width}%' style='background-color:${rv_msg_colour}; word-wrap:break-word;'>" + this_sender + "<br>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + reply_link + " ${space3} " + forward_link + "</td>" +
                    "      <td width='${indentation}%'></td>" +
                    "    </tr>" +
                    "    </table>" +
                    "  </td>" +
                    "</tr>";
        }
    
        $('#msg_table').append(this_tr).enhanceWithin();  
        this_tr = "<tr id='blankline_" + this_msg_id + "' style='height:8px;'><td></td></tr>";
        $('#msg_table').append(this_tr).enhanceWithin();

        //-- Seek to last message --//            
        $('html, body').animate({scrollTop: $('#page_end').offset().top}, 500);
      }
      
      // Clear session AES key from RAM after used //
      aes_key = "";      
    }
        
    async function deleteMessage(msg_id) {
      if (msg_id != '') {
        await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
        let roll_rec = document.getElementById("roll_rec").value;
        let iv_roll_rec = document.getElementById("iv_roll_rec").value;
        let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
              
        $.ajax({
          type: 'POST',
          url: '/delete_message',
          dataType: 'html',
          data: {
            roll_rec: roll_rec,
            iv_roll_rec: iv_roll_rec,
            roll_rec_sum: roll_rec_sum,
            group_id: group_id, 
            msg_id: msg_id
          },
          success: function(ret_data) {
            //-- If message is deleted successfully, hide the row contained the deleted message, and update the value of --//
            //-- 'update_token' on do_sms.pl to avoid page refreshing.                                                   --//
            let result = JSON.parse(ret_data);              // Note: Return data is in JSON format.
            let mg_status = result.mg_status;
            let new_token = allTrim(mg_status.update_token);
            
            switch (new_token) {
              case 'error':
                alert("Error is found when delete this message");
                break;
             
              case 'invalid':
                logoutSMS();
                break;
                               
              case 'sess_expired':
                alert("Session expired!");
                logoutSMS();
                break;

              case 'hacking':
                alert("Don't try to hack the system, you are blacklisted!");
                logoutSMS();
                break;
                
              default:    
                parent.update_token = new_token;            
                $('#row_' + msg_id).hide();
                $('#blankline_' + msg_id).hide();
                $('#omid_' + msg_id).remove();
                //-- Inform other group members to refresh message via WebSocket --//
                informGroupMembersToRefresh(group_id, user_id);                
            }
          },
          error: function(xhr, ajaxOptions, thrownError) {
            alert("Unable to delete message. Error " + xhr.status + ": " + thrownError);
          }
        });
      }
    }
    
    async function loadPrevMessages(group_id, user_id) {
      await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
      let roll_rec = document.getElementById("roll_rec").value;
      let iv_roll_rec = document.getElementById("iv_roll_rec").value;
      let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
    
      let button_status = $('#btn_load_more').attr("disabled");
      if (button_status == "disabled") {
        return false;
      }

      //-- Change button image from 'readmore.png' to 'files_uploading.gif' --//
      $('#btn_load_more').attr('src', '/images/files_uploading.gif');
      //-- Then disable it to prevent load more than one message block --//
      $('#btn_load_more').attr("disabled", "disabled");
                  
      //-- Note: 'first_msg_id' means the ID of the first message which has already loaded --//
      $.ajax({
        type: 'POST',
        url: '/pull_prev_message',
        dataType: 'json',
        data: {
          roll_rec: roll_rec,
          iv_roll_rec: iv_roll_rec,
          roll_rec_sum: roll_rec_sum, 
          group_id: group_id, 
          receiver_id: user_id, 
          first_msg_id: first_msg_id, 
          rows_limit: rows_limit
        },
        success: function(ret_data) {                     
          if (ret_data.msg_status == "error") {
            alert(ret_data.message);
          }      
          else if (ret_data.msg_status == "invalid") {
            logoutSMS();
          }         
          else if (ret_data.msg_status == "sess_expired") {
            alert(ret_data.message);
            logoutSMS();
          }         
          else if (ret_data.msg_status == "hacking") {
            alert(ret_data.message);
            logoutSMS();
          }         
          else {                       
            first_msg_id = addPrevMessageRow(JSON.parse(ret_data.message));
            if (is_iOS) {
              Cookies.set("m_id", first_msg_id, {expires: 1});      // Defined on js.cookies.min.js
            }
            else {
              setLocalStoredItem("m_id", first_msg_id);             // Defined on common_lib.js
            }
          }
          
          $('#btn_load_more').removeAttr("disabled");
          $('#btn_load_more').attr('src', '/images/readmore.png');          
        },
        error: function(xhr, ajaxOptions, thrownError) {
          alert("Unable to get previous message(s). Error " + xhr.status + ": " + thrownError);
          $('#btn_load_more').removeAttr("disabled");
          $('#btn_load_more').attr('src', '/images/readmore.png');                    
        }             
      });            
    }
        
    async function addPrevMessageRow(ret_data) {
      let the_msg_id = '';
      
      //-- Get the AES key to decrypt received messages --//
      aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
                
      for (let i = 0; i < ret_data.length; i++) {
        let rec = ret_data[i];          
        let this_msg_id = rec.msg_id;
        let this_is_my_msg = rec.is_my_msg;
        let this_user_color = (allTrim(rec.user_status) == "A")? '#8B0909' : '#A4A5A5';
        let is_member = (parseInt(rec.is_member, 10) == 0)? "(Non member)" : '';
        let this_sender_id = rec.sender_id;
        let this_sender = "<font color='" + this_user_color + "' size='2px'><b>" + rec.sender + " " + is_member + "</b></font>";
        let this_s_date = rec.s_date;
        let this_s_time_12 = rec.s_time_12;
        let this_from_now = rec.from_now;
        let this_week_day = rec.week_day;
        let this_message = await aesDecryptBase64(rec.algorithm, aes_key, rec.iv, rec.message);
        let this_fileloc = rec.fileloc;
        let this_file_link = rec.file_link;
        let this_op_flag = rec.op_flag;
        let this_op_user = rec.op_user;            
        let this_op_msg = await aesDecryptBase64(rec.algorithm, aes_key, rec.op_iv, rec.op_msg);        
        let show_time = this_s_time_12;
        let this_msg_time = "<font color='#31B404' size='2px'>" + show_time + "</font>";
        let is_new_msg = rec.is_new_msg;
        // Process " and ' characters on 'this_msg_30' to avoid syntax error //
        let this_msg_30 = processQuotationMarks(await aesDecryptBase64(rec.algorithm, aes_key, rec.msg_30_iv, rec.msg_30));
        // Process " and ' characters on 'this_msg_30' to avoid syntax error //
        this_msg_30 = this_msg_30.replace(/"/g, '“'); 
        this_msg_30 = this_msg_30.replace(/'/g, '‘');           
        let this_tr = '';
        let re_header = "";
        let fw_header = "";

        //-- With reason still unknown, extra garbage record(s) may be embedded in the return data, so it needs to --//
        //-- take this checking for returned records.                                                              --//
        if (typeof(this_msg_id) != 'undefined' && this_msg_id != null) {        
          if (this_file_link.match(/audio controls/gi)) {
            this_file_link = this_file_link + "<br>";
          }
        
          //-- If it is replied or forward message, process it here. --//
          if (this_op_flag == 'R') {
            re_header = "<table width='100%' cellspacing=2 cellpadding=6>" +
                        "<tr>" +
                        "  <td style='border-left: 5px solid #0180FF;'>" +
                        "    <font color='#0081FE' size='2px'><b>" + this_op_user + "</b></font><br>" + this_op_msg +
                        "  </td>" +
                        "</tr>" +
                        "</table>";
          }
          else if (this_op_flag == 'F') {
            fw_header = "<font color='#298A09' size='2px'>Forwarded message<br>From <b>" + this_op_user + "</b><br></font>";
          }
                
          if (first_msg_date != this_s_date) {
            let blank_tr = "<tr style='height:8px;'><td></td></tr>";
            $('#msg_table > tbody > tr').eq(0).before(blank_tr).enhanceWithin();                                  
            let date_tr = "<tr style='background-color:#D9D9D8'><td align=center>" + this_s_date + "</td></tr>";
            $('#msg_table > tbody > tr').eq(0).before(date_tr).enhanceWithin();
            first_msg_date = this_s_date
          }
                                
          if (this_is_my_msg) {
            let delete_link = "<a href=\\"javascript:deleteMessage('" + this_msg_id + "');\\">Delete</a>";
            let reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
            let forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
      
            this_tr = "<tr id='row_" + this_msg_id + "'>" +
                      "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                      "  <td width='100%'>" +
                      "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                      "    <tr>" +
                      "      <td width='${indentation}%'></td>" +
                      "      <td width='${msg_width}%' style='background-color:${my_msg_colour}; word-wrap:break-word;'>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + delete_link + " ${space3} " + reply_link + " ${space3} " + forward_link + "</td>" +
                      "    </tr>" +
                      "    </table>" +
                      "  </td>" +
                      "</tr>";
          }
          else {
            let reply_link = "<a href=\\"javascript:replyMessage('" + this_msg_id + "', " + this_sender_id + ", '" + rec.sender + "', '" + this_msg_30 + "');\\">Reply</a>";
            let forward_link = "<a href=\\"javascript:forwardMessage(" + group_id + ", '" + this_msg_id + "');\\">Forward</a>";
        
            this_tr = "<tr id='row_" + this_msg_id + "'>" +
                      "  <input type='hidden' id='omid_" + this_msg_id + "' name='omid_" + this_msg_id + "' value='" + this_msg_id + "'>" +
                      "  <td width='100%'>" +
                      "    <table width='100%' cellspacing=0 cellpadding=0 style='table-layout:fixed;'>" +
                      "    <tr>" + 
                      "      <td width='${msg_width}%' style='background-color:${rv_msg_colour}; word-wrap:break-word;'>" + this_sender + "<br>" + fw_header + re_header + this_file_link + this_message + "<br>" + this_msg_time + " ${spaces} " + reply_link + " ${space3} " + forward_link + "</td>" +
                      "      <td width='${indentation}%'></td>" +
                      "    </tr>" +
                      "    </table>" +
                      "  </td>" +
                      "</tr>";
          }
    
          $('#msg_table > tbody > tr').eq(0).after(this_tr).enhanceWithin();
          this_tr = "<tr id='blankline_" + this_msg_id + "' style='height:8px;'><td></td></tr>";
          $('#msg_table > tbody > tr').eq(0).after(this_tr).enhanceWithin();            
        
          the_msg_id = this_msg_id;
        }
      }
      
      // Clear aes_key from RAM after used //
      aes_key = '';
      
      //-- Try to retrieve the first message id of this group of this user (Note: It may not exist) --//
      let top_msg_id = (is_iOS)? Cookies.get("top_id") : getLocalStoredItem("top_id");   // Defined on js.cookie.min.js : common_lib.js
      top_msg_id = (top_msg_id == undefined)? 0 : top_msg_id;
      
      if (ret_data.length < rows_limit || the_msg_id == top_msg_id) {
        $('#read_more').hide();
        if (the_msg_id != top_msg_id) {
          if (is_iOS) {
            Cookies.set("top_id", the_msg_id, {expires: 1});
          }
          else {
            setLocalStoredItem("top_id", the_msg_id);
          }
        }
      }

      //-- Return the most updated value of 'first_msg_id' --//      
      return the_msg_id;
    }`; 
    
    js = await wev.minifyJS(js);
    
    html = `
      <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
      <link rel="shortcut icon" href="/favicon.ico">
      <script src="/js/jquery.min.js"></script>
      <script src="/js/jquery.mobile-1.4.5.min.js"></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src='/js/crypto-lib.js'></script>
      <script src="/js/common_lib.js"></script>
      
      <script>
        ${js}
      </script>
    </head>`;           
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _printMessagesDoSMSpage(conn, group_id, group_name, group_type, group_role, user_id, user_role) {
  var html, panel, admin_options, group_marker;
  
  try {
    html = ``;
    
    group_marker = (group_type == 1)? "<img src='/images/lock.png' height='15px'>" : "";
    
    if (group_role == 1 || user_role == 2) {                 // The current user is message group admin. or system admin.
      if (group_type == 1) {                                 // It is a private group.
        //-- For private messaging group (1 to 1), operations of adding member, member deletion, promoting user to group admin., --//
        //-- and demote admin. to member are not relevance.                                                                      --//
        admin_options = `
        <li data-role="list-divider" style="color:darkgreen;">Group Administration</li>
        <li><a href="javascript:autoDeleteSetup(${group_id});" data-ajax="false">Auto Delete Setup</a></li>`;
      }
      else {
        admin_options = `
        <li data-role="list-divider" style="color:darkgreen;">Group Administration</li>
        <li><a href="javascript:addGroupMember(${group_id});" data-ajax="false">Add Member</a></li>
        <li><a href="javascript:deleteGroupMember(${group_id});" data-ajax="false">Delete Member</a></li>            
        <li><a href="javascript:promoteGroupMember(${group_id});" data-ajax="false">Promote Member</a></li>
        <li><a href="javascript:demoteGroupAdmin(${group_id});" data-ajax="false">Demote Admin</a></li>
        <li><a href="javascript:informMember(${group_id});" data-ajax="false">Inform Member</a></li>`;
      }
      
      //-- Group administrator --//
      panel = `
        <div data-role="panel" data-position-fixed="true" data-position="left" data-display="overlay" id="setup">
          <div data-role="main" class="ui-content">
            <ul data-role="listview">
              <li><a href="javascript:goHome();" data-ajax="false">Go Home</a></li>
              <li data-role="list-divider" style="color:darkgreen;">Group Profile</li>
              <li><a href="javascript:changeGroupName(${group_id});" data-ajax="false">Change Group Name</a></li>
              <li><a href="javascript:listGroupMember(${group_id});" data-ajax="false">List Member</a></li>            
              <li><a href="javascript:quitMessageGroup(${group_id}, ${user_id});" data-ajax="false">Exit Group</a></li>
              ${admin_options}
              <li data-role="list-divider" style="color:darkgreen;">Emergency</li>
              <li><a href="javascript:deleteThisGroup(${group_id});" data-ajax="false">Delete Group</a></li>
            </ul>	
          </div>
        </div>`;	    
    }
    else {
      //-- Ordinary group member --// 
      panel = `
        <div data-role="panel" data-position-fixed="true" data-position="left" data-display="overlay" id="setup">
          <div data-role="main" class="ui-content">
            <ul data-role="listview">
              <li><a href="javascript:goHome();" data-ajax="false">Go Home</a></li> 
              <li data-role="list-divider" style="color:darkgreen;">Group Profile</li>
              <li><a href="javascript:changeGroupName(${group_id});" data-ajax="false">Change Group Name</a></li>
              <li><a href="javascript:listGroupMember(${group_id});" data-ajax="false">List Member</a></li>            
              <li><a href="javascript:quitMessageGroup(${group_id}, ${user_id});" data-ajax="false">Exit Group</a></li>
            </ul>	
          </div>
        </div>`;	    
    }
    
    html = `
    <div id="dosms" data-role="page">
      ${panel}
      
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="#setup" data-icon="bars" class="ui-btn-left">Setup</a>					
        <h1>${group_marker}${group_name}</h1>
        <a href="javascript:logoutSMS();" data-icon="power" class="ui-btn-right" data-ajax="false">Quit</a>
      </div>	
      
      <div data-role="content" style="overflow-y:auto;" data-position="fixed" data-tap-toggle="false">
        <!-- The form is used to switch to another page with rolling key mechanism embedded -->
        <form id="frmLeap" name="frmLeap" action="" method="POST">
          <input type=hidden id="roll_rec" name="roll_rec" value="">
          <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
          <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
          <input type=hidden id="from_group_id" name="from_group_id" value="">
          <input type=hidden id="msg_id" name="msg_id" value="">            
          <input type=hidden id="g_id" name="g_id" value="">
          <input type=hidden id="member_id" name="member_id" value="">   
        </form>
      
        <table id="msg_table" width=100% cellspacing=0 cellpadding=0 style="table-layout:fixed;">
        <thead><tr id="read_more"><td align=center valign=center><img src='/images/files_uploading.gif' width="50%"></td></tr></thead>
        <tbody>
          <!-- Messages will be put in here -->  
        </tbody>
        </table>
      </div>
      
      <div id="page_end" style="overflow-y:auto;"></div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr><td></td></tr>
        </thead>
        <tbody>
          <tr id="reply_row">
           <td colspan=4>
             <table width=100% cellpadding=0 cellspacing=0>
             <thead>
               <tr><td></td></tr>
             </thead>
             <tbody>
               <tr>
                 <td align=center valign=center><img src="/images/reply.png" width="28px"></td>
                 <td width="75%" id="reply_msg_area"></td>
                 <td align=center valign=center><img src="/images/cross.png" width="30px" onClick="javascript:noReply();"></td>
               </tr>
             </tbody>
             </table>
            </td>
          </tr>
          
          <tr id="text_send">
            <td width="78%" id="msg_area"><textarea id="s_message" name="s_message" autofocus data-role="none" class="s_message"></textarea></td>
            <td id="btn_msg_send" align=center valign=center><a href="javascript:sendMessage(${group_id}, ${user_id});"><img src="/images/send.png" width="50px"></a></td>
            <td id="btn_attach_file" align=center><a href="javascript:attachFile();"><img src="/images/attachment.png" width="27px"></a></td>
            <td id="btn_audio_input" align=center><a href="javascript:audioInput();"><img src="/images/mic.png" width="30px"></a></td>          
          </tr>
          
          <tr id="file_upload" style="display:none">
            <td colspan=4>
              <table width=100% cellspacing=0 cellpadding=0>
              <thead><tr><td></td></tr></thead>
              <tbody>
              <tr>
                <td align=center valign=top><img src="/images/camera.png" width="50px" onClick="openCamera();"><br>Camera</td>
                <td align=center valign=top><img src="/images/file.png" width="50px" onClick="selectFileToUpload();"><br>File</td>
                <td align=center valign=top><img src="/images/hide.png" width="50px" onClick="showTextInputPanel();"></td>
              </tr>
              </tbody>
              </table>
            </td>
          </tr>
          
          <tr id="go_camera" style="display:none">
            <td colspan=4>
              <table width=100% cellspacing=0 cellpadding=0>
              <thead><tr><td></td></tr></thead>
              <tbody>
              <tr>
                <td align=center valign=center nowap>
                  <img src="/images/hide.png" width="50px" onClick="showTextInputPanel();">
                </td>                        
                <td width="65%" valign=center>
                  <input type="file" id="photo" name="photo" accept="image/*" capture="camera">
                  <input type=text id="caption" name="caption"> 
                </td>
                <td align=center valign=center nowap>
                  <img id="btn_send_photo" src="/images/send.png" width="50px" onClick="sendPhoto(${group_id}, ${user_id});">
                </td>
              </tr>
              </tbody>
              </table>          
            </td>
          </tr>
          
          <tr id="go_file" style="display:none">
            <td colspan=4>
              <table width=100% cellspacing=0 cellpadding=0>
              <thead><tr><td></td></tr></thead>
              <tbody>
              <tr>
                <td align=center valign=center nowap>
                  <img src="/images/hide.png" width="50px" onClick="showTextInputPanel();">
                </td>            
                <td width="65%" valign=center>
                  <input type="file" id="ul_file" name="ul_file">
                </td>
                <td align=center valign=center nowap>
                  <img id="btn_send_file" src="/images/send.png" width="50px" onClick="sendFile(${group_id}, ${user_id});">
                </td>
              </tr>
              </tbody>
              </table>
            </td>  
          </tr>
          
          <tr id="go_audio" style="display:none">
            <td colspan=4>
              <table width=100% cellspacing=0 cellpadding=0>
              <thead><tr><td></td></tr></thead>
              <tbody>
              <tr>
                <td align=center valign=center nowap>
                  <img src="/images/hide.png" width="50px" onClick="showTextInputPanel();">
                </td>                        
                <td width="65%" valign=center>
                  <input type="file" id="sound" name="sound" accept="audio/*" capture="microphone">
                  <script>
                    var soundElement = document.getElementById("sound");
                    soundElement.addEventListener("change", soundFileHandler, "false");     
                    
                    function soundFileHandler() {
                      //*****************
                      console.log("see me?");
                    
                      var filelist = this.files;
                      
                      // Note: If it is tested ok, the sound file uploading operation must be moved in here. // 
                                  
                      for (var i = 0; i < filelist.length; i++) {
                        var fname = filelist[i].name;
                        var fsize = filelist[i].size;
                        var ftype = filelist[i].type;
                        
                        console.log(fname + ', ' + fsize + ', ' + ftype);              
                      }
                      
                      $('#btn_send_sound').removeAttr("disabled");
                      $('#btn_send_sound').attr('src', '/images/send.png');
                      
                      return false;      
                      //******************                   
                    }                                 
                  </script>
                </td>
                <td align=center valign=center nowap>
                  <img id="btn_send_sound" src="/images/send.png" width="50px" onClick="sendSound(${group_id}, ${user_id});">
                </td>
              </tr>
              </tbody>
              </table>          
            </td>          
          </tr>
        </tbody>  
        </table>
      </div>    
    </div>`;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.getUserName = async function(conn, user_id) {
  var sql, param, data, user_name;
  
  user_name = '';
  
  try {
    sql = `SELECT user_name, user_alias ` +
          `  FROM user_list ` +
          `  WHERE user_id = ?`;
          
    param = [user_id];
    data = await dbs.sqlQuery(conn, sql, param);
    data = JSON.parse(data);      
    
    if (data.length > 0) {
      user_name = (data[0].user_alias.trim() != '')? data[0].user_alias : data[0].user_name;
    }
    else {
      throw new Error('Unable to get user name. User ID is ' + user_id);
    }
  }
  catch(e) {
    throw e; 
  }
  
  return user_name;
} 


exports.showDoSMSpage = async function(msg_pool, user_id, group_id, f_m_id, top_id, client_device_info, http_user_agent) {
  var conn, user_role, group_name, update_token, group_role, group_type, rows_limit, m_site_dns, wspath, html;
  var my_msg_colour = '#F5EDB3';              // Background colour of my message.
  var rv_msg_colour = '#CFF3F9';              // Background colour of received message.
  //-- Let message and identation width percentage be two variables to simplify program maintenance. --//
  var msg_width = 90;                         // Message width percentage.
  var indentation = 100 - msg_width;          // Indentation width percentage.
  var m_params = {};
  var message = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, 'COOKIE_MSG');
    
    user_role = await getUserRole(conn, user_id);             // User role of the messaging system
    group_name = await msglib.getMessageGroupName(conn, group_id);
    update_token = await msglib.getMessageUpdateToken(conn, group_id);
    group_role = await msglib.getGroupRole(conn, group_id, user_id);
    group_type = await msglib.getGroupType(conn, group_id);
    rows_limit = await getMessageBlockSize(conn);             // Number of messages will be loaded initially.
    m_params = {new_msg_only: 0, rows_limit: rows_limit, f_m_id: f_m_id};
    //-- Note: message loading operation is moved into the web page by using ajax, in order to encrypt all loading messages. --// 
    //message = await msglib.getGroupMessage(conn, group_id, user_id, m_params, client_device_info, http_user_agent);
    
    //-- Construct websocket access path from DNS of messaging site. It will --//
    //-- be in format "wss://<your messaging site>/ws".                      --//        
    m_site_dns = await wev.getSiteDNS(conn, 'M');
    if (m_site_dns != '') {
      wspath = m_site_dns.replace('https', 'wss') + '/ws';
      
      //-- Construct web page --//
      html = await _printStyleDoSMSpage();
      html += await _printJavascriptDoSMSpage(conn, m_site_dns, wspath, group_id, user_id, update_token, msg_width, indentation, my_msg_colour, rv_msg_colour, rows_limit, top_id, m_params); 
      html += await _printMessagesDoSMSpage(conn, group_id, group_name, group_type, group_role, user_id, user_role);          
    }
    else {
      throw new Error('Unable to find DNS of messaging site');
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
 
  return html; 
}


async function _deleteRollingKey(conn, sess_code) {
  let sql, param;
  
  try {
    sql = `DELETE FROM sess_roll_key ` +
          `  WHERE sess_code = ?`;
          
    param = [sess_code];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }
}


exports.deleteSession = async function(db_pool, sess_code, conn_option) {
  let conn, url;
  
  try {
    conn_option = (typeof(conn_option) != "string")? "" : conn_option; 
    conn = await dbs.getPoolConn(db_pool, dbs.selectCookie(conn_option));    
    await _deleteSession(conn, sess_code);
    
    if (conn_option == "MSG") {    
      await _deleteRollingKey(conn, sess_code);
      url = await _selectSiteForVisitor(conn);
    }
    else {
      url = "/";
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);    
  }
  
  return url;
}


exports.getRandomSiteForVisitor = async function(msg_pool) {
	let conn, url;
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));		
		url = await _selectSiteForVisitor(conn);		
	}
	catch(e) {
		_consoleLog(e.message);
		url = "https://www.microsoft.com";
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return url;
}


async function _getGroupsCouldBeForwarded(conn, user_id) {
  var sql, param, data;
  var result = [];

  try {
    sql = `SELECT a.group_id, a.group_name, a.group_type ` +
          `  FROM msg_group a, group_member b ` +
          `  WHERE a.group_id = b.group_id ` +
          `    AND b.user_id = ? ` +
          `  ORDER BY a.group_name`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      result.push({group_id: data[i].group_id, group_name: data[i].group_name, group_type: data[i].group_type});
    }      
  }
  catch(e) {
    throw e;
  }

  return result;
}


async function _printFwMsgJavaScriptSection(sess_code) {
  let html;
  
  try {
    html = `
    <!doctype html>
      <html>
      <head>
        <title>Message</title>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>
      </head>  
  
      <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
      <link rel="shortcut icon" href="/favicon.ico">
      <script src="/js/jquery.min.js"></script>
      <script src="/js/jquery.mobile-1.4.5.min.js"></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src='/js/crypto-lib.js'></script>
      <script src="/js/common_lib.js"></script>
      
      <script>
        let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
        let algorithm = "AES-GCM";
        let aes_key = "";
      
        async function forwardMessage() {
          await prepareRollingKey(${_key_len});
        
          let value = parseInt($('input[name=to_group_id]:checked', '#frm_forward').val(), 10);
          if (isNaN(value)) {
            alert("Please select a group to let message forward to");
          }
          else {
            let key_ready = true;
            let err_msg = "";
            aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
          
            if (typeof(aes_key) != "string") {
              key_ready = false;
              err_msg = "Session secure key is lost, the system is going to log you out!";
            }
            else {
              if (aes_key.trim().length < ${_key_len}) {
                key_ready = false;
                err_msg = "Session secure key length is too short, something is wrong. The system is going to log you out.";
              }
            }  
          
            if (key_ready) {
              //-- Encrypt additional message before send it out, even it is blank. --//
              let a_message = document.getElementById("a_message").value;
              let enc_obj = await aesEncryptJSON(algorithm, aes_key, a_message);
              
              document.getElementById("algorithm").value = algorithm;
              document.getElementById("a_iv").value = enc_obj.iv;
              document.getElementById("a_enc_msg").value = enc_obj.encrypted;
              document.getElementById("a_message").value = '';                                                      
              document.getElementById("oper_mode").value = "S";
              
              // Clear AES key from RAM after used //
              aes_key = null;
              
              document.getElementById("frm_forward").submit();
            }
            else {
              alert(err_msg);
              window.location.href = "/logout_msg";
            }
          }
        }
        
        async function goBack(from_group_id) {
          await prepareRollingKey(${_key_len}); 
        
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          document.getElementById("g_id").value = from_group_id;
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_forward").action = "/do_sms";
          document.getElementById("frm_forward").submit();
        }
      </script>`;
  }
  catch(e) {
    throw e;
  }  
  
  return html;  
}


async function _printFwMsgStyleSection() {
  var html;
  
  try {
    html = `<style>
              .a_message {
                width:95%;
                height:120px;
                max-height:200px;
              }
            </style>`;
  }
  catch(e) {
    throw e;
  }

  return html;  
}


async function _printFwMsgGroupSelectionForm(from_group_id, user_id, msg_id, groups) {
  var html, private_group_marker, cnt;
  
  try {
    private_group_marker = "<img src='/images/lock.png' height='15px'>";
    
    html = `<form id="frm_forward" name="frm_forward" action="/save_forward_message" method="post">
            <input type=hidden id="oper_mode" name="oper_mode" value="">
            <input type=hidden id="from_group_id" name="from_group_id" value="${from_group_id}">
            <input type=hidden id="msg_id" name="msg_id" value="${msg_id}">
            <input type=hidden id="algorithm" name="algorithm" value="AES-GCM">
            <input type=hidden id="a_iv" name="a_iv" value="">
            <input type=hidden id="a_enc_msg" name="a_enc_msg" value="">
            <input type=hidden id="g_id" name="g_id" value="">
            <input type=hidden id="f_m_id" name="f_m_id" value="">
            <input type=hidden id="top_id" name="top_id" value="">
            <input type=hidden id="roll_rec" name="roll_rec" value="">
            <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
            <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
                          
            <div data-role="page">
              <div data-role="header" data-position="fixed">
                <a href="javascript:goBack(${from_group_id});" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>    
                <h1>Forward to...</h1>
              </div>	
          
              <div data-role="main" class="ui-body-d ui-content">    
                <fieldset data-role="controlgroup">
                <table width=100% cellpadding=0 cellspacing=0>
                <thead>
                  <tr style="background-color:lightblue"><td align=center><b>Group</b></td></tr>
                </thead>
                <tbody>`;
    
    cnt = 0;
    for (var i = 0; i < groups.length; i++) {
      var this_group_id = groups[i].group_id;
      var this_group_name = groups[i].group_name;
      var this_group_marker = (parseInt(groups[i].group_type, 10) == 1)? private_group_marker : '';
      
      cnt++;
      html += `<tr style="background-color:lightyellow">
                 <td>
                   <input type="radio" id="to_group_id_${cnt}" name="to_group_id" value="${this_group_id}"><label for="to_group_id_${cnt}">${this_group_marker}${this_group_name}</label>
                 </td>
               </tr>`;      
    }            
                
    html += `    </tbody>
                 </table>
                 </fieldset>
                 <br>
                 <label for="a_message"><b>Additional message:</b></label>
                 <textarea id="a_message" name="a_message" autofocus data-role="none" class="a_message"></textarea>
               </div>
          
               <div data-role="footer" data-position="fixed">
                 <table width=100% cellpadding=0 cellspacing=0>
                 <thead>
                   <tr><td></td></tr>
                 </thead>
                 <tbody>  
                 <tr>    
                   <td align=center valign=center><input type="button" id="save" name="save" value="Go Forward" onClick="forwardMessage();"></td>
                 </tr>
                 </tbody>
                 </table>
               </div>    
             </div>
             </form>`;            
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.showForwardMessageForm = async function(msg_pool, from_group_id, user_id, msg_id, sess_code, http_user_agent, ip_addr) {
  var conn, html;
  var groups = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    groups = await _getGroupsCouldBeForwarded(conn, user_id);
    
    html = await _printFwMsgJavaScriptSection(sess_code);
    html += await _printFwMsgStyleSection();
    html += await _printFwMsgGroupSelectionForm(from_group_id, user_id, msg_id, groups);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.returnToSMSpageHTML = async function(group_id, message) {
  let html;
  
  try {
    message = (typeof(message) != "string")? "" : message;
    
    html = `
    <!doctype html>
    <html>
      <head>
        <script type="text/javascript" src='/js/jquery.min.js'></script>
        <script type="text/javascript" src="/js/js.cookie.min.js"></script>
        <script type="text/javascript" src='/js/crypto-lib.js'></script>               
        <script type="text/javascript" src='/js/common_lib.js'></script>
                        
        <script>
          $(document).ready(function() {
            let message = "${message}";
            
            if (message.trim() != "") {
              alert("${message}");
            }
            
            switchPage();
          });
          
          async function switchPage() {
            await prepareRollingKey(${_key_len});
            let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
            let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
            let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id"); 
            document.getElementById("g_id").value = ${group_id};
            document.getElementById("f_m_id").value = f_m_id;
            document.getElementById("top_id").value = top_id;
            document.getElementById("frmLeap").submit();
          }
        </script>
      </head>
      
      <body>
        <form id="frmLeap" name="frmLeap" action="/do_sms" method="POST">
          <input type=hidden id="roll_rec" name="roll_rec" value="">
          <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
          <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
          <input type=hidden id="g_id" name="g_id" value="">
          <input type=hidden id="f_m_id" name="f_m_id" value="">
          <input type=hidden id="top_id" name="top_id" value="">
        </form>        
      </body>        
    </html>`;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _includeJsLib(title) {
  var html;
  
  html = `
  <!DOCTYPE html>
  <html>
  <head>
    <title>${title}</title>
    <meta name="viewport" content="minimum-scale=1.0, width=device-width, maximum-scale=1.0, initial-scale=1.0, user-scalable=no">   
    <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>                
  </head>
  <body style="width:auto;">  
  <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
  <link rel="shortcut icon" href="/favicon.ico">
  <script src="/js/jquery.min.js"></script>
  <script src="/js/jquery.mobile-1.4.5.min.js"></script>
  <script src="/js/js.cookie.min.js"></script>
  <script src='/js/crypto-lib.js'></script>
  <script src="/js/common_lib.js"></script>
  `;
  
  return html;
}


exports.showGroupNameAmendPage = async function(msg_pool, group_id) {
  var conn, group_name, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    group_name = await msglib.getGroupName(conn, group_id);
    
    html = _includeJsLib('Change Group Name');
    
    html += `
    <script>
      async function goBack() {
        await prepareRollingKey(${_key_len});
      
        let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
        //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
        let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
        let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
        document.getElementById("f_m_id").value = f_m_id;
        document.getElementById("top_id").value = top_id;
        document.getElementById("frm_profile").action = "/do_sms";
        document.getElementById("frm_profile").submit();
      }
    
      async function updateGroupName() {
        let g_name = document.getElementById("group_name").value;
        
        if (allTrim(g_name) == "") {
          alert("Group name should not be blank");
          document.getElementById("group_name").focus();
        }
        else {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_profile").submit();
        }
      }    
    </script>
    
    <form id="frm_profile" name="frm_profile" action="/save_change_group_name" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type="hidden" id="f_m_id" name="f_m_id" value="">
    <input type="hidden" id="top_id" name="top_id" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Group Name</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <label for="group_name">Group name:</label>
        <input type="text" id="group_name" name="group_name" value="${group_name}">
        <br>
        <input type="button" id="save" name="save" value="Change" onClick="updateGroupName();">            
      </div>  
    </div>
    </form>`;
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.updateGroupName = async function(msg_pool, group_id, group_name) {
  var conn, sql, param;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    sql = `UPDATE msg_group ` +
          `  SET group_name = ? ` +
          `  WHERE group_id = ?`;
    
    param = [group_name, group_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {    
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
}


exports.listGroupMember = async function(msg_pool, group_id) {
  var conn, html;
  var members = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    members = await msglib.getMessageGroupMembers(conn, group_id);

    html = _includeJsLib('List Member');    
    
    html += `
    <script>
      async function goBack() {
        await prepareRollingKey(${_key_len});
      
        let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
        //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
        let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
        let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
        document.getElementById("f_m_id").value = f_m_id;
        document.getElementById("top_id").value = top_id;
        document.getElementById("frm_profile").action = "/do_sms";
        document.getElementById("frm_profile").submit();
      }
    </script>

    <div data-role="page">
      <div data-role="header" style="overflow:hidden;">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Members</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <form id="frm_profile" name="frm_profile" action="/save_change_group_name" method="post">
          <input type="hidden" id="g_id" name="g_id" value="${group_id}">
          <input type="hidden" id="f_m_id" name="f_m_id" value="">
          <input type="hidden" id="top_id" name="top_id" value="">
          <input type=hidden id="roll_rec" name="roll_rec" value="">
          <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
          <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        </form>  
      
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td><td align=center><b>Role</b></td></tr>
        </thead>
        <tbody>`;
        
    for (var i = 0; i < members.length; i++) {
      var this_member = (wev.allTrim(members[i].alias) == '')? members[i].username : members[i].alias;
      var this_group_role = (parseInt(members[i].group_role, 10) == 1)? 'Group Admin' : '';

      html += `
        <tr style="background-color:lightyellow">
          <td align=center>${this_member}</td>
          <td align=center>${this_group_role}</td>
        </tr>`;      
    }  
    
    html += `
        <tr style="background-color:lightblue; height:22px;"><td colspan=2></td></tr>
        </tbody>  
        </table>
      </div>  
    </div>`;    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.quitMessageGroup = async function(msg_pool, group_id, member_id) {
  var conn, sql, param, data;  
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    //-- Step 1: Remove group membership --//
    sql = `DELETE FROM group_member ` +
          `  WHERE group_id = ? ` +
          `    AND user_id = ?`;
    
    param = [group_id, member_id];
    await dbs.sqlExec(conn, sql, param);
    
    //-- Step 2: Remove group message transactions which this user is receiver --//
    sql = `SELECT DISTINCT hex(a.msg_id) AS msg_id ` +
          `  FROM message a, msg_tx b ` +
          `  WHERE a.msg_id = b.msg_id ` +
          `    AND a.group_id = ? ` +
          `    AND b.receiver_id = ? `;
          
    param = [group_id, member_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      sql = `DELETE FROM msg_tx ` +
            `  WHERE hex(msg_id) = ? ` +
            `    AND receiver_id = ?`;
            
      param = [data[i].msg_id, member_id];
      await dbs.sqlExec(conn, sql, param);
    }      
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
}


exports.showAddGroupMemberPage = async function(group_id) {
  var html;
  
  try {
    html = _includeJsLib('Add New Member');
    
    html += `
    <script>
      var idx = 0;
  
      $(document).on("pagecreate", function() {
        for (i = 1; i <= 5; i++) {
          addMemberInput(); 
        }    
      });    
  
      function addMemberInput() {
        idx++;
        
        $("#member_section").each(
          function() {
            var id = "new_member_" + idx;
            var row = "<tr id='row_" + idx + "'><td><input type='text' id='" + id + "' name='" + id + "'/></td></tr>";
            //*-- Note: jQuery mobile API function ".enhanceWithin()" will apply default CSS settings to dynamically added objects --*//
            $(this).append(row).enhanceWithin();
          }
        );      
      }
      
      function deleteMemberInput() {
        if (idx > 1) {
          $("#row_" + idx).remove();
          idx--;
        }
      }  
  
      async function addNewMember() {
        if (newMemberDataSetOk()) {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById("frm_profile").submit();
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
            
      function newMemberDataSetOk() {
        var count = 0;    
        for (i = 1; i <= idx; i++) {
          if (document.getElementById("new_member_" + i) != null) {
            var member = allTrim(document.getElementById("new_member_" + i).value);
            if (member != "") {
              count++;  
            }
          }
        }
        
        if (count == 0) {
          alert("You should invite at least one person to create a message group");
          return false;
        }
        
        return true;
      }
      
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
        
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }        
    </script>
    
    <form id="frm_profile" name="frm_profile" action="/save_group_member" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type=hidden id="f_m_id" name="f_m_id" value="">
    <input type=hidden id="top_id" name="top_id" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Add Member</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <table id="member_section" width=100% cellpadding=0 cellspacing=0>
        <thead>
          <tr><td>Who will be invited (alias):</td></tr>
        </thead>
        <tbody>
          <!-- Rows will be added dynamically //-->
        </tbody>  
        </table>
              
        <table width=100%>
        <thead><tr><td colspan=3></td></tr></thead>
        <tbody>
        <tr>  
          <td align=left width=35%><a href="#" data-icon="plus" data-role="button" data-ajax="false" onClick="addMemberInput();">More</a></td>
          <td></td>
          <td align=right width=35%><a href="#" data-icon="minus" data-role="button" data-ajax="false" onClick="deleteMemberInput();">Less</a></td>
        </tr>
        </tbody>
        </table>
        
        <br>
        <input type="button" id="save" name="save" value="Add" onClick="addNewMember();">            
      </div>
    </div>
    </form>  
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.showDeleteGroupMemberPage = async function(msg_pool, group_id, user_id) {
  let conn, cnt, html;
  let members = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    members = await msglib.getMessageGroupMembers(conn, group_id);
    
    html = _includeJsLib('Delete Member');
    
    html += `
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
        
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        } 
      }        

      async function deleteMember(cnt) {
        let select_cnt = 0;

        try {       
          for (idx = 1; idx <= cnt; idx++) {
            if (document.getElementById("dm_id_" + idx).checked) {
              select_cnt++;
            }
          }
          
          if (select_cnt == 0) {
            alert("You must select at least one member to proceed");
            return false;
          }
          else {
            await prepareRollingKey(${_key_len});        
            document.getElementById("frm_profile").submit();
          }
        }
        catch(e) {
          alert(e.message);
        }
      }    
    </script>
    
    <form id="frm_profile" name="frm_profile" action="/confirm_delete_group_member" method="POST">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type=hidden id="f_m_id" name="f_m_id" value="">
    <input type=hidden id="top_id" name="top_id" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Delete Member</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td><td align=center><b>Role</b></td></tr>
        </thead>
        <tbody>`;
    
    cnt = 0;    
    for (let i = 0; i < members.length; i++) {
      let this_user_id = members[i].user_id;
      let this_member = (wev.allTrim(members[i].alias) == '')? wev.allTrim(members[i].username) : wev.allTrim(members[i].alias);
      let this_group_role = (members[i].group_role == 1)? 'Group Admin' : '';       
      
      if (this_user_id != user_id) {    // Don't delete yourself
        cnt++;
        
        html += `
        <tr style="background-color:lightyellow">
          <td>
            <input type="checkbox" id="dm_id_${cnt}" name="dm_id_${cnt}" value="${this_user_id}"><label for="dm_id_${cnt}">${this_member}</label>
          </td>
          <td align=center>${this_group_role}</td>
        </tr>`;
      }              
    }
    
    html += `
        </tbody>  
        </table>
        <br>
        <input type="button" id="save" name="save" value="Delete" onClick="deleteMember(${cnt});">
      </div>  
    </div>
    </form>`;            
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.showPromoteGroupMemberPage = async function(msg_pool, group_id, user_id) {
  var conn, cnt, html;
  var members = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    members = await msglib.getMessageGroupMembers(conn, group_id);
    
    html = _includeJsLib('Promote Member');

    html += `
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});    // Defined on crypto-lib.js
        
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }        

      async function promoteMember(cnt) {
        let select_cnt = 0;

        try {      
          for (idx = 1; idx <= cnt; idx++) {
            if (document.getElementById("pm_id_" + idx).checked) {
              select_cnt++;
            }
          }
          
          if (select_cnt == 0) {
            alert("You must select at least one member to promote");
            return false;
          }
          else {
            await prepareRollingKey(${_key_len});    // Defined on crypto-lib.js
            document.getElementById("frm_profile").submit();
          }    
        }
        catch(e) {
          alert(e.message);
        }  
      }
    </script>
    
    <form id="frm_profile" name="frm_profile" action="/confirm_promote_group_member" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type="hidden" id="f_m_id" name="f_m_id" value="">
    <input type="hidden" id="top_id" name="top_id" value="">    
    <input type="hidden" id="roll_rec" name="roll_rec" value="">
    <input type="hidden" id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type="hidden" id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Promote Member</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <b>Select member(s) to become group administrator:</b>
        <br>
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td></tr>
        </thead>
        <tbody>`;
    
    cnt = 0;
    for (var i = 0; i < members.length; i++) {
      var this_user_id = members[i].user_id;
      var this_member = (wev.allTrim(members[i].alias) == '')? wev.allTrim(members[i].username) : wev.allTrim(members[i].alias);
      var this_group_role = parseInt(members[i].group_role, 10);       

      if (this_user_id != user_id && this_group_role == 0) {  // Don't promote yourself, and only ordinary member(s) can be promoted to group admin.
        cnt++;
        
        html += `
        <tr style="background-color:lightyellow">
          <td>
            <input type="checkbox" id="pm_id_${cnt}" name="pm_id_${cnt}" value="${this_user_id}"><label for="pm_id_${cnt}">${this_member}</label>
          </td>
        </tr>`;
      }      
    }
    
    if (cnt > 0) {
      html += `
          </tbody>  
          </table>
          <br>
          <input type="button" id="save" name="save" value="Promote" onClick="promoteMember(${cnt});">
        </div>  
      </div>
      </form>`;
    }
    else {
      html += `
          <tr style="background-color:lightyellow">
            <td>No group member is available to be promoted to group administrator</td>
          </tr>
          </tbody>  
          </table>
        </div>  
      </div>
      </form>`;
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


exports.showDemoteGroupAdminPage = async function(msg_pool, group_id, user_id) {
  var conn, cnt, html;
  var members = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    members = await msglib.getMessageGroupMembers(conn, group_id);
    
    html = _includeJsLib('Demote Member');
    
    html += `
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});    // Defined on crypto-lib.js
        
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }        

      async function confirmDemoteGroupAdmin(cnt) {
        let select_cnt = 0;
      
        try {
          for (idx = 1; idx <= cnt; idx++) {
            if (document.getElementById("da_id_" + idx).checked) {
              select_cnt++;
            }
          }
          
          if (select_cnt == 0) {
            alert("You must select at least one group administrator to demote");
            return false;
          }
          else {
            await prepareRollingKey(${_key_len});    // Defined on crypto-lib.js
            document.getElementById("frm_profile").submit();
          }    
        }
        catch(e) {
          alert(e.message);
        }  
      }
    </script>

    <form id="frm_profile" name="frm_profile" action="/confirm_demote_group_admin" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type="hidden" id="f_m_id" name="f_m_id" value="">
    <input type="hidden" id="top_id" name="top_id" value="">    
    <input type="hidden" id="roll_rec" name="roll_rec" value="">
    <input type="hidden" id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type="hidden" id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Demote Admin</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <b>Select group administrator(s) to demote:</b>
        <br>    
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr><td></td></tr>
        </thead>
        <tbody>`;
    
    cnt = 0;
    for (var i = 0; i < members.length; i++) {
      var this_user_id = members[i].user_id;
      var this_member = (wev.allTrim(members[i].alias) == '')? wev.allTrim(members[i].username) : wev.allTrim(members[i].alias);
      var this_group_role = parseInt(members[i].group_role, 10);       

      if (this_user_id != user_id && this_group_role == 1) {   // Don't demote yourself, and only group administrator can be demoted.
        cnt++;
        
        html += `
        <tr style="background-color:lightyellow">
          <td>
            <input type="checkbox" id="da_id_${cnt}" name="da_id_${cnt}" value="${this_user_id}"><label for="da_id_${cnt}">${this_member}</label>
          </td>
        </tr>`;
      }
    }
    
    if (cnt > 0) {
      html += `
          </tbody>  
          </table>
          <br>
          <input type="button" id="save" name="save" value="Demote" onClick="confirmDemoteGroupAdmin(${cnt});">
        </div>  
      </div>
      </form>`;
    }
    else {
      html += `
          <tr style="background-color:lightyellow">
            <td>No group administrator is available to be demoted</td>
          </tr>
          </tbody>  
          </table>
        </div>  
      </div>
      </form>`;
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


exports.showManualInformMemberPage = async function(group_id) {
  var html, inform_message;
  
  try {
    inform_message = "You have important message, please check for it ASAP.";
    
    html = _includeJsLib('Inform Member');
        
    html += `
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
          
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }        
    
      async function sendInformMessage() {
        let message = allTrim(document.getElementById("inform_message").value);
        if (message == "") {
          alert("Please input notification message before click send button.");
          document.getElementById("inform_message").focus();
        }
        else {
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js        
          document.getElementById("to_be_inform").style.display = "none";      // Hide the table row
          document.getElementById("go_inform").style.display = "table-row";    // Show the table row      
          document.getElementById("frm_profile").submit();        
        }
      }        
    </script>    
    
    <form id="frm_profile" name="frm_profile" action="/confirm_inform_member" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type="hidden" id="f_m_id" name="f_m_id" value="">
    <input type="hidden" id="top_id" name="top_id" value="">
    <input type="hidden" id="roll_rec" name="roll_rec" value="">
    <input type="hidden" id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type="hidden" id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Inform Member</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <table id="member_section" width=100% cellpadding=0 cellspacing=0>
        <thead>
          <tr><td><b>Message to be sent:</b></td></tr>
        </thead>
        <tbody>
          <tr>
            <td><textarea id="inform_message" name="inform_message" autofocus data-role="none" style="width:100%; height:150px; max-height:300px;">${inform_message}</textarea></td>
          </tr>
          
          <tr><td>&nbsp;</td></tr>
          
          <tr id="to_be_inform" style="display:table-row">
            <td align=center width=100%><input type="button" id="send" name="send" value="Send" onClick="sendInformMessage();"></td>  
          </tr>
          
          <tr id="go_inform" style="display:none">
            <td align=center valign=center width=100%><img src="/images/files_uploading.gif" width="40px"><br>Sending....</td>
          </tr>
        </tbody>  
        </table>                                    
      </div>
    </div>
    </form>`;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.buildGroupDeletedInformHTML = async function(msg_pool, group_id, members) {
  var conn, html, jsonMembers, m_site_dns, wspath;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    jsonMembers = JSON.stringify(members);
    
    //-- Construct websocket access path from DNS of messaging site. It will --//
    //-- be in format "wss://<your messaging site>/ws".                      --//        
    m_site_dns = await wev.getSiteDNS(conn, 'M');
    if (m_site_dns != '') {
      wspath = m_site_dns.replace('https', 'wss') + '/ws';
    }
    else {
      wspath = '';
    }
        
    html = _includeJsLib('Inform Member');
    
    if (wspath != '') {
      html += `
      <script>
        var members = ${jsonMembers};     // Note: 'jsonMembers' in here is an object, not string. 
        
        var group_id = ${group_id};
        var myWebSocket = null;
        var wsOpenSocket = null;   
        var is_reopen = false;
        
        function connectWebServer() {
          var ws = new WebSocket("${wspath}");
                                            
          function reopenWebSocket() {                                    
            is_reopen = true; 
            myWebSocket = connectWebServer();
          }
        
          ws.onopen = function(e) {
            var this_cmd = {type: 'cmd', content:{op: 'group_deleted', group_id: group_id, members: members}};
            groupDeleted(this_cmd);
          }
                              
          ws.onerror = function(e) {
            console.log('Error: ' + e.message);
          }
          
          return ws;
        }  
        
        $(document).on("pageshow", function(event) {
          //-- Open a websocket and send out group deleted message --//
          myWebSocket = connectWebServer();      
        });

        async function groupDeleted(cmd) {
          var message = JSON.stringify(cmd);
          
          if (myWebSocket.readyState == WebSocket.OPEN) {
            myWebSocket.send(message);
          }
          else {
            console.log('Unable to send group_deleted message due to websocket is not opened'); 
          }
          
          try {
            clearLocalData();
            //-- Return to the landing page of messaging --//
            await prepareRollingKey(${_key_len}); 
            document.getElementById("frmLeap").submit();
          }
          catch(e) {
            alert(e.message);
          }
        }

        function clearLocalData() {
          var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
           
          if (is_iOS) {
            Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
            Cookies.remove("u_id");
            Cookies.remove("m_id");
            Cookies.remove("top_id");
          }
          else {
            deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
            deleteLocalStoredItem("u_id");                             
            deleteLocalStoredItem("m_id");                             
            deleteLocalStoredItem("top_id");                                   
          }      
        }    
      </script>   
      `;
    }
    else {
      html += `
      </script>
        $(document).ready(function() {
          switchPage();
        });

        function clearLocalData() {
          var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
           
          if (is_iOS) {
            Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
            Cookies.remove("u_id");
            Cookies.remove("m_id");
            Cookies.remove("top_id");
          }
          else {
            deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
            deleteLocalStoredItem("u_id");                             
            deleteLocalStoredItem("m_id");                             
            deleteLocalStoredItem("top_id");                                   
          }      
        }    
        
        async function switchPage() {
          try {
            clearLocalData();
            await prepareRollingKey(${_key_len});
            document.getElementById("frmLeap").submit();
          }
          catch(e) {
            alert(e.message);
          }  
        }
      </script>      
      `;
    }
    
    html += `
      <form id="frmLeap" name="frmLeap" action="/message" method="POST">
        <input type=hidden id="roll_rec" name="roll_rec" value="">
        <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
        <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
      </form>      
    `;
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.showAutoDeleteSetupForm = async function(msg_pool, group_id) {
  let conn, auto_delete, delete_after, checked, html;
  let group_settings = null;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    group_settings = await msglib.getGroupSettings(conn, group_id);
    auto_delete = parseInt(group_settings.msg_auto_delete, 10);  
    delete_after = parseInt(group_settings.delete_after_read, 10);
    checked = (auto_delete == 1)? 'checked' : '';
    
    html = _includeJsLib('Auto Delete Setup');
    
    html += `
    <script>
      var val_auto_delete = ${auto_delete};
      var val_delete_after = ${delete_after};
      
      $(document).on("pagecreate", function() {
        if (val_auto_delete == 1) {
          $("#input_grp").show();  
        }
        else {
          $("#input_grp").hide();
        }      
      });
      
      //*-- Define event handler of checkbox 'auto_delete' --*//
      $(function() {
        $("#auto_delete").on('change', function() {
          if (this.checked) {
            if ($("#delete_after").val() < 1 || \$("#delete_after").val() > 30) {
              $("#delete_after").val(1);
            }
          
            $("#input_grp").show();
          }
          else {
            $("#input_grp").hide();
          }
        })      
      });
      
      async function updateAutoDeleteSettings() {
        try {
          let is_checked = document.getElementById("auto_delete").checked;
          if (is_checked == false) {
            document.getElementById("auto_delete").value = 0;
            document.getElementById("delete_after").value = 0;
          }
          else {
            document.getElementById("auto_delete").value = 1;
            let da = parseInt(document.getElementById("delete_after").value, 10);
            if (isNaN(da) || (da < 1 || da > 30)) {
              document.getElementById("delete_after").value = 1;
            }
          }
          
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js          
          document.getElementById("frm_profile").submit();
        }
        catch(e) {
          alert(e.message);
        } 
      }    
      
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});                   // Defined on crypto-lib.js
        
          let is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);      
          //*-- Due to limitation on iOS, so I use cookies to store cross page data, instead to use localStorage. --*// 
          let f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");
          let top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
          
          document.getElementById("f_m_id").value = f_m_id;
          document.getElementById("top_id").value = top_id;
          document.getElementById("frm_profile").action = "/do_sms";
          document.getElementById("frm_profile").submit();
        }
        catch (e) {
          alert(e.message); 
        }
      }        
    </script>
    
    <form id="frm_profile" name="frm_profile" action="/confirm_auto_delete_setup" method="post">
    <input type="hidden" id="g_id" name="g_id" value="${group_id}">
    <input type=hidden id="f_m_id" name="f_m_id" value="">
    <input type=hidden id="top_id" name="top_id" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Auto Delete Setup</h1>
      </div>
  
      <div data-role="main" class="ui-content">
        <label for="auto_delete">Auto delete read message:</label>
        <input type="checkbox" data-role="flipswitch" id="auto_delete" name="auto_delete" value="${auto_delete}" ${checked}>
        <br>
        <div id="input_grp">
          <label for="delete_after" id="lbl_delete_after">Delete after read (minute):</label>
          <input type="range" id="delete_after" name="delete_after" value="${delete_after}" min="1" max="30">
        </div>
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="updateAutoDeleteSettings();">            
      </div>  
    </div>
    </form>
    `;     
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _printJoinUsJavascriptSection(conn) {
  var html, key_id, rsa_keys, public_pem, public_pem_b64, algorithm, algorithm_b64, public_sha256sum;
  
  try {
    // Step 1: Obtain an existing RSA public key or generate a new RSA key pair. //
    // Note: key_obj.public, key_obj.private and key_obj.algorithm are in base64 //
    //       string format. Moreover, key_obj.public and key_obj.private are pem //
    //       of public key and private key respectively.                         //		
    let key_obj = await _getRsaPublicKey(conn, 5);
				
    if (key_obj.id == null) {
      algorithm = {
        // Name of the algorithm
        name: 'RSA-OAEP',
        // Length of the RSA key (modulus), in bits
        modulusLength: 4096,
        // Public exponent: always use this static value (equivalent to 65537)
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
        hash: 'SHA-256'
      };
		  
      rsa_keys = await cipher.generateRsaKeyPair(algorithm, true);
		  
      // Note: The public key, private keys and algorithm object must be converted to base64 string before save to the database. //                                   // 
      let rsa_key_strs = {public: '', private: '', algorithm: ''};
      let pub_key_pem = await cipher.pemFromKey('public', rsa_keys.public);
      let pri_key_pem = await cipher.pemFromKey('private', rsa_keys.private);
      rsa_key_strs.public = cipher.convertObjectToBase64Str(pub_key_pem);
      rsa_key_strs.private = cipher.convertObjectToBase64Str(pri_key_pem);
      rsa_key_strs.algorithm = cipher.convertObjectToBase64Str(rsa_keys.algorithm);
		  
      key_id = await cipher.addNewRsaKeyPair(conn, rsa_key_strs);
      public_pem_b64 = rsa_key_strs.public;		  
      algorithm_b64 = rsa_key_strs.algorithm;
    }
    else {
      key_id = key_obj.id;
      public_pem_b64 = key_obj.public;       // In base64 format
      algorithm_b64 = key_obj.algorithm;     // In base64 format
		}
		
    // Step 2: Generate a base64 encoded SHA256SUM of the public key in base64 format. i.e. It is the signature of the //
    //         public key.                                                                                             //
    public_sha256sum = await cipher.digestData("SHA-256", public_pem_b64);
	  
    // Step 3: Generate another RSA key pair for the public key signature verification. Encrypt "public_sha256sum" by //
    //         the signed RSA private key (use for security verification later)                                       //
    let sign_algorithm = {
      name: 'RSA-PSS',
      saltLength: 32,
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    };
	  
    // Note: Since the private key of the signed key pair doesn't need to be converted into pem format, so that it can //
    //       be set as non extractable to maintain the highest security level.                                         //
    let sign_keypair = await cipher.generateSignKeyPair(sign_algorithm, false);
    let sign_key = sign_keypair.private;
    let verify_key = sign_keypair.public;
	  
    let pub_pem_signature = await cipher.createSignature(sign_algorithm, sign_key, cipher.base64StringToArrayBuffer(public_sha256sum));
    let pub_pem_signature_b64 = cipher.arrayBufferToBase64String(pub_pem_signature);
    let verify_key_pem = await cipher.pemFromKey('public', verify_key);
    let sign_algorithm_b64 = cipher.convertObjectToBase64Str(sign_algorithm);
		
    // Step 4: Convert the verification key pem strings into base64 format. Note: Key pem strings can't embed into 'html' directly or //
    //         they will cause syntax error on javascript due to the line-break characters.                                           //
    let verify_key_pem_b64 = cipher.convertObjectToBase64Str(verify_key_pem);

    // Step 5: Generate a Crystals Kyber key pair (it will be used to protect the RSA encrypted session key).  //
    let kyber_obj = await _getKyberKeyData(conn);
    let kyber_id = kyber_obj.key_id;
    let kyber_pkey_b64 = kyber_obj.pkey;  

    // Step 6: Create signature for the Crystals Kyber public key and sign it with the same RSA signing key pair. //
    //         Note: It will be used Crystals Dilithium later.                                                    //  
    let kyber_pkey_signature = await cipher.digestData("SHA-256", kyber_pkey_b64);
    let kyber_pem_signature = await cipher.createSignature(sign_algorithm, sign_key, cipher.base64StringToArrayBuffer(kyber_pkey_signature));
    let kyber_pem_signature_b64 = cipher.arrayBufferToBase64String(kyber_pem_signature);
		
    let kyber_module = cipher.getKyberClientModule();
    
    let js = `
    var key = "";                 // AES-256 key generated at client side
    var key_id = "${key_id}"; 
    var kyber_id = "${kyber_id}";
    var algorithm_b64 = "${algorithm_b64}";    // The algorithm used by the RSA key pair generation
    var algorithm;                             // The algorithm used by the RSA in required object format
    var public_pem_b64 = "${public_pem_b64}";
    var public_pem;
    var public_key;               // The RSA public key imported from public_pem (from public_pem_b64) 
    var pub_pem_signature_b64 = "${pub_pem_signature_b64}";			  
    var pub_pem_signature;        // The sha256sum signature (encrypted) of the public key pem (i.e. public_pem)
    var kyber_pkey_b64 = "${kyber_pkey_b64}";     // The Crystals Kyber public key
    var kyber_pem_signature_b64 = "${kyber_pem_signature_b64}";  // The signature of the Crystals Kyber public key (base64 format)
    var kyber_pem_signature;                                     // The signature of the Crystals Kyber public key (binary format)
    var cs_kyber_pkey_signature;                                 // Client side generated SHA256SUM of the received Crystals Kyber public key pem    
    var sign_algorithm_b64 = "${sign_algorithm_b64}";       // The algorithm used by the RSA public key signature verification 
    var sign_algorithm;
    var verify_key_pem_b64 = "${verify_key_pem_b64}";
    var verify_key_pem;
    var verify_key;               // The key used to verify the RSA public key signature
    var cs_public_sha256sum;      // Client side generated SHA256SUM of the received public key pem (i.e. public_pem)      
    var is_valid = false;         // true: public key is valid, false otherwise.
    var is_ck_valid = false;      // true: Crystals Kyber public key is valid, false otherwise.

    async function prepareAESkey() {
      try {
        key = generateTrueRandomStr('A', ${_key_len});      // Defined on crypto-lib.js
        
        algorithm = convertBase64StrToObject(algorithm_b64);
        public_pem = convertObjectToBase64Str(public_pem_b64);
        public_key = await importKeyFromPem('public', public_pem, algorithm, true, ['encrypt']);    // Defined on crypto-lib.js
                    
        sign_algorithm = convertBase64StrToObject(sign_algorithm_b64);
        verify_key_pem = convertObjectToBase64Str(verify_key_pem_b64);
        verify_key = await importKeyFromPem('public', verify_key_pem, sign_algorithm, true, ['verify']);    // Defined on crypto-lib.js
 
        // Verify RSA public key //       
        pub_pem_signature = base64StringToArrayBuffer(pub_pem_signature_b64);
        cs_public_sha256sum = await digestData('SHA-256', public_pem_b64);                      // In base64 format
        is_valid = await verifySignature(sign_algorithm, verify_key, pub_pem_signature, base64StringToArrayBuffer(cs_public_sha256sum));

        // Verify Crystals Kyber public key //
        kyber_pem_signature = base64StringToArrayBuffer(kyber_pem_signature_b64);
        cs_kyber_pkey_signature = await digestData('SHA-256', kyber_pkey_b64);
        is_ck_valid = await verifySignature(sign_algorithm, verify_key, kyber_pem_signature, base64StringToArrayBuffer(cs_kyber_pkey_signature));
        
        if (!is_valid) {
          throw new Error("Warning: The received RSA public key is invalid, request-to-join cannot proceed! You may be under Man-In-The-Middle attack!");
        }
        
        if (!is_ck_valid) {
          throw new Error("Warning: The received Crystals Kyber public key is invalid, request-to-join cannot proceed! You may be under Man-In-The-Middle attack!");
        }        
      }
      catch(e) {
        throw e;
      }
      
      return key;				
    }
  
    async function goRegister() {
      var this_name = allTrim(document.getElementById("name").value);
      var this_email = allTrim(document.getElementById("email").value);
      var this_refer = allTrim(document.getElementById("refer").value);
      var this_remark = document.getElementById("remark").value
      var aes_algorithm = "AES-GCM";          // algorithm used for AES-256 encryption 
      var enc_obj;

      try {
        if (this_name == "") {
          alert("Your name is compulsory.");
          document.getElementById("name").focus();
          return false;
        }
        
        if (this_email == "") {
          alert("Your email address is compulsory.");
          document.getElementById("email").focus();
          return false;
        }
        
        if (this_refer == "") {
          alert("Your referrer's email address is compulsory.");
          document.getElementById("refer").focus();
          return false;
        }

        key = await prepareAESkey();

        //-- Encrypt data before send to the back-end server --//
        $('#algorithm').val(aes_algorithm);
        
        enc_obj = await aesEncryptJSON(aes_algorithm, key, this_name);
        $('#iv_name').val(enc_obj.iv);
        $('#e_name').val(enc_obj.encrypted);
        enc_obj = await aesEncryptJSON(aes_algorithm, key, this_email);
        $('#iv_email').val(enc_obj.iv);
        $('#e_email').val(enc_obj.encrypted);
        enc_obj = await aesEncryptJSON(aes_algorithm, key, this_refer);
        $('#iv_refer').val(enc_obj.iv);
        $('#e_refer').val(enc_obj.encrypted);
        enc_obj = await aesEncryptJSON(aes_algorithm, key, this_remark);
        $('#iv_remark').val(enc_obj.iv);
        $('#e_remark').val(enc_obj.encrypted);
        $('#cs_public_sha256sum').val(cs_public_sha256sum);
        //-- Use the RSA public key to encrypt the AES key --//
        let enc_key = await rsaEncrypt(algorithm, public_key, key);                       // Defined on crypto-lib.js
        // Step 1: Convert encrypted key from ArrayBuffer to Uint8Array //
        let enc_key_u8a = new Uint8Array(enc_key);
        // Step 2: Stringify the Uint8Array to a JSON format string //
        let enc_key_json = JSON.stringify(enc_key_u8a);
        // Step 3: Use the secret key of the Kyber object to encrypt the RSA encrypted session key by AES-256 encryption. //
        //         i.e. Use AES-256 with Kyber secret key as encryption key to encrypt the RSA encrypted session key once //
        //         more.                                                                                                  //
        let secret = await generateSharedCipherKey(kyber_pkey_b64);
        let ct = secret.ct;
        let skey = base64Decode(secret.sk);
          
        enc_obj = await aesEncryptWithKeyJSON(aes_algorithm, skey, enc_key_json);
        let keycode_iv = enc_obj.iv;
        let keycode = enc_obj.encrypted;
        $('#key_id').val(key_id);          
        $('#key_iv').val(keycode_iv);
        $('#key').val(keycode);
        $('#kyber_id').val(kyber_id);          
        $('#kyber_ct').val(ct);
                
        //-- Remove content from the clear text data --//
        $('#name').val('');
        $('#email').val('');
        $('#refer').val('');
        $('#remark').val('');
        
        document.getElementById("oper_mode").value = "S";
        document.getElementById("frmRegister").action = "/request-to-join";
        document.getElementById("frmRegister").submit();
      }
      catch(e) {
        console.log(e);
        alert("Error: " + e + ". Request-to-join process is aborted.");
      }
    }`;

    js = await wev.minifyJS(js);
    		
    html = `
    <style>
      .a_message {
        width:98%;
        height:120px;
        max-height:200px;
      }
    </style>

    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
		<script src="/js/js.cookie.min.js"></script>
		<script src='/js/crypto-lib.js'></script>               
		<script src='/js/common_lib.js'></script>

    <!-- Async function generateSharedCipherKey is defined here //-->
    ${kyber_module} 
    
    <script>
      ${js}
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _printRequestToJoinForm(conn) {
  var red_dot, pda_bg_color, copy_right, html;
  
  try {
    red_dot = "<font color='red'>*</font>";
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    copy_right = await wev.getDecoySiteCopyRight(conn);
        
    html = `
    <body>
    <form id="frmRegister" name="frmRegister" action="" method="post" data-ajax="false">
    <input type=hidden id="algorithm" name="algorithm" value="">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="iv_name" name="iv_name" value="">
    <input type=hidden id="e_name" name="e_name" value="">
    <input type=hidden id="iv_email" name="iv_email" value="">
    <input type=hidden id="e_email" name="e_email" value="">
    <input type=hidden id="iv_refer" name="iv_refer" value="">
    <input type=hidden id="e_refer" name="e_refer" value="">
    <input type=hidden id="iv_remark" name="iv_remark" value="">
    <input type=hidden id="e_remark" name="e_remark" value="">
    <input type=hidden id="key_iv" name="key_iv" value="">
    <input type=hidden id="key" name="key" value="">
    <input type=hidden id='kyber_id' name='kyber_id' value="">
    <input type=hidden id="kyber_ct" name="kyber_ct" value="">
    <input type=hidden id="key_id" name="key_id" value="">
    <input type=hidden id="cs_public_sha256sum" name="cs_public_sha256sum", value="">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="/" data-icon="back" style="ui-btn-left" data-ajax="false">Back</a>
        <h1>Welcome to Join</h1>
      </div>
    
      <div data-role="main" style="ui-body-d ui-content">
        <label for="name"><b>Your Name ${red_dot}:</b></label>
        <input type=text id="name" name="name" value="" maxlength=125 required>
    
        <label for="email"><b>Your Email ${red_dot}:</b></label>  
        <input type=email id="email" name="email" value="" maxlength=125 required placeholder="Enter your email address">
  
        <label for="refer"><b>Referrer's Email ${red_dot}:</b></label>
        <input type=email id="refer" name="refer" value="" maxlength=125 required placeholder="Enter referrer's email address">
    
        <label for="remark"><b>Any Words to Your Referrer?</b></label>
        <textarea id="remark" name="remark" data-role="none" class="a_message"></textarea>
        <br>
        <br>
  
        <input type=button id="go_reg" name="go_reg" value="Register" onClick="goRegister();">  
        <br>  
        <b>Note:</b> Input item with ${red_dot} is compulsory.
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width="100%" cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr><td align=center><font size="2px">${copy_right}</font></td></tr>
        </tbody>
        </table>
      </div>     
    </div>
    </form> 
    </body>   
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.printRequestToJoinForm = async function(msg_pool, name, email, refer) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader('Join Us');
    html += await _printJoinUsJavascriptSection(conn);
    html += await _printRequestToJoinForm(conn, name, email, refer);
  }
  catch(e) {
    throw e;
  } 
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


exports.decryptRequestToJoinData = async function(algorithm, aes_key, data) {
	let name, email, refer, remark, result;
	
	try {
		name = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_name, data.e_name);
		email = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_email, data.e_email);
		refer = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_refer, data.e_refer);
		remark = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_remark, data.e_remark);
		
		result = {name: name, email: email, refer: refer, remark: remark};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _printRegisteredJavascriptSection() {
  var html = `
	<link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
	<link rel="shortcut icon" href="/favicon.ico">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/jquery.mobile-1.4.5.min.js"></script>    
  <script src="/js/common_lib.js"></script>  
  `;
  
  return html;
}


async function _printRequestedOkPage(conn, name) {
  var message, company_name, copy_right, pda_bg_color, html;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    copy_right = await wev.getDecoySiteCopyRight(conn);
    company_name = await wev.getDecoyCompanyName(conn);
    
    message = `Hi ${name}, <br><br>` +
              `Your application has been sent to approval, and you should get our reply within 3 days. However, ` + 
              `if you don't get the mail, please contact your referrer.<br><br>` +
              `P.R. Team <br>` +
              `${company_name}`;    
    
    html = `
    <form id="frmRegister" name="frmRegister" action="/" method="get">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <h1>Thanks You</h1>
      </div>
      
      <div data-role="main" style="ui-body-d ui-content">
        ${message}
        <br>
        <br>
        <input type=button id="return_home" name="return_home" value="Return" onClick="this.form.submit();">
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width="100%" cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr><td align=center><font size="2px">${copy_right}</font></td></tr>
        </tbody>
        </table>
      </div>         
    </div>
    </form>
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printRegistedOkPage = async function(msg_pool, name) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader('Welcome, ' + name);
    html += _printRegisteredJavascriptSection();
    html += await _printRequestedOkPage(conn, name);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getApplicantInfo(conn, apply_id) {
  var sql, param, data;
  var applicant = {apply_id: 0, token: '', name: '', email: ''};
  
  try {
    sql = `SELECT token, name, email ` +
          `  FROM applicant ` +
          `  WHERE apply_id = ? ` +
          `    AND status = 'A'`;
          
    param = [apply_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      applicant = {apply_id: apply_id, token: data[0].token, name: data[0].name, email: data[0].email};
    }
    else {
      throw new Error('Unable to retrieve the profile of the applicant!');
    }      
  }
  catch(e) {
    throw e; 
  }
  
  return applicant;
}


async function _userNameHasBeenUsed(conn, username) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` + 
          `  FROM user_list ` +
          `  WHERE user_name = ?`;
          
    param = [username];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (parseInt(data[0].cnt, 10) > 0)? true : false;      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _suggestUserName(conn, name, email) {
  var username, uname_bkup, stop_run, cnt;
  
  try {
    username = '';
    stop_run = false;
    cnt = 0;

    //-- Try to use email first --//
    var parts = email.split('@');
    if (parts.length >= 1) {
      username = parts[0].toLowerCase();
    } 
    
    //-- If 'username' is blank, then try to use the name. --//
    if (username == '') {
      username = name.replace(/ /g, '').toLowerCase();
    } 
    
    uname_bkup = username;
    
    while (!stop_run) {      
      if (username == '') {
        username = cipher.generateTrueRandomStr('A', 6);
      }
      else {
        username = uname_bkup + cipher.generateTrueRandomStr('N', 2);
      }
      
      if (await _userNameHasBeenUsed(conn, username)) {
        cnt++;
        
        if (cnt >= 3) {
          //-- The last resort --//
          username = cipher.generateTrueRandomStr('A', 8);
          stop_run = true;
        }         
      }
      else {
        stop_run = true;
      }       
    }
  }
  catch(e) {
    //-- No need to throw error even something is wrong --//
    _consoleLog(e.message);
  }
  
  return username;  
}


async function _printAddUserAccountJavascriptSection(conn) {
  let html, key_id, rsa_keys, public_pem, public_pem_b64, algorithm, algorithm_b64, public_sha256sum;
  
  try {
    // Step 1: Obtain an existing RSA public key or generate a new RSA key pair. //
    // Note: key_obj.public, key_obj.private and key_obj.algorithm are in base64 //
    //       string format. Moreover, key_obj.public and key_obj.private are pem //
    //       of public key and private key respectively.                         //		
    let key_obj = await _getRsaPublicKey(conn, 5);
				
    if (key_obj.id == null) {
      algorithm = {
        // Name of the algorithm
        name: 'RSA-OAEP',
        // Length of the RSA key (modulus), in bits
        modulusLength: 4096,
        // Public exponent: always use this static value (equivalent to 65537)
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
        hash: 'SHA-256'
      };
		  
      rsa_keys = await cipher.generateRsaKeyPair(algorithm, true);
		  
      // Note: The public key, private keys and algorithm object must be converted to base64 string before save to the database. //                                   // 
      let rsa_key_strs = {public: '', private: '', algorithm: ''};
      let pub_key_pem = await cipher.pemFromKey('public', rsa_keys.public);
      let pri_key_pem = await cipher.pemFromKey('private', rsa_keys.private);
      rsa_key_strs.public = cipher.convertObjectToBase64Str(pub_key_pem);
      rsa_key_strs.private = cipher.convertObjectToBase64Str(pri_key_pem);
      rsa_key_strs.algorithm = cipher.convertObjectToBase64Str(rsa_keys.algorithm);
		  
      key_id = await cipher.addNewRsaKeyPair(conn, rsa_key_strs);
      public_pem_b64 = rsa_key_strs.public;		  
      algorithm_b64 = rsa_key_strs.algorithm;
    }
    else {
      key_id = key_obj.id;
      public_pem_b64 = key_obj.public;       // In base64 format
      algorithm_b64 = key_obj.algorithm;     // In base64 format
		}
		
    // Step 2: Generate a base64 encoded SHA256SUM of the public key in base64 format. i.e. It is the signature of the //
    //         public key.                                                                                             //
    public_sha256sum = await cipher.digestData("SHA-256", public_pem_b64);
	  
    // Step 3: Generate another RSA key pair for the public key signature verification. Encrypt "public_sha256sum" by //
    //         the signed RSA private key (use for security verification later)                                       //
    let sign_algorithm = {
      name: 'RSA-PSS',
      saltLength: 32,
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    };
	  
    // Note: Since the private key of the signed key pair doesn't need to be converted into pem format, so that it can //
    //       be set as non extractable to maintain the highest security level.                                         //
    let sign_keypair = await cipher.generateSignKeyPair(sign_algorithm, false);
    let sign_key = sign_keypair.private;
    let verify_key = sign_keypair.public;
	  
    let pub_pem_signature = await cipher.createSignature(sign_algorithm, sign_key, cipher.base64StringToArrayBuffer(public_sha256sum));
    let pub_pem_signature_b64 = cipher.arrayBufferToBase64String(pub_pem_signature);
    let verify_key_pem = await cipher.pemFromKey('public', verify_key);
    let sign_algorithm_b64 = cipher.convertObjectToBase64Str(sign_algorithm);
		
    // Step 4: Convert the verification key pem strings into base64 format. Note: Key pem strings can't embed into 'html' directly or //
    //         they will cause syntax error on javascript due to the line-break characters.                                           //
    let verify_key_pem_b64 = cipher.convertObjectToBase64Str(verify_key_pem);

    // Step 5: Generate a Crystals Kyber key pair (it will be used to protect the RSA encrypted session key).  //
    let kyber_obj = await _getKyberKeyData(conn);
    let kyber_id = kyber_obj.key_id;
    let kyber_pkey_b64 = kyber_obj.pkey;  
    
    let kyber_module = cipher.getKyberClientModule();
    
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>    
    <script src="/js/common_lib.js"></script>
    <script src='/js/crypto-lib.js'></script>
    
    <!-- Async function generateSharedCipherKey is defined here //-->
    ${kyber_module}
    
    <script type="text/javascript">
      var key = "";                 // AES-256 key generated at client side
      var kyber_id = "${kyber_id}"; 
			var key_id = "${key_id}";     // ID of the given RSA public key   
		  var algorithm_b64 = "${algorithm_b64}";    // The algorithm used by the RSA key pair generation
		  var algorithm;
		  var public_pem_b64 = "${public_pem_b64}";
		  var public_pem;
			var public_key;               // The RSA public key imported from public_pem (from public_pem_b64) 
			var pub_pem_signature_b64 = "${pub_pem_signature_b64}";			  
		  var pub_pem_signature;        // The sha256sum signature (encrypted) of the public key pem (i.e. public_pem)
		  var sign_algorithm_b64 = "${sign_algorithm_b64}";       // The algorithm used by the RSA public key signature verification 
		  var sign_algorithm;
		  var verify_key_pem_b64 = "${verify_key_pem_b64}";
		  var verify_key_pem;
		  var verify_key;               // The key used to verify the RSA public key signature
		  var cs_public_sha256sum;      // Client side generated SHA256SUM of the received public key pem (i.e. public_pem)                       
		  var is_valid = false;         // true: public key is valid, false otherwise.
      
      async function prepareAESkey() {
        try {
          key = generateTrueRandomStr('A', ${_key_len});      // Defined on crypto-lib.js
				  
          algorithm = convertBase64StrToObject(algorithm_b64);
          public_pem = convertObjectToBase64Str(public_pem_b64);
          public_key = await importKeyFromPem('public', public_pem, algorithm, true, ['encrypt']);    // Defined on crypto-lib.js
				  					  
          sign_algorithm = convertBase64StrToObject(sign_algorithm_b64);
          verify_key_pem = convertObjectToBase64Str(verify_key_pem_b64);
          verify_key = await importKeyFromPem('public', verify_key_pem, sign_algorithm, true, ['verify']);    // Defined on crypto-lib.js
				  
          pub_pem_signature = base64StringToArrayBuffer(pub_pem_signature_b64);
          cs_public_sha256sum = await digestData('SHA-256', public_pem_b64);                      // In base64 format
          is_valid = await verifySignature(sign_algorithm, verify_key, pub_pem_signature, base64StringToArrayBuffer(cs_public_sha256sum));
				  
          if (!is_valid) {
            throw new Error("Warning: The received public key is invalid, request-to-join cannot proceed! You may be under Man-In-The-Middle attack!");
          }
        }
        catch(e) {
          throw e;
        }
			  
        return key;				
      }
                
      async function goCreateUserAccount() {
        if (await dataSetValid()) {
          document.getElementById("save").disabled = true;
          document.getElementById("frmAddUser").action = "/create_user_acct";
          document.getElementById("frmAddUser").submit();
        }
      }
      
      async function dataSetValid() {
        var aes_algorithm = "AES-GCM";
        var user = allTrim(document.getElementById("user").value);
        var alias = allTrim(document.getElementById("alias").value);
        var happy_pw1 = document.getElementById("happy_passwd1").value;
        var happy_pw2 = document.getElementById("happy_passwd2").value;
        var unhappy_pw1 = document.getElementById("unhappy_passwd1").value;
        var unhappy_pw2 = document.getElementById("unhappy_passwd2").value;
        var email = document.getElementById("email").value;
        var name = document.getElementById("name").value;
        var enc_obj;
        
        try {        
	        if (user == "") {
	          alert("User name is compulsory");
	          document.getElementById("user").focus();
	          return false;
	        }
	        
	        if (alias == "") {
	          alert("Alias is compulsory");
	          document.getElementById("alias").focus();
	          return false;        
	        }
	        
	        if (happy_pw1.length < 8) {
	          alert("Happy password must contain 8 characters or more");
	          document.getElementById("happy_passwd1").focus();
	          return false;
	        }
	        else {
	          if (happy_pw1 != happy_pw2) {
	            alert("Happy password is not match");
	            document.getElementById("happy_passwd2").focus();
	            return false;
	          }
	        }
	        
	        if (unhappy_pw1.length < 8) {
	          alert("Unhappy password must contain 8 characters or more");
	          document.getElementById("unhappy_passwd1").focus();
	          return false;
	        }
	        else {
	          if (unhappy_pw1 != unhappy_pw2) {
	            alert("Unhappy password is not match");
	            document.getElementById("unhappy_passwd2").focus();
	            return false;
	          }
	        }
	        
	        if (happy_pw1 == unhappy_pw1) {
	          alert("Happy password must be different from unhappy password");
	          document.getElementById("happy_passwd1").focus();
	          return false;        
	        }
        
	        //-- If everything is OK, encrypt the data and delete data in clear text format. --//                
          key = await prepareAESkey();        
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, user);                      // Defined on crypto-lib.js
          document.getElementById("iv_user").value = enc_obj.iv;
          document.getElementById("e_user").value = enc_obj.encrypted;
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, alias);
          document.getElementById("iv_alias").value = enc_obj.iv;
          document.getElementById("e_alias").value = enc_obj.encrypted;
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, happy_pw1);
          document.getElementById("iv_happy_passwd").value = enc_obj.iv;
          document.getElementById("e_happy_passwd").value = enc_obj.encrypted;
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, unhappy_pw1);
          document.getElementById("iv_unhappy_passwd").value = enc_obj.iv;
          document.getElementById("e_unhappy_passwd").value = enc_obj.encrypted;
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, email);
          document.getElementById("iv_email").value = enc_obj.iv;
          document.getElementById("e_email").value = enc_obj.encrypted;
          
          enc_obj = await aesEncryptJSON(aes_algorithm, key, name);
          document.getElementById("iv_name").value = enc_obj.iv;
          document.getElementById("e_name").value = enc_obj.encrypted;
          	        
	        $('#algorithm').val(aes_algorithm);
	        $('#key_id').val(key_id);
	        $('#cs_public_sha256sum').val(cs_public_sha256sum);
	        
	        //-- Use the RSA public key to encrypt the AES key --//
					let enc_key = await rsaEncrypt(algorithm, public_key, key);                       // Defined on crypto-lib.js
					// Step 1: Convert encrypted key from ArrayBuffer to Uint8Array //
					let enc_key_u8a = new Uint8Array(enc_key);
					// Step 2: Stringify the Uint8Array to a JSON format string //
					let enc_key_json = JSON.stringify(enc_key_u8a);	        
          // Step 3: Use the secret key of the Kyber object to encrypt the RSA encrypted session key by AES-256 encryption. //
          //         i.e. Use AES-256 with Kyber secret key as encryption key to encrypt the RSA encrypted session key once //
          //         more.                                                                                                  //
          let secret = await generateSharedCipherKey("${kyber_pkey_b64}");
          let ct = secret.ct;
          let skey = base64Decode(secret.sk);
            
          enc_obj = await aesEncryptWithKeyJSON(aes_algorithm, skey, enc_key_json);
          let keycode_iv = enc_obj.iv;
          let keycode = enc_obj.encrypted;          

          $('#key_iv').val(keycode_iv);
	        $('#key').val(keycode);
          $('#kyber_id').val(kyber_id);
          $('#kyber_ct').val(ct);
	                
	        $('#user').val('');
	        $('#alias').val('');
	        $('#happy_passwd1').val('');
	        $('#happy_passwd2').val('');
	        $('#unhappy_passwd1').val('');
	        $('#unhappy_passwd2').val('');
	        $('#email').val('');
	        $('#name').val('');
	        
	        return true;
			  }
			  catch(e) {
			    console.log(e); 
			    alert("Error is found, process is abort. Error: " + e);
			    return false;
			  }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html; 
}


async function _printAddUserAccountForm(conn, username, apply_id, applicant) {
  var html, red_dot, message, spaces, copy_right, pda_bg_color;
  
  try {
    red_dot = "<font color='red'>*</font>";
    message = `<font color='darkblue'>Hi ${applicant.name}, you need to input further data to complete your registration.</font><br><br>`;
    spaces = '&nbsp;'.repeat(2); 
    copy_right = await wev.getDecoySiteCopyRight(conn);      
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frmAddUser" name="frmAddUser" action="" method="post" data-ajax="false">
    <input type=hidden id="apply_id" name="apply_id" value="${apply_id}">
    <input type=hidden id="token" name="token" value="${applicant.token}">
    <input type=hidden id="algorithm" name="algorithm" value="">
    <input type=hidden id="iv_user" name="iv_user" value="">
    <input type=hidden id="e_user" name="e_user" value="">
    <input type=hidden id="iv_alias" name="iv_alias" value="">
    <input type=hidden id="e_alias" name="e_alias" value="">
    <input type=hidden id="iv_happy_passwd" name="iv_happy_passwd" value="">
    <input type=hidden id="e_happy_passwd" name="e_happy_passwd" value="">
    <input type=hidden id="iv_unhappy_passwd" name="iv_unhappy_passwd" value="">
    <input type=hidden id="e_unhappy_passwd" name="e_unhappy_passwd" value="">
    <input type=hidden id="iv_email" name="iv_email" value="">
    <input type=hidden id="e_email" name="e_email" value="">
    <input type=hidden id="iv_name" name="iv_name" value="">
    <input type=hidden id="e_name" name="e_name" value="">        
    <input type=hidden id="email" name="email" value="${applicant.email}">
    <input type=hidden id="name" name="name" value="${applicant.name}">    
    <input type=hidden id="key_iv" name="key_iv" value="">
    <input type=hidden id="key" name="key" value="">
    <input type=hidden id="key_id" name="key_id" value="">
    <input type=hidden id="kyber_id" name="kyber_id" value="">
    <input type=hidden id="kyber_ct" name="kyber_ct" value="">
    <input type=hidden id="cs_public_sha256sum" name="cs_public_sha256sum", value="">
        
    <div data-role="page" style="background-color:${pda_bg_color}"> 
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <h1>Create Account</h1>
      </div>
    
      <div data-role="content" style="ui-content">
        ${message}
        
        <label for="user"><b>Username ${red_dot}</b></label>
        <input type=text id="user" name="user" value="${username}">
  
        <label for="alias"><b>Alias ${red_dot}</b></label>
        <input type=text id="alias" name="alias">
    
        <label for="happy_passwd1"><b>Happy Password ${red_dot} (2)</b></label>
        <input type=password id="happy_passwd1" name="happy_passwd1">
        (8 chars. or more)
  
        <label for="happy_passwd2"><b>Retype Happy Password ${red_dot}</b></label>
        <input type=password id="happy_passwd2" name="happy_passwd2">
  
        <label for="unhappy_passwd1"><b>Unhappy Password ${red_dot} (3)</b></label>
        <input type=password id="unhappy_passwd1" name="unhappy_passwd1">
        (8 chars. or more)
    
        <label for="unhappy_passwd2"><b>Retype Unhappy Password ${red_dot}</b></label>
        <input type=password id="unhappy_passwd2" name="unhappy_passwd2">
        <br>
        <input type=button id="save" name="save" value="Create Account" onClick="goCreateUserAccount();">  
        <br>
        
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td colspan=2><b>Remarks:</b></td> 
          </tr>
        
          <tr>
            <td valign=top>1.${spaces}</td>
            <td valign=top>Input items with ${red_dot} are compulsory that they must be filled</td>
          </tr>
        
          <tr>
            <td valign=top>2.${spaces}</td>
            <td valign=top>Happy password means the <font color='darkblue'>normal</font> password you use to login to the system</td>
          </tr>
  
          <tr>
            <td valign=top>3.${spaces}</td>
            <td valign=top>Please <font color='red'>ask</font> your referrer the purpose of the unhappy password and it's usage.</td>
          </tr>
        </tbody>
        </table>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width="100%" cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr><td align=center><font size="2px">${copy_right}</font></td></tr>
        </tbody>
        </table>
      </div>     
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.showUserCreationForm = async function(msg_pool, token, apply_id) {
  var conn, applicant, username, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    applicant = await _getApplicantInfo(conn, apply_id);    
    username = await _suggestUserName(conn, applicant.name, applicant.email);
    
    html = wev.printHeader('Create Account');
    html += await _printAddUserAccountJavascriptSection(conn);
    html += await _printAddUserAccountForm(conn, username, apply_id, applicant);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.decryptUserAccountDataSet = async function(algorithm, aes_key, data) {
	let user, alias, happy_passwd, unhappy_passwd, email, name, result;
	
	try {
		user = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_user, data.e_user);
		alias = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_alias, data.e_alias);
		happy_passwd = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_happy_passwd, data.e_happy_passwd);
		unhappy_passwd = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_unhappy_passwd, data.e_unhappy_passwd);
		email = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_email, data.e_email);
		name = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_name, data.e_name);
		
		result = {user: user, alias: alias, happy_passwd: happy_passwd, unhappy_passwd: unhappy_passwd, email: email, name: name};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _promoteUserJavascriptSection(op) {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>    
    <script src="/js/crypto-lib.js"></script>
  
    <script>
      async function goStep(to_step, cnt) {
        to_step = parseInt(to_step, 10);
        
        try {
          if (to_step == 0) {
            await prepareRollingKey(${_key_len});
            document.getElementById("op0").value = ${op};
            document.getElementById("frm_promote").action = "/promote_user";          
            document.getElementById("frm_promote").submit();          
          }
          else if (to_step == 1) {
            await prepareRollingKey(${_key_len});
            document.getElementById("frm_promote").action = "/promote_select_user";          
            document.getElementById("frm_promote").submit();
          }
          else if (to_step == 2) {
            if (dataSetValid(cnt)) {
              await prepareRollingKey(${_key_len});
              document.getElementById("frm_promote").action = "/promote_confirm_user";
              document.getElementById("frm_promote").submit();          
            }
          }    
        }
        catch(e) {
          alert(e.message);
        }          
      }

      function dataSetValid(cnt) {
        var this_op = parseInt(document.getElementById("op").value, 10);
        if (this_op != 1 && this_op != 2) {
          alert("Something is wrong, please start over again.");
          return false;
        }
  
        var select_cnt = 0;
        for (ix = 1; ix <= cnt; ix++) {
          if (document.getElementById("pm_user_id_" + ix).checked) {
            select_cnt++;
          }
        }
        
        if (select_cnt == 0) {
          alert("You must select at least one user to proceed");
          return false;
        }
        
        return true;
      }
      
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_promote").action = "/message";
          document.getElementById("frm_promote").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printPromoteSelectOperationForm(op) {
  var html, tu_check, sa_check;

  try {  
    if (op == 1) {
      tu_check = "checked";
      sa_check = "";
    }
    else {
      tu_check = "";
      sa_check = "checked";      
    }
    
    html = `
    <form id="frm_promote" name="frm_promote" action="" method="post">  
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    <input type=hidden id="op0" name="op0" value="">
          
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Promote User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <input type="radio" id="op1" name="op" value="1" ${tu_check}><label for="op1">To Trusted User</label>
        <input type="radio" id="op2" name="op" value="2" ${sa_check}><label for="op2">To System Administrator</label>
        <br>
        <input type="button" id="next" name="next" value="Next" onClick="goStep(1, 0);">
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e; 
  }
  
  return html;
}


exports.printPromoteSelectOperationForm = async function(op) {
  var html;
  
  try {    
    html = wev.printHeader("Promote User");
    html += _promoteUserJavascriptSection(op);
    html += _printPromoteSelectOperationForm(op);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _getAvailableUsersToPromote(conn, op) {
  var sql, data, filter;
  var result = [];
  
  try {
    filter = (op == 1)? "0" : "0, 1";
    
    sql = `SELECT user_id, user_name, user_alias, user_role ` +
          `  FROM user_list ` +
          `  WHERE status = 'A' ` +
          `    AND user_role IN (${filter}) ` +
          `  ORDER BY user_alias, user_name`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push({user_id: data[i].user_id, username: data[i].user_name, alias: data[i].user_alias, role: data[i].user_role});
    }    
  }
  catch(e) {
    throw e;    
  }
  
  return result;  
}


async function _printPromoteSelectUserForm(conn, op) {
  var html, cnt;
  var users = [];
  
  try {
    users = await _getAvailableUsersToPromote(conn, op);
    
    html = `
    <form id="frm_promote" name="frm_promote" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    <input type=hidden id="op0" name="op0" value="">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Promote User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <b>Select user(s) to promote:</b>
        <br>
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td><td align=center><b>Current Role</b></td></tr>
        </thead>
        <tbody>        
    `;
    
    cnt = 0;    
    for (var i = 0; i < users.length; i++) {
      var this_user_id = users[i].user_id;
      var this_username = wev.allTrim(users[i].username);
      var this_alias = wev.allTrim(users[i].alias);
      var this_user = (this_alias != '')? this_alias : this_username;
      var this_role = (users[i].role == 0)? 'Common User' : ((users[i].role == 1)? 'Trusted User' : 'System Admin');
      
      cnt++;
      html += `
      <tr style="background-color:lightyellow">
        <td>
          <input type="checkbox" id="pm_user_id_${cnt}" name="pm_user_id_${cnt}" value="${this_user_id}">
          <label for="pm_user_id_${cnt}">${this_user}</label>
        </td>
        
        <td align=center>${this_role}</td>
      </tr>      
      `;      
    }
    
    if (users.length > 0) {
      html += `
      </tbody>
      </table>
      <br>
      <table width=100% cellpadding=1 cellspacing=1>
      <thead>
        <tr><td colspan=2></td></tr>
      </thead>
      
      <tbody>
      <tr>  
        <td width=50% align=center><input type="button" id="back" name="back" value="Back" onClick="goStep(0, 0);"></td>
        <td width=50% align=center><input type="button" id="next" name="next" value="Save" onClick="goStep(2, ${cnt});"></td>
      </tr>
      </tbody>
      </table>            
      `;  
    }
    else {
      var post = (op == 1)? 'trusted user' : 'system administrator';
      
      html += `
        <tr style="background-color:lightyellow"><td colspan=2>No user is available to promote to ${post}</td></tr>
      </tbody>
      </table>      
      `;
    }
    
    html += `
      </div>
    </div>
    </form>      
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.printPromoteSelectUserForm = async function(msg_pool, op) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader("Promote User");
    html += _promoteUserJavascriptSection(op);
    html += await _printPromoteSelectUserForm(conn, op);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


function _demoteUserJavascriptSection(op) {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>   
    <script src="/js/crypto-lib.js"></script> 
  
    <script>
      async function goStep(to_step, cnt) {
        to_step = parseInt(to_step, 10);
        
        try {
          if (to_step == 0) {
            await prepareRollingKey(${_key_len});
            document.getElementById("op0").value = ${op};
            document.getElementById("frm_demote").action = "/demote_user";          
            document.getElementById("frm_demote").submit();
            
          }
          else if (to_step == 1) {
            await prepareRollingKey(${_key_len});
            document.getElementById("frm_demote").action = "/demote_select_user";          
            document.getElementById("frm_demote").submit();
          }
          else if (to_step == 2) {
            if (dataSetValid(cnt)) {
              await prepareRollingKey(${_key_len});
              document.getElementById("frm_demote").action = "/demote_confirm_user";
              document.getElementById("frm_demote").submit();          
            }
          }    
        }
        catch(e) {
          alert(e.message);
        }                  
      }
      
      function dataSetValid(cnt) {
        var this_op = parseInt(document.getElementById("op").value, 10);
        if (this_op != 1 && this_op != 2) {
          alert("Something is wrong, please start over again.");
          return false;
        }
  
        var select_cnt = 0;
        for (ix = 1; ix <= cnt; ix++) {
          if (document.getElementById("dm_user_id_" + ix).checked) {
            select_cnt++;
          }
        }
        
        if (select_cnt == 0) {
          alert("You must select at least one user to proceed");
          return false;
        }
        
        return true;
      }
      
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_demote").action = "/message";
          document.getElementById("frm_demote").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printDemoteSelectOperationForm(op) {
  var html, cu_check, tu_check;
  
  try {
    if (op == 1) {
      cu_check = "checked";
      tu_check = "";
    }
    else {
      cu_check = "";
      tu_check = "checked";    
    }
    
    html = `
    <form id="frm_demote" name="frm_demote" action="" method="post">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    <input type=hidden id="op0" name="op0" value="">    
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Demote User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <input type="radio" id="op1" name="op" value="1" ${cu_check}><label for="op1">To Common User</label>
        <input type="radio" id="op2" name="op" value="2" ${tu_check}><label for="op2">To Trusted User</label>
        <br>
        <input type="button" id="next" name="next" value="Next" onClick="goStep(1, 0);">
      </div>
    </div>
    </form>  
    `;
  }
  catch(e) {
    throw e;
  }

  return html;  
}


exports.printDemoteSelectOperationForm = async function(op) {
  var html;
  
  try {    
    html = wev.printHeader("Demote User");
    html += _demoteUserJavascriptSection(op);
    html += _printDemoteSelectOperationForm(op);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _getAvailableUsersToDemote(conn, op, user_id) {
  var sql, param, data, filter;
  var result = [];
  
  try {
    filter = (op == 1)? "1, 2" : "2";
    
    sql = `SELECT user_id, user_name, user_alias, user_role ` +
          `  FROM user_list ` +
          `  WHERE status = 'A' ` +
          `    AND user_role IN (${filter}) ` +
          `    AND user_id <> ? ` +
          `  ORDER BY user_alias, user_name`;
    
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      result.push({user_id: data[i].user_id, username: data[i].user_name, alias: data[i].user_alias, role: data[i].user_role});
    }    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _printDemoteSelectUserForm(conn, op, user_id) {
  var html, cnt;
  var users = [];

  try {
    users = await _getAvailableUsersToDemote(conn, op, user_id);
    
    html = `
    <form id="frm_demote" name="frm_demote" action="" method="post">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    <input type=hidden id="op0" name="op0" value="">
    <input type=hidden id="op" name="op" value="${op}">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Demote User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <b>Select user(s) to demote:</b>
        <br>
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td><td align=center><b>Current Role</b></td></tr>
        </thead>
        <tbody>            
    `;

    cnt = 0;
    for (var i = 0; i < users.length; i++) {
      var this_user_id = users[i].user_id;
      var this_username = wev.allTrim(users[i].username);
      var this_alias = wev.allTrim(users[i].alias);
      var this_user = (this_alias != '')? this_alias : this_username;
      var this_role = (users[i].role == 0)? 'Common User' : ((users[i].role == 1)? 'Trusted User' : 'System Admin');
      
      cnt++;
      html += `
      <tr style="background-color:lightyellow">
        <td>
          <input type="checkbox" id="dm_user_id_${cnt}" name="dm_user_id_${cnt}" value="${this_user_id}">
          <label for="dm_user_id_${cnt}">${this_user}</label>
        </td>
      
        <td align=center>${this_role}</td>
      </tr>
      `;            
    }
    
    if (users.length > 0) {
      html += `
      </tbody>
      </table>
      <br>
      <table width=100% cellpadding=1 cellspacing=1>
      <thead>
        <tr><td colspan=2></td></tr>
      </thead>
      
      <tbody>
      <tr>  
        <td width=50% align=center><input type="button" id="back" name="back" value="Back" onClick="goStep(0, 0);"></td>
        <td width=50% align=center><input type="button" id="next" name="next" value="Save" onClick="goStep(2, ${cnt});"></td>
      </tr>
      </tbody>
      </table>      
      `;
    }
    else {
      var post = (op == 1)? 'common user' : 'trusted user'; 

      html += `
        <tr style="background-color:lightyellow"><td colspan=2>No user is available to demote to ${post}</td></tr>
      </tbody>
      </table>      
      `;
    }
    
    html += `
      </div>
    </div>
    </form>      
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printDemoteSelectUserForm = async function(msg_pool, op, user_id) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader("Demote User");
    html += _demoteUserJavascriptSection(op);
    html += await _printDemoteSelectUserForm(conn, op, user_id);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


function _lockUserJavascriptSection(op) {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>   
    <script src="/js/crypto-lib.js"></script> 
  
    <script>
      async function goStep(to_step, cnt) {
        try {
          var to_step = parseInt(to_step, 10);
          
          if (to_step == 0 || to_step == 1 || to_step == 2) {
            await prepareRollingKey(${_key_len});
          }
          
          if (to_step == 0) {
            document.getElementById("op0").value = ${op};
            document.getElementById("frm_lock").action = "/lock_user";          
            document.getElementById("frm_lock").submit();
          }
          else if (to_step == 1) {
            document.getElementById("frm_lock").action = "/lock_select_user";          
            document.getElementById("frm_lock").submit();
          }
          else if (to_step == 2) {
            if (dataSetValid(cnt)) {
              document.getElementById("frm_lock").action = "/lock_confirm_user";
              document.getElementById("frm_lock").submit();          
            }
          }    
        }
        catch(e) {
          alert(e.message);
        }                  
      }
          
      function dataSetValid(cnt) {
        var this_op = parseInt(document.getElementById("op").value, 10);
        if (this_op != 1 && this_op != 2) {
          alert("Something is wrong, please start over again.");
          return false;
        }
  
        var select_cnt = 0;
        for (ix = 1; ix <= cnt; ix++) {
          if (document.getElementById("op_user_id_" + ix).checked) {
            select_cnt++;
          }
        }
        
        if (select_cnt == 0) {
          alert("You must select at least one user to proceed");
          return false;
        }
        
        return true;
      }
      
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_lock").action = "/message";
          document.getElementById("frm_lock").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printLockUnlockOptionForm(op) {
  var html, lock_check, unlock_check;
  
  try {
    if (op == 1) {
      lock_check = "checked"; 
      unlock_check = "";
    }
    else {
      lock_check = ""; 
      unlock_check = "checked";      
    }
    
    html = `
    <form id="frm_lock" name="frm_lock" action="" method="post">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    <input type=hidden id="op0" name="op0" value="${op}">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Lock/Unlock User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <input type="radio" id="op1" name="op" value="1" ${lock_check}><label for="op1">Lock User</label>
        <input type="radio" id="op2" name="op" value="2" ${unlock_check}><label for="op2">Unlock User</label>
        <br>
        <input type="button" id="next" name="next" value="Next" onClick="goStep(1, 0);">
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printLockUnlockOptionForm = async function(op) {
  var html;
  
  try {
    html = wev.printHeader("Lock/Unlock User");
    html += _lockUserJavascriptSection(op);
    html += _printLockUnlockOptionForm(op);     
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _getAvailableUsersToLockUnlock(conn, op, user_id) {
  var sql, param, data, status;
  var users = [];
  
  try {
    status = (op == 1)? "A" : "D";
    
    sql = `SELECT user_id, user_name, user_alias, status ` +
          `  FROM user_list ` +
          `  WHERE status = ? ` + 
          `    AND user_id <> ? ` +
          `  ORDER BY user_alias, user_name`;
    
    //-- Note: 'user_id' is your user id. i.e. You should not lock yourself. --//
    param = [status, user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      users.push({user_id: data[i].user_id, 'username': data[i].user_name, 'alias': data[i].user_alias, 'status': data[i].status});
    }
  }
  catch(e) {
    throw e;
  }
  
  return users;
}


async function _printLockUnlockSelectUserForm(conn, op, user_id) {
  var html, cnt, prompt;
  var users = [];
  
  try {
    users = await _getAvailableUsersToLockUnlock(conn, op, user_id);
    prompt = (op == 1)? "Select user(s) to lock:" : "Select user(s) to unlock:";
    
    html = `
    <form id="frm_lock" name="frm_lock" action="" method="post">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">    
    <input type=hidden id="op0" name="op0" value="${op}">
    <input type=hidden id="op" name="op" value="${op}">
    
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>		
        <h1>Lock/Unlock User</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <b>${prompt}</b>
        <br>
        <table width=100% cellpadding=1 cellspacing=1>
        <thead>
          <tr style="background-color:lightblue"><td align=center><b>Username / Alias</b></td><td align=center><b>Current Status</b></td></tr>
        </thead>
        <tbody>            
    `;
    
    cnt = 0;
    for (var i = 0; i < users.length; i++) {
      var this_user_id = users[i].user_id;
      var this_username = wev.allTrim(users[i].username);
      var this_alias = wev.allTrim(users[i].alias);
      var this_user = (this_alias != '')? this_alias : this_username;
      var this_status = (users[i].status == 'A')? "Active" : "Locked";

      cnt++;
      html += `
      <tr style="background-color:lightyellow">
        <td>
          <input type="checkbox" id="op_user_id_${cnt}" name="op_user_id_${cnt}" value="${this_user_id}">
          <label for="op_user_id_${cnt}">${this_user}</label>
        </td>
        
        <td align=center>${this_status}</td>
      </tr>      
      `;      
    }
    
    if (users.length > 0) {
      html += `
      </tbody>
      </table>
      <br>
      <table width=100% cellpadding=1 cellspacing=1>
      <thead>
        <tr><td colspan=2></td></tr>
      </thead>
      
      <tbody>
      <tr>  
        <td width=50% align=center><input type="button" id="back" name="back" value="Back" onClick="goStep(0, 0);"></td>
        <td width=50% align=center><input type="button" id="next" name="next" value="Save" onClick="goStep(2, ${cnt});"></td>
      </tr>
      </tbody>
      </table>      
      `;
    }
    else {
      var action = (op == 1)? 'be locked' : 'be unlocked'; 
      
      html += `
        <tr style="background-color:lightyellow"><td colspan=2>No user is available to ${action}</td></tr>
      </tbody>
      </table>      
      `;
    }
      
    html += `
      </div>
    </div>
    </form>      
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.printLockUnlockSelectUserForm = async function(msg_pool, op, user_id) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader("Lock/Unlock User");
    html += _lockUserJavascriptSection(op);
    html += await _printLockUnlockSelectUserForm(conn, op, user_id);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}
 

exports.buildForceLogoutHTML = async function(msg_pool, users, alert_message, landing_page) {
  var conn, html, jsonUsers, m_site_dns, wspath;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    jsonUsers = JSON.stringify(users);
    alert_message = (typeof(alert_message) != "string")? "" : wev.allTrim(alert_message);
    landing_page = (typeof(landing_page) != "string")? "/message" : wev.allTrim(landing_page);
    
    //-- Construct websocket access path from DNS of messaging site. It will --//
    //-- be in format "wss://<your messaging site>/ws".                      --//        
    m_site_dns = await wev.getSiteDNS(conn, 'M');
    if (m_site_dns != '') {
      wspath = m_site_dns.replace('https', 'wss') + '/ws';
    }
    else {
      wspath = '';
    }
            
    if (wspath != '') {
      html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Force Logout</title>
        <meta name="viewport" content="minimum-scale=1.0, width=device-width, maximum-scale=1.0, initial-scale=1.0, user-scalable=no">   
        <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>                
      </head>
      <body style="width:auto;">  
      <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
      <link rel="shortcut icon" href="/favicon.ico">
      <script src="/js/jquery.min.js"></script>
      <script src="/js/jquery.mobile-1.4.5.min.js"></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src="/js/common_lib.js"></script>
      <script src="/js/crypto-lib.js"></script>
            
      <script>
        var users = ${jsonUsers};     // Note: 'jsonUsers' in here is an object, not string. 
        var alert_message = "${alert_message}";
        
        var myWebSocket = null;
        var wsOpenSocket = null;   
        var is_reopen = false;
        
        function connectWebServer() {
          var ws = new WebSocket("${wspath}");
                                            
          function reopenWebSocket() {                                    
            is_reopen = true; 
            myWebSocket = connectWebServer();
          }
        
          ws.onopen = function(e) {
            var this_cmd = {type: 'cmd', content:{op: 'force_logout', users: users}};
            sendCommand(this_cmd);
          }
                              
          ws.onerror = function(e) {
            console.log('Error: ' + e.message);
          }
          
          return ws;
        }  
        
        $(document).on("pageshow", function(event) {
          //-- Open a websocket and send out force logout message --//
          myWebSocket = connectWebServer();             
        });

        function sendCommand(cmd) {
          var message = JSON.stringify(cmd);
          
          if (myWebSocket.readyState == WebSocket.OPEN) {
            myWebSocket.send(message);
          }
          else {
            console.log('Unable to send force logout message due to websocket is not opened'); 
          }

          if (alert_message != "") {
            alert(alert_message);
          }   

          //-- Return to the message page --//
          returnToHome();       
        }
        
        async function returnToHome() {
          await prepareRollingKey(${_key_len});
          document.getElementById('frmLeap').submit();
        }        
      </script>   
      `;
    }
    else {
      html += `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Force Logout</title>
        <meta name="viewport" content="minimum-scale=1.0, width=device-width, maximum-scale=1.0, initial-scale=1.0, user-scalable=no">   
        <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>                
      </head>
      <body style="width:auto;">  
      <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
      <link rel="shortcut icon" href="/favicon.ico">
      <script src="/js/jquery.min.js"></script>
      <script src="/js/jquery.mobile-1.4.5.min.js"></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src="/js/common_lib.js"></script>
      <script src="/js/crypto-lib.js"></script>
      
      </script>
        var err_msg = "Unable to force logout these users, since no websocket can be created.";
        alert_message = (alert_message == "")? err_msg : alert_message + " " + err_msg;
        alert(alert_message);
        
        returnToHome();
        
        async function returnToHome() {
          await prepareRollingKey(${_key_len});
          document.getElementById('frmLeap').submit();
        }
      </script>      
      `;
    }
    
    html += `
      <form id='frmLeap' name='frmLeap' action='${landing_page}' method='POST'>
        <input type=hidden id="roll_rec" name="roll_rec" value="">
        <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
        <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
      </form>        
    </body>
    </html>     
    `
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


function _printSysSetupJavascriptSection() {
  var html;
  
  try {
    html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>System Setup</title>
      <meta name="viewport" content="minimum-scale=1.0, width=device-width, maximum-scale=1.0, initial-scale=1.0, user-scalable=no">   
      <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>                
      <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
      <link rel="shortcut icon" href="/favicon.ico">
      <script src="/js/jquery.min.js"></script>
      <script src="/js/jquery.mobile-1.4.5.min.js"></script>
      <script src="/js/js.cookie.min.js"></script>
      <script src="/js/common_lib.js"></script>
      <script src="/js/crypto-lib.js"></script>
    
      <script>
        async function maintainMainSites() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/maintain_main_sites";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }        
        }
        
        async function maintainEmailSenders() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/maintain_email_senders";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }                
        }
        
        async function maintainDecoySites() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/maintain_decoy_sites";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }                        
        }
        
        async function maintainFileTypes() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/maintain_file_types";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }                                
        }
        
        async function maintainSysSettings() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/maintain_sys_settings";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }                                        
        }
        
        async function telegramBotMaintain() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/admin/telegram_bot_maintain";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }                                        
        }
      
        async function goBack() {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById('frmLeap').action = "/message";
            document.getElementById('frmLeap').submit();        
          }
          catch(e) {
            alert(e.message);
          }
        }
      </script>
    </head>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printSystemSetupMenu() {
  var warning, html;
  
  try {
    warning = `<font color="red"><b>Warning:</b><br>Incorrect settings change may cause system malfunction and data lost!</font>`;
    
    html = `
    <body style="width:auto;">  
      <div data-role="page">
        <div data-role="header" data-position="fixed" data-tap-toggle="false">
          <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
          <h1>System Settings</h1>
        </div>	
    
        <div data-role="main" class="ui-body-d ui-content">
          <a href="javascript:maintainMainSites();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">Main Sites</a>
          <a href="javascript:maintainEmailSenders();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">Email Senders</a>      
          <a href="javascript:maintainDecoySites();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">Decoy Sites</a>
          <a href="javascript:maintainFileTypes();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">File Types</a>
          <a href="javascript:maintainSysSettings();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">Misc. System Settings</a>
          <a href="javascript:telegramBotMaintain();" class="ui-btn ui-corner-all ui-shadow" data-ajax="false">Telegram Bot</a>
          <br>
          ${warning}      
        </div>
      </div>
  
      <form id='frmLeap' name='frmLeap' action='' method='POST'>
        <input type=hidden id="roll_rec" name="roll_rec" value="">
        <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
        <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
      </form>            
    </body>
    </html>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printSystemSetupMenu = async function() {
  var html;
  
  try {
    html = wev.printHeader("System Config");
    html += _printSysSetupJavascriptSection();
    html += _printSystemSetupMenu();    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _getMainSites(conn) {
  var sql, data;
  var result = {decoy_site: '', message_site: ''};
  
  try {    
    sql = `SELECT site_type, site_dns ` +
          `  FROM sites ` +
          `  WHERE status = 'A'`;
    
    data = JSON.parse(await dbs.sqlQuery(conn, sql));

    for (var i = 0; i < data.length; i++) {
      var this_site_type = data[i].site_type.toUpperCase();
      
      if (this_site_type == "DECOY") {
        result.decoy_site = data[i].site_dns;
      }
      else if (this_site_type == "MESSAGE") {
        result.message_site = data[i].site_dns;
      }      
    }  
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printMainSitesMaintainJavascriptSection() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>
    <script src="/js/crypto-lib.js"></script>
  
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_main_sites").action = "/system_setup";
          document.getElementById("frm_main_sites").submit();          
        }
        catch(e) {
          alert(e.message);
        }
      }
    
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_main_sites").action = "/message";
          document.getElementById("frm_main_sites").submit();          
        }
        catch(e) {
          alert(e.message);
        }
      }
      
      async function saveMainSites() {
        try {
          var the_decoy_site = allTrim(document.getElementById("decoy_site").value);
          var the_message_site = allTrim(document.getElementById("message_site").value);
          
          if (the_decoy_site == "") {
            alert("Login (decoy) site DNS name should not be blank");
            return false;
          }
          
          if (the_message_site == "") {
            alert("Messaging site DNS name should not be blank");
            return false;
          }
        
          await prepareRollingKey(${_key_len});  
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frm_main_sites").action = "/admin/save_main_sites";
          document.getElementById("frm_main_sites").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printMainSitesMaintainForm(main_sites) {
  var html;
  
  try {
    html = `
    <form id="frm_main_sites" name="frm_main_sites" action="" method="post">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Main Sites</h1>
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>      
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <label for="decoy_site">Login (Decoy) Site DNS name:</label>
        <input type="text" id="decoy_site" name="decoy_site" value="${main_sites.decoy_site}">
        <label for="message_site">Messaging Site DNS name:</label>
        <input type="text" id="message_site" name="message_site" value="${main_sites.message_site}">      
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveMainSites();">                  
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printMainSitesMaintainForm = async function(msg_pool) {
  var conn, html;
  var main_sites = {decoy_site: '', message_site: ''};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    main_sites = await _getMainSites(conn);
    
    html = wev.printHeader("Maintain Main Sites");
    html += _printMainSitesMaintainJavascriptSection();
    html += _printMainSitesMaintainForm(main_sites);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


async function _getEmailSenderList(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT ms_id, email ` +
          `  FROM sys_email_sender ` +
          `  WHERE status = 'A' ` +
          `  ORDER BY email`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push({ms_id: data[i].ms_id, email: data[i].email});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _printEmailSenderListJavascriptSection(conn, sess_code, op, ms_id) {
  let html;
  
  try {
    await extendSession(conn, sess_code);   // Extend session period 
				
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
		<script src="/js/js.cookie.min.js"></script>  
		<script src='/js/crypto-lib.js'></script>	      
    <script src="/js/common_lib.js"></script>
  
    <script>
      var op = "${op}";
      var ms_id = ${ms_id};
	    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
	    var aes_key = "";
				        
	    async function showEmailSenderDataInForm(op, enc_data) {
	      let email, m_user, m_pass, smtp_server, port;
	    
	      try {
	        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
	        
	        if (op == "E") {        
				    email = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_email, enc_data.email);
            m_user = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_m_user, enc_data.m_user);
            m_pass = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_m_pass, enc_data.m_pass);
            smtp_server = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_smtp_server, enc_data.smtp_server);				    
				    port = parseInt(enc_data.port, 10);
				    
				    $('#email').val(email);
				    $('#m_user').val(m_user);
				    $('#m_pass').val(m_pass);
				    $('#smtp_server').val(smtp_server);
				    $('#port').val(port);
				  }
          
          // Clear AES key from RAM after used //
          aes_key = "";
			  }
			  catch(e) {
			    console.log(e);
			    alert("Error is found, operation is aborted. Error: " + e.message);
			    goHome();
			  }	    
		  }
	    	    
	    async function getEmailWorkerProfile() {
				var key_valid = true;
				aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
				if (typeof(aes_key) != "string") {
					key_valid = false;  
			  }
			  else {
			    aes_key = aes_key.trim();
			    if (aes_key.length < ${_key_len}) {
			      key_valid = false;
				  }					    
			  }
				
        // Clear AES key from RAM after used //
        aes_key = null;
                
				if (!key_valid) {
					alert("Secure key is lost, operation is aborted.");
          goHome(); 
			  }
			  else {					
					//-- Note: Due to asynchronous nature of javascript execution, it needs to use a  --//
					//--       promise to ensure the data is received from the server before the form --//
					//--       is displayed.                                                          --//  
					if (op == "E") {
            await prepareRollingKey(${_key_len});
            let roll_rec = document.getElementById("roll_rec").value;
            let iv_roll_rec = document.getElementById("iv_roll_rec").value;
            let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
                              
						let this_promise = new Promise((resolve, reject) => {                  			          
					    $.ajax({
					      type: 'POST',
					      url: '/get_email_sender_data',
					      dataType: 'html',
					      data: {
                  op: op, 
                  ms_id: ms_id, 
                  roll_rec: roll_rec,
                  iv_roll_rec: iv_roll_rec,
                  roll_rec_sum: roll_rec_sum 
                },
					      success: function(ret_data) {
					        let result = JSON.parse(ret_data);
                  let err_msg = "";
					        
					        if (result.ok == '1') {						
					          resolve(result.data);         // Note: 'result.data' is encrypted by 'aes_key' on server side, except 'result.data.port'.
								  }
					        else {
                    if (result.msg == "force_logout" || result.msg == "session_expired" || result.msg == "session_check_error" || result.msg == "no_cookie") {
                      err_msg = result.msg;
                    }  
                    else {
					            err_msg = "Unable to get data. Error: " + result.msg;
					            console.log(err_msg);
                    }
                    
					          reject(new Error(err_msg));
								  }
							  },
							  error: function(xhr, ajaxOptions, thrownError) {
							    let err_msg = "Unable to get data. Error " + xhr.status + ": " + thrownError
							    console.log(err_msg);
		              reject(new Error(err_msg));
		            }
						  });
					  });
					  
					  this_promise.then((enc_data) => {
							showEmailSenderDataInForm(op, enc_data);
					  }).catch((error) => {
              if (error.message.match(/force_logout/g)) {
                logout_msg();
              } 
              else if (error.message.match(/no_cookie/g)) {
                window.location.href = "/";
              }
              else if (error.message.match(/session_expired/g)) {
                alert("Session expired!");
                logout_msg();
              }
              else if (error.message.match(/session_check_failure/g)) {
                alert("Unable to check your session status, please login again");
                logout_msg();
              }
              else {
					      alert(error.message);
                goHome();
              }
					  });
				  }
			  }	    
		  }
	    
			$(document).on("pageshow", function(event) {          
				getEmailWorkerProfile();				
			});	    
    
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_email_sender").action = "/system_setup";
          document.getElementById("frm_email_sender").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_email_sender").action = "/message";
          document.getElementById("frm_email_sender").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
      
      async function goEmailWorkerList() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_email_sender").action = "/admin/maintain_email_senders";
          document.getElementById("frm_email_sender").submit();                    
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      function logout_msg() {
        window.location.href = "/logout_msg";
      }
      
      async function addEmailSender() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("op").value = "A";
          document.getElementById("frm_email_sender").action = "/admin/new_email_senders";
          document.getElementById("frm_email_sender").submit();
        }
        catch(e) {
          alert(e.message);
        }          
      }
      
      async function editEmailSender(ms_id) {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("op").value = "E";
          document.getElementById("ms_id").value = ms_id;
          document.getElementById("frm_email_sender").action = "/admin/edit_email_senders";
          document.getElementById("frm_email_sender").submit();    
        }
        catch(e) {
          alert(e.message);
        }  
      }
      
      async function deleteEmailSender(ms_id) {
        if (confirm("Are you sure to delete this email sender?")) {
          try {
            await prepareRollingKey(${_key_len});
            document.getElementById("op").value = "D";
            document.getElementById("oper_mode").value = "S";
            document.getElementById("ms_id").value = ms_id;
            document.getElementById("frm_email_sender").action = "/admin/save_email_senders";
            document.getElementById("frm_email_sender").submit();
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
      
      async function saveEmailSender() {
        var email = allTrim($('#email').val());
        var m_user = allTrim($('#m_user').val());
        var m_pass = allTrim($('#m_pass').val());
        var smtp_server = allTrim($('#smtp_server').val());
        var port = parseInt($('#port').val(), 10);
        var enc_obj;
        
        if (email == "") {
          alert("Please input email sender address before saving");
          $('#email').focus();
          return false;
        }
        
        if (m_user == "") {
          alert("Please input login username for the email sender before saving");
          $('#m_user').focus();
          return false;
        }
        
        if (m_pass == "") {
          alert("Please input login password for the email sender before saving");
          $('#m_pass').focus();
          return false;
        }
        
        if (smtp_server == "") {
          alert("Please input SMTP server for the email sender before saving");
          $('#smtp_server').focus();
          return false;
        }
        
        if (port <= 0 || isNaN(port)) {
          alert("Please input port number used by the SMTP server for the email sender before saving");
          $('#port').focus();
          return false;
        }
        
        var ready_to_go = true;
        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
        if (typeof(aes_key) != "string") {
          //-- It has no key --//
          ready_to_go = false;
			  }
			  else {
			    aes_key = aes_key.trim();
			    if (aes_key.length < ${_key_len}) {
			      //-- The key is too weak --//
			      ready_to_go = false;
				  }
			  }
        
        if (ready_to_go) {
          try {
            var algorithm = "AES-GCM";
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, email);
            var iv_email = enc_obj.iv
            var e_email = enc_obj.encrypted;
  
            enc_obj = await aesEncryptJSON(algorithm, aes_key, m_user);
            var iv_m_user = enc_obj.iv
            var e_m_user = enc_obj.encrypted;
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, m_pass);
            var iv_m_pass = enc_obj.iv
            var e_m_pass = enc_obj.encrypted;
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, smtp_server);
            var iv_smtp_server = enc_obj.iv
            var e_smtp_server = enc_obj.encrypted;
            
            var e_port = port;             // SMTP server port number isn't going to be encrypted.
            
            // Clear AES key from RAM after used //
            aes_key = null;
            
            $('#algorithm').val(algorithm);
            $('#iv_email').val(iv_email);
            $('#e_email').val(e_email);
            $('#iv_m_user').val(iv_m_user);
            $('#e_m_user').val(e_m_user);
            $('#iv_m_pass').val(iv_m_pass);
            $('#e_m_pass').val(e_m_pass);
            $('#iv_smtp_server').val(iv_smtp_server);
            $('#e_smtp_server').val(e_smtp_server);
            $('#e_port').val(e_port);
            
            $('#email').val("");
            $('#m_user').val("");
            $('#m_pass').val("");
            $('#smtp_server').val("");
            $('#port').val("");
                            
            $('#oper_mode').val("S");
            //-- Note: Don't use jQuery syntax to submit the form, or else a strange issue will get in next step. --//
            //--       Since currently used jQuery libray is too old to understand asyn/await syntax.             --// 
            await prepareRollingKey(${_key_len});
            document.getElementById("frm_email_sender").action = "/admin/save_email_senders";
            document.getElementById("frm_email_sender").submit();
          }
          catch(e) {
            alert(e.message);
          }
			  }
			  else {
			    alert("The secure key is lost, and operation is aborted. Now, you will be returned to the home page.");
          goHome();
			  }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printEmailSenderList(ms_list) {
  var html;
  
  try {
    html = `
    <form id="frm_email_sender" name="frm_email_sender" action="" method="post">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="ms_id" name="ms_id" value="0">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">    
    
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Email Senders</h1>
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>      
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed;">
        <thead>
          <tr style="background-color:lightblue">
            <td width=70% align=center valign=center><b>Email Sender</b></td>
            <td align=center valign=center><b>Delete</b></td>
          </tr>
        </thead>
        <tbody>`;
    
    for (var i = 0; i < ms_list.length; i++) {
      var this_ms_id = ms_list[i].ms_id;
      var this_email = ms_list[i].email;
      
      html += `
      <tr style="background-color:lightyellow">
        <td align=center valign=center style="word-wrap:break-word;"><a href="javascript:editEmailSender(${this_ms_id})">${this_email}</a></td>
        <td align=center valign=center><input type="button" id="del_es" name="del_es" value="" data-icon="delete" data-iconpos="notext" onClick="deleteEmailSender(${this_ms_id})"></td>
      </tr>`;
    }
    
    html += `
        </tbody>
        </table>
        <br>
        <input type="button" id="add_new" name="add_new" value="Add Email Sender" onClick="addEmailSender();" data-icon="plus">                  
      </div>
    </div>
    </form>`;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printEmailSenderList = async function(msg_pool, sess_code) {
  var conn, html;
  var ms_list = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    ms_list = await _getEmailSenderList(conn);
    
    html = wev.printHeader("Maintain Email Sender");
    html += await _printEmailSenderListJavascriptSection(conn, sess_code, "L", 0);
    html += _printEmailSenderList(ms_list);     
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
    
  return html;  
}


function _printNewEmailSenderForm(op) {
  var html;
  
  try {
    html = `
    <form id="frm_email_sender" name="frm_email_sender" action="" method="post">
    <input type=hidden id="algorithm" name="algorithm" value="">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="iv_email" name="iv_email" value="">
    <input type=hidden id="e_email" name="e_email" value="">
    <input type=hidden id="iv_m_user" name="iv_m_user" value="">
    <input type=hidden id="e_m_user" name="e_m_user" value="">
    <input type=hidden id="iv_m_pass" name="iv_m_pass" value="">
    <input type=hidden id="e_m_pass" name="e_m_pass" value="">
    <input type=hidden id="iv_smtp_server" name="iv_smtp_server" value="">
    <input type=hidden id="e_smtp_server" name="e_smtp_server" value="">
    <input type=hidden id="e_port" name="e_port" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goEmailWorkerList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Add Email Sender</h1>
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <label for="email">Email Address:</label>
        <input type="text" id="email" name="email" value="" maxlength=128>
        <label for="m_user">Login Username:</label>
        <input type="text" id="m_user" name="m_user" value="" maxlength=64>
        <label for="m_pass">Login Password:</label>
        <input type="text" id="m_pass" name="m_pass" value="" maxlength=64>
        <label for="smtp_server">SMTP Server:</label>
        <input type="text" id="smtp_server" name="smtp_server" value="" maxlength=128>
        <label for="port">Port No.:</label>
        <input type="text" id="port" name="port" value="0">
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveEmailSender();">                  
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printNewEmailSenderForm = async function(msg_pool, op, sess_code) {
  var conn, html;
  
  try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
		
    html = wev.printHeader("Add Email Worker");
    html += await _printEmailSenderListJavascriptSection(conn, sess_code, op, 0);
    html += _printNewEmailSenderForm(op);
  }
  catch(e) {
    throw e;
  }
  finally {
		dbs.releasePoolConn(conn);
	}
  
  return html;
}


async function _getEmailSenderDetails(conn, ms_id) {
  var sql, param, data;
  var email_worker = {};
  
  try {
    sql = `SELECT email, m_user, m_pass, smtp_server, port ` +
          `  FROM sys_email_sender ` +
          `  WHERE ms_id = ?`;
          
    param = [ms_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      email_worker = {email: data[0].email, m_user: data[0].m_user, m_pass: data[0].m_pass, smtp_server: data[0].smtp_server, port: data[0].port};
    }
    else {
      throw new Error("Unable to find the email worker, may be someone just delete it.");
    }          
  }
  catch(e) {
    throw e;
  }
  
  return email_worker;
}


exports.getEmailSenderDetails = async function(msg_pool, ms_id, user_id, sess_code) {
	let conn, aes_key, enc_obj, buffer, algorithm;
	let email_worker = {algorithm: "", iv_email: "", email: "", iv_m_user: "", m_user: "", iv_m_pass: "", m_pass: "", iv_smtp_server: "", smtp_server: "", port: ""};
	
	try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
		//-- Step 1: Get email worker profile --//
		buffer = await _getEmailSenderDetails(conn, ms_id);		
		//-- Step 2: Get session AES key of requested user --//
		aes_key = await msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
    //-- Step 3: Encrypt all data on 'buffer' --//
    algorithm = "AES-GCM";
    email_worker.algorithm = algorithm;
    		
    enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, buffer.email);
    email_worker.iv_email = enc_obj.iv;
    email_worker.email = enc_obj.encrypted;

    enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, buffer.m_user);
    email_worker.iv_m_user = enc_obj.iv;
    email_worker.m_user = enc_obj.encrypted;
    
    enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, buffer.m_pass);
    email_worker.iv_m_pass = enc_obj.iv;
    email_worker.m_pass = enc_obj.encrypted;
    
    enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, buffer.smtp_server);
    email_worker.iv_smtp_server = enc_obj.iv;
    email_worker.smtp_server = enc_obj.encrypted;
    
    //-- SMTP server port is a numeric data, and it is not going to be encrypted. --//
    email_worker.port = buffer.port;
	}
	catch(e) {		
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
	
	return email_worker;
}


function _printEmailSenderEditForm(op, ms_id) {
  var html;
  
  try {
    html = `
    <form id="frm_email_sender" name="frm_email_sender" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="algorithm" name="algorithm" value="">
    <input type=hidden id="ms_id" name="ms_id" value="${ms_id}">
    <input type=hidden id="iv_email" name="iv_email" value="">
    <input type=hidden id="e_email" name="e_email" value="">
    <input type=hidden id="iv_m_user" name="iv_m_user" value="">
    <input type=hidden id="e_m_user" name="e_m_user" value="">
    <input type=hidden id="iv_m_pass" name="iv_m_pass" value="">
    <input type=hidden id="e_m_pass" name="e_m_pass" value="">
    <input type=hidden id="iv_smtp_server" name="iv_smtp_server" value="">
    <input type=hidden id="e_smtp_server" name="e_smtp_server" value="">
    <input type=hidden id="e_port" name="e_port" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goEmailWorkerList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Edit Email Sender</h1>
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <label for="email">Email Address:</label>
        <input type="text" id="email" name="email" value="" maxlength=128>
        <label for="m_user">Login Username:</label>
        <input type="text" id="m_user" name="m_user" value="" maxlength=64>
        <label for="m_pass">Login Password:</label>
        <input type="text" id="m_pass" name="m_pass" value="" maxlength=64>
        <label for="smtp_server">SMTP Server:</label>
        <input type="text" id="smtp_server" name="smtp_server" value="" maxlength=128>
        <label for="port">Port No.:</label>
        <input type="text" id="port" name="port" value="">
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveEmailSender();">                  
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printEmailSenderEditForm = async function(msg_pool, op, ms_id, sess_code) {
  let conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader("Edit Email Worker");
    html += await _printEmailSenderListJavascriptSection(conn, sess_code, op, ms_id);
    html += _printEmailSenderEditForm(op, ms_id);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


exports.decryptEmailAccountDataSet = async function(algorithm, aes_key, data) {
	let email, m_user, m_pass, smtp_server, result;
	
	try {
		email = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_email, data.e_email);
		m_user = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_m_user, data.e_m_user);
		m_pass = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_m_pass, data.e_m_pass);
		smtp_server = await cipher.aesDecryptJSON(algorithm, aes_key, data.iv_smtp_server, data.e_smtp_server);
		
		result = {email: email, m_user: m_user, m_pass: m_pass, smtp_server: smtp_server};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


async function _getDecoySiteList(conn) {
  var sql, data;
  var site_list = [];
  
  try {
    sql = `SELECT site_url ` +
          `  FROM decoy_sites ` +
          `  ORDER BY site_url`;
    
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      site_list.push(data[i].site_url);
    } 
  }
  catch(e) {
    throw e;
  }
  
  return site_list;
}


function _printDecoySiteListJavascriptSection() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>
    <script src="/js/crypto-lib.js"></script>
  
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_decoy_site").action = "/system_setup";
          document.getElementById("frm_decoy_site").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_decoy_site").action = "/message";
          document.getElementById("frm_decoy_site").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
      
      async function goDecoySiteList() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_decoy_site").action = "/admin/maintain_decoy_sites";
          document.getElementById("frm_decoy_site").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }      
      
      async function addDecoySite() {
        try {
          await prepareRollingKey(${_key_len});        
          document.getElementById("op").value = "A";
          document.getElementById("frm_decoy_site").action = "/admin/add_new_decoy_site";
          document.getElementById("frm_decoy_site").submit();
        }
        catch(e) {
          alert(e.message);
        }          
      }
      
      async function editDecoySite(site_url) {
        try {
          await prepareRollingKey(${_key_len});                
          document.getElementById("op").value = "E";
          document.getElementById("site_url").value = site_url;
          document.getElementById("frm_decoy_site").action = "/admin/modify_decoy_site";
          document.getElementById("frm_decoy_site").submit();
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      async function deleteDecoySite(site_url) {
        if (confirm("Are you sure to delete this decoy site?")) {
          try {
            await prepareRollingKey(${_key_len});                          
            document.getElementById("op").value = "D";
            document.getElementById("oper_mode").value = "S";
            document.getElementById("site_url").value = site_url;
            document.getElementById("frm_decoy_site").action = "/admin/save_decoy_site";
            document.getElementById("frm_decoy_site").submit();
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
      
      async function saveDecoySite() {
        try {            
          let site_url = allTrim(document.getElementById("site_url").value);
          
          if (site_url == "") {
            alert("Please input decoy site URL before saving");          
            document.getElementById("site_url").focus();
            return false;
          }
        
          await prepareRollingKey(${_key_len});                                  
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frm_decoy_site").action = "/admin/save_decoy_site";
          document.getElementById("frm_decoy_site").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printDecoySiteList(site_list) {
  var html;
  
  try {
    html = `
    <form id="frm_decoy_site" name="frm_decoy_site" action="" method="post">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="site_url" name="site_url" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack()" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Decoy Sites</h1>
        <a href="javascript:goHome()" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed;">
        <thead>
          <tr style="background-color:lightblue">
            <td width=80% align=center valign=center><b>Decoy Site</b></td>
            <td align=center valign=center><b>Delete</b></td>
          </tr>
        </thead>      
        <tbody>    
    `;
    
    for (var i = 0; i < site_list.length; i++) {
      var this_site_url = site_list[i];
      
      html += `
          <tr style="background-color:lightyellow">
            <td valign=center style="word-wrap:break-word;"><a href="javascript:editDecoySite('${this_site_url}')">${this_site_url}</a></td>
            <td align=center valign=center><input type=button id="del_ds" name="del_ds" data-icon="delete" data-iconpos="notext" onClick="deleteDecoySite('${this_site_url}')"></td>
          </tr>      
      `;
    }
    
    html += `
          <tr style="background-color:lightblue">
            <td colspan=2 align=center>End</td>
          </tr>
        </tbody>
        </table>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center valign=center><input type=button id="add_ds" name="add_ds" value="Add Decoy Site" data-icon="plus" onClick="addDecoySite()"></td>
          </tr> 
        </tbody>
        </table>
      </div>        
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printDecoySiteList = async function(msg_pool) {
  var conn, html;
  var site_list = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    site_list = await _getDecoySiteList(conn);
    
    html = wev.printHeader("Maintain Decoy Sites");
    html += _printDecoySiteListJavascriptSection();
    html += _printDecoySiteList(site_list);     
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


function _printNewDecoySiteForm(op) {
  var html;
  
  try {
    html = `
    <form id="frm_decoy_site" name="frm_decoy_site" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goDecoySiteList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Add Decoy Site</h1>
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <label for="site_url">Decoy Site URL:</label>
        <input type="text" id="site_url" name="site_url" value="" maxlength=512>
        <label for="key_words">Site Categorization Key Words:</label>
        <input type="text" id="key_words" name="key_words" value="" maxlength=512 placeholder="Key words like 'Tech News', 'Forum', etc.">
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveDecoySite();">
        <br>
        <b>Remark:</b><br>
        You may input multiple key words by seperating them with comma.
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printNewDecoySiteForm = async function(op) {
  var html;
  
  try {
    html = wev.printHeader("Add decoy site");
    html += _printDecoySiteListJavascriptSection();
    html += _printNewDecoySiteForm(op);
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


async function _getDecoySiteDetails(conn, site_url) {
  var sql, param, data;
  var result = {};
  
  try {
    sql = `SELECT key_words ` +
          `  FROM decoy_sites ` +
          `  WHERE site_url = ?`;
          
    param = [site_url];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));      
    
    if (data.length > 0) {
      result = {site_url: site_url, key_words: data[0].key_words};
    }
    else {
      throw new Error("Unable to find details of decoy site ${site_url}, it may be deleted.");
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printDecoySiteEditForm(op, decoy_site) {
  var html;
  
  try {
    html = `
    <form id="frm_decoy_site" name="frm_decoy_site" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="site_url_old" name="site_url_old" value="${decoy_site.site_url}">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goDecoySiteList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>			
        <h1>Edit Decoy Site</h1>
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
        <label for="site_url">Decoy Site URL:</label>
        <input type="text" id="site_url" name="site_url" value="${decoy_site.site_url}" maxlength=512>
        <label for="key_words">Site Categorization Key Words:</label>
        <input type="text" id="key_words" name="key_words" value="${decoy_site.key_words}" maxlength=512 placeholder="Key words like 'Tech News', 'Forum', etc.">
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveDecoySite();">
        <br>
        <b>Remark:</b><br>
        You may input multiple key words by seperating them with comma.
      </div>    
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.printDecoySiteEditForm = async function(msg_pool, op, site_url) {
  var conn, html;
  var decoy_site = {};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    decoy_site = await _getDecoySiteDetails(conn, site_url);
    
    html = wev.printHeader("Modify Decoy Site");
    html += _printDecoySiteListJavascriptSection();
    html += _printDecoySiteEditForm(op, decoy_site);
  }
  catch(e) {https://www.torproject.org/
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


async function _getFileTypeList(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT ftype_id, file_ext, file_type ` +
          `  FROM file_type ` +
          `  ORDER BY file_type, file_ext`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push({ftype_id: data[i].ftype_id, file_ext: data[i].file_ext, file_type: data[i].file_type});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printFileTypeListJS() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/jquery-editable-select.min.js"></script>
    <link href="/js/jquery-editable-select.min.css" rel="stylesheet">  
    <script src="/js/common_lib.js"></script>
    <script src="/js/crypto-lib.js"></script>
  
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_file_type").action = "/system_setup";
          document.getElementById("frm_file_type").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_file_type").action = "/message";
          document.getElementById("frm_file_type").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
      
      async function goFileTypeList() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_file_type").action = "/admin/maintain_file_types";
          document.getElementById("frm_file_type").submit();                    
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      async function addFileType() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("op").value = "A";
          document.getElementById("frm_file_type").action = "/admin/add_new_file_type";
          document.getElementById("frm_file_type").submit();
        }
        catch(e) {
          alert(e.message);
        }          
      }
      
      async function editFileType(ftype_id) {
        try {
          await prepareRollingKey(${_key_len});        
          document.getElementById("op").value = "E";
          document.getElementById("ftype_id").value = ftype_id;
          document.getElementById("frm_file_type").action = "/admin/modify_file_type";
          document.getElementById("frm_file_type").submit();
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      async function deleteFileType(ftype_id) {
        if (confirm("Are you sure to delete this file type?")) {
          try {
            await prepareRollingKey(${_key_len});        
            document.getElementById("op").value = "D";
            document.getElementById("ftype_id").value = ftype_id;
            document.getElementById("oper_mode").value = "S";
            document.getElementById("frm_file_type").action = "/admin/save_file_type";
            document.getElementById("frm_file_type").submit();
          }
          catch(e) {
            alert(e.message);
          }
        }
      }
      
      async function saveFileType() {
        try {
          var file_ext = allTrim($('#file_ext').val());
          var file_type = allTrim($('#file_type').val());
          
          if (file_ext == "") {
            alert("Please input file extension before saving");
            $('#file_ext').focus();
            return false;
          }
          
          if (file_type == "") {
            alert("Please input file type before saving");
            $('#file_type').focus();
            return false;
          }      

          await prepareRollingKey(${_key_len});
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frm_file_type").action = "/admin/save_file_type";
          document.getElementById("frm_file_type").submit();
        }
        catch(e) {
          alert(e.message);
        }        
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printFileTypeList(ftype_list) {
  var html;
  
  try {
    html = `
    <form id="frm_file_type" name="frm_file_type" action="" method="post">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="ftype_id" name="ftype_id" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack()" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>File Types</h1>
        <a href="javascript:goHome()" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed;">
        <thead>
          <tr style="background-color:lightblue">
            <td width=30% align=center valign=center><b>File Ext.</b></td>
            <td width=50% align=center valign=center><b>File Type</b></td>
            <td align=center valign=center><b>Delete</b></td>
          </tr>
        </thead>      
        <tbody>    
    `;
    
    for (var i = 0; i < ftype_list.length; i++) {
      var this_ftype_id = ftype_list[i].ftype_id;
      var this_file_ext = ftype_list[i].file_ext;
      var this_file_type = ftype_list[i].file_type;
            
      html += `
          <tr style="background-color:lightyellow">
            <td align=center valign=center style="word-wrap:break-word;"><a href="javascript:editFileType(${this_ftype_id})">${this_file_ext}</a></td>
            <td align=center valign=center style="word-wrap:break-word;"><a href="javascript:editFileType(${this_ftype_id})">${this_file_type}</a></td>
            <td align=center valign=center><input type=button id="del_ft" name="del_ft" data-icon="delete" data-iconpos="notext" onClick="deleteFileType(${this_ftype_id})"></td>
          </tr>      
      `;
    }
    
    html += `
          <tr style="background-color:lightblue">
            <td align=center valign=center colspan=3>End</td>  
          </tr>
        </tbody>
        </table>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center valign=center><input type=button id="add_ft" name="add_ft" value="Add File Type" data-icon="plus" onClick="addFileType()"></td>
          </tr> 
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printFileTypeList = async function(msg_pool) {
  var conn, html;
  var ftype_list = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    ftype_list = await _getFileTypeList(conn);
        
    html = wev.printHeader("Maintain File Type");
    html += _printFileTypeListJS();
    html += _printFileTypeList(ftype_list);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getExistFileTypes(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT DISTINCT file_type ` +
          `  FROM file_type ` +
          `  ORDER BY file_type`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push(data[i].file_type);
    }          
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printNewFileTypeForm(op, file_types) {
  var file_type_options, html;
  
  try {
    file_type_options = "";
    for (var i = 0; i < file_types.length; i++) {
      file_type_options += `
      <option>${file_types[i]}</option>
      `;
    }
    
    html = `
    <form id="frm_file_type" name="frm_file_type" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goFileTypeList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Add File Type</h1>
      </div>
      
      <div data-role="main" class="ui-body-d ui-content">
        <label for="file_ext">File Ext.:</label>
        <input type=text id="file_ext" name="file_ext" value="" maxlength=16>
        <label for="file_type">File Type:</label>
        <select id="file_type" name="file_type">
          ${file_type_options}
        </select>      
        <script>
          //-- Activate editable selection for input object 'file_type' --// 
          $('#file_type').editableSelect({
            effects: 'slide',
            duration: 200
          });
        </script>
        <br>
        <input type=button id="save" name="save" Value="Save" onClick="saveFileType()">
        <br>
        <b>Remark:</b><br>
        You may add new file type or select existing file type from the list.
      </div>    
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printNewFileTypeForm = async function(msg_pool, op) {
  var conn, html;
  var file_types = []; 
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    file_types = await _getExistFileTypes(conn);
    
    html = wev.printHeader("Add File Type");
    html += _printFileTypeListJS();
    html += _printNewFileTypeForm(op, file_types);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getFileTypeDetails(conn, ftype_id) {
  var sql, param, data;
  var result = {file_ext: '', file_type: ''};
  
  try {
    sql = `SELECT file_ext, file_type ` +
          `  FROM file_type ` +
          `  WHERE ftype_id = ?`;
    
    param = [ftype_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = {file_ext: data[0].file_ext, file_type: data[0].file_type};
    }
    else {
      throw new Error("Unable to get details of this file type, the record may be just deleted.");
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function _printFileTypeEditForm(op, ftype_id, ftype_dtl, file_types) {
  var file_type_options, html;
  
  try {
    file_type_options = ``;
    for (var i = 0; i < file_types.length; i++) {
      var selected = (file_types[i] == ftype_dtl.file_type)? "selected" : "";      
      file_type_options += `<option ${selected}>${file_types[i]}</option>`;
    }
    
    html = `
    <form id="frm_file_type" name="frm_file_type" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="ftype_id" name="ftype_id" value="${ftype_id}">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goFileTypeList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Edit File Type</h1>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <label for="file_ext">File Ext.:</label>
        <input type=text id="file_ext" name="file_ext" value="${ftype_dtl.file_ext}" maxlength=16>
        <label for="file_type">File Type:</label>
        <select id="file_type" name="file_type">
          ${file_type_options}
        </select>      
        <script>
          //-- Activate editable selection for input object 'file_type' --// 
          $('#file_type').editableSelect({
            effects: 'slide',
            duration: 200
          });
        </script>
        <br>
        <input type=button id="save" name="save" Value="Save" onClick="saveFileType()">
        <br>
        <b>Remark:</b><br>
        You may add new file type or select existing file type from the list.
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printFileTypeEditForm = async function(msg_pool, op, ftype_id) {
  var conn, html;
  var file_types = [];
  var ftype_dtl = {};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    file_types = await _getExistFileTypes(conn);
    ftype_dtl = await _getFileTypeDetails(conn, ftype_id);
    
    html = wev.printHeader("Modify File Type");
    html += _printFileTypeListJS();
    html += _printFileTypeEditForm(op, ftype_id, ftype_dtl, file_types);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


async function _getSysSettingList(conn) {
  var sql, data;
  var result = [];
  
  try {
    sql = `SELECT sys_key, sys_value ` +
          `  FROM sys_settings ` +
          `  ORDER BY sys_key`;
    
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      result.push({sys_key: data[i].sys_key, sys_value: data[i].sys_value});
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printSysSettingJS() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>
    <script src="/js/crypto-lib.js"></script>
  
    <script>
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_sys_set").action = "/system_setup";
          document.getElementById("frm_sys_set").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }
    
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_sys_set").action = "/message";
          document.getElementById("frm_sys_set").submit();                    
        }
        catch(e) {
          alert(e.message);
        }
      }

      async function goSysSettingList() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frm_sys_set").action = "/admin/maintain_sys_settings";
          document.getElementById("frm_sys_set").submit();                    
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      /* This code block is frozen to prevent user add misc. system settings.
      function addSysSetting() {
        document.getElementById("op").value = "A";
        document.getElementById("frm_sys_set").action = "/admin/add_sys_setting";
        document.getElementById("frm_sys_set").submit();          
      }
      */
      
      async function editSysSetting(sys_key) {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("op").value = "E";
          document.getElementById("sys_key").value = sys_key;
          document.getElementById("frm_sys_set").action = "/admin/modify_sys_setting";
          document.getElementById("frm_sys_set").submit();
        }
        catch(e) {
          alert(e.message);
        }      
      }
      
      /* This code block is frozen to prevent user delete misc. system settings.
      function deleteSysSetting(sys_key) {
        if (confirm("Are you sure to delete this system setting?")) {
          document.getElementById("op").value = "D";
          document.getElementById("oper_mode").value = "S";
          document.getElementById("sys_key").value = sys_key;
          document.getElementById("frm_sys_set").action = "/admin/save_sys_setting";
          document.getElementById("frm_sys_set").submit();
        }
      }
      */
      
      async function saveSysSetting() {
        try {
          var sys_key = allTrim($('#sys_key').val());
          var sys_value = allTrim($('#sys_value').val());
          
          if (sys_key == "") {
            alert("Please input key of system setting before saving");
            $('#sys_key').focus();
            return false;
          }
          
          if (sys_value == "") {
            alert("Please input key value of system setting before saving");
            $('#sys_value').focus();
            return false;
          }

          await prepareRollingKey(${_key_len});          
          document.getElementById("oper_mode").value = "S";
          document.getElementById("frm_sys_set").action = "/admin/save_sys_setting";
          document.getElementById("frm_sys_set").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printSysSettingList(key_list) {
  var html;
  
  try {
    html = `
    <form id="frm_sys_set" name="frm_sys_set" action="" method="post">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="sys_key" name="sys_key" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack()" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>System Settings</h1>
        <a href="javascript:goHome()" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed">
        <thead>
          <tr style="background-color:lightblue">
            <td width=30% align=center valign=center><b>Key</b></td>
            <td width=70% align=center valign=center><b>Value</b></td>
            <!-- User should not delete a misc. system settings
            <td align=center valign=center><b>Delete</b></td>
            //-->
          </tr>
        </thead>
        <tbody>    
    `;
    
    for (var i = 0; i < key_list.length; i++) {
      var this_sys_key = key_list[i].sys_key;
      var this_sys_value = key_list[i].sys_value;
      
      html += `
          <tr style="background-color:lightyellow">
            <td valign=center style="word-wrap:break-word">
              <a href="javascript:editSysSetting('${this_sys_key}')">${this_sys_key}</a>
            </td>
            <td valign=center style="word-wrap:break-word">
              <a href="javascript:editSysSetting('${this_sys_key}')">${this_sys_value}</a>
            </td>
            <!--
            <td align=center valign=center>
              <input type=button id="del_ss" name="del_ss" data-icon="delete" data-iconpos="notext" onClick="deleteSysSetting('${this_sys_key}')">
            </td>
            //-->
          </tr>      
      `;
    }
    
    html += `
          <tr style="background-color:lightblue"><td align=center colspan=2>End</td></tr>
        </tbody>
        </table>
      </div>
  
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <!-- User should not add a new misc. system setting
        <table width=100% cellspacing=0 cellpadding=0 style="table-layout:fixed">
        <thead></thead>
        <tbody>
          <tr>
            <td align=center valign=center><input type=button id="add_ss" name="add_ss" value="Add System Setting" data-icon="plus" onClick="addSysSetting()"></td>
          </tr>
        </tbody>
        //-->
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  } 
  
  return html;
}


exports.printSysSettingList = async function(msg_pool) {
  var conn, html;
  var key_list = [];
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie("MSG"));
    
    key_list = await _getSysSettingList(conn);
    
    html = wev.printHeader("Maintain Misc. System Settings");
    html += _printSysSettingJS();
    html += _printSysSettingList(key_list);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getSysSettingDetails(conn, sys_key) {
  var sql, param, data;
  var result = {sys_key: '', sys_value: ''};
  
  try {
    sql = `SELECT sys_value ` +
          `  FROM sys_settings ` +
          `  WHERE sys_key = ?`;
          
    param = [sys_key];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = {sys_key: sys_key, sys_value: data[0].sys_value};
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printSysSettingEditForm(op, key_dtl) {
  var html;
  
  try {
    html = `
    <form id="frm_sys_set" name="frm_sys_set" action="" method="post">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="sys_key_old" name="sys_key_old" value="${key_dtl.sys_key}">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goSysSettingList();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Edit Sys Setting</h1>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <label for="sys_key">Key:</label>
        <!-- Don't let user change the system setting key //-->
        <input type=text id="sys_key" name="sys_key" value="${key_dtl.sys_key}" maxlength=64 readonly>
        <label for="sys_value">Value:</label>
        <input type=text id="sys_value" name="sys_value" value="${key_dtl.sys_value}" maxlength=512>
        <br>
        <input type=button id="save" name="save" value="Save" onClick="saveSysSetting()">  
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printSysSettingEditForm = async function(msg_pool, op, sys_key) {
  var conn, html;
  var key_dtl = {};
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    key_dtl = await _getSysSettingDetails(conn, sys_key);
 
    html = wev.printHeader("Edit System Setting");
    html += _printSysSettingJS();
    html += _printSysSettingEditForm(op, key_dtl);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _printTelegramBotProfileJS(conn, sess_code) {
  let html;
  
  try {
    await extendSession(conn, sess_code);   // Extend session period 
				
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
		<script src="/js/js.cookie.min.js"></script>  
		<script src='/js/crypto-lib.js'></script>    
    <script src="/js/common_lib.js"></script>    
  
    <script>
      var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
      var aes_key = "";

			$(document).on("pageshow", function(event) {    
			  getTelegramBotProfile();      
			});	    
				        	    
	    async function getTelegramBotProfile() {
				var key_ready = true;
				aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
				if (typeof(aes_key) != "string") {
					key_ready = false;
			  }
			  else {
			    aes_key = aes_key.trim();
			    if (aes_key.length < ${_key_len}) {
			      key_ready = false;
				  }
			  }
        // Clear AES key from RAM after used //
        aes_key = null;
				
				if (!key_ready) {
					alert("Secure key is lost, operation is aborted and return to home page.");
          goHome(); 
			  }
			  else {
          await prepareRollingKey(${_key_len});
          let roll_rec = document.getElementById("roll_rec").value;
          let iv_roll_rec = document.getElementById("iv_roll_rec").value;
          let roll_rec_sum = document.getElementById("roll_rec_sum").value;          
                  					
					//-- Note: Due to asynchronous nature of javascript execution, it needs to use a  --//
					//--       promise to ensure the data is received from the server before the form --//
					//--       is displayed.                                                          --//                      
					let this_promise = new Promise((resolve, reject) => {                  			          
				    $.ajax({
				      type: 'POST',
				      url: '/get_telegram_bot_profile',
				      dataType: 'html',
              data: {
                roll_rec: roll_rec,
                iv_roll_rec: iv_roll_rec,
                roll_rec_sum: roll_rec_sum
              },
				      success: function(ret_data) {
				        let result = JSON.parse(ret_data);
				        
				        if (result.ok == '1') {						
				          resolve(result.data);         // Note: 'result.data' is encrypted by 'aes_key' on server side.
							  }
				        else {
                  if (result.msg == "force_logout") {
                    reject(new Error(result.msg));
                  }
                  else if (result.msg == "unable_admin_verify") {
                    reject(new Error(result.msg));
                  }
                  else if (result.msg == "sess_expired") {
                    reject(new Error(result.msg));
                  }
                  else if (result.msg == "unable_sess_verify") {
                    reject(new Error(result.msg));
                  }
                  else if (result.msg == "no_cookie") {
                    reject(new Error(result.msg));
                  }
                  else {                
                    let err_msg = "Unable to get Telegram bot profile data. Error: " + result.msg;
                    console.log(err_msg);
                    reject(new Error(err_msg));
                  }
							  }
						  },
						  error: function(xhr, ajaxOptions, thrownError) {
						    let err_msg = "Unable to get Telegram bot profile data. Error " + xhr.status + ": " + thrownError
						    console.log(err_msg);
	              reject(new Error(err_msg));
	            }
					  });
				  });
				  
				  this_promise.then((enc_data) => {
						showProfileDataInForm(enc_data);
				  }).catch((error) => {
            if (error.message.match(/force_logout/g)) {
              logout();
            } 
            else if (error.message.match(/unable_admin_verify/g)) {
              alert("Unable to check whether you are system administrator, process is aborted.");
              goHome();
            } 
            else if (error.message.match(/sess_expired/g)) {
              alert("Session expired!");
              logout();
            } 
            else if (error.message.match(/unable_sess_verify/g)) {
              alert("Unable to verify your session status, please login again.");
              logout();
            } 
            else if (error.message.match(/no_cookie/g)) {
              window.location.href = "/";
            } 
            else {           
				      alert(error.message);
              goBack();
            }
				  });
			  }	    
		  }
      
	    async function showProfileDataInForm(enc_data) {
	      let bot_name, bot_username, http_api_token;
	    
	      try {
	        aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
	        
	        bot_name = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_bot_name, enc_data.bot_name);
	        bot_username = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_bot_username, enc_data.bot_username);
	        http_api_token = await aesDecryptBase64(enc_data.algorithm, aes_key, enc_data.iv_http_api_token, enc_data.http_api_token);
	        
          // Clear session AES key from RAM after used //
          aes_key = null;
          	        
          $('#bot_name').val(bot_name);
			    $('#bot_username').val(bot_username);
			    $('#http_api_token').val(http_api_token);
			  }
			  catch(e) {
			    console.log(e);
			    alert("Error is found, operation is aborted. Error: " + e.message);
          goBack();
			  }	    
		  }
      	    	        
      async function saveTgBotProfile() {
        if (dataSetOk()) {
	        var bot_name = allTrim(document.getElementById("bot_name").value);
	        var bot_username = allTrim(document.getElementById("bot_username").value);
	        var http_api_token = allTrim(document.getElementById("http_api_token").value);

          var key_ready = true;
          aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");
          if (typeof(aes_key) != "string") {
            key_ready = false;
				  }
				  else {
				    aes_key = aes_key.trim();
				    if (aes_key.length < ${_key_len}) {
				      key_ready = false;
					  }
				  }
                    
          if (key_ready) {          
            //-- Encrypt data before send to server --//         
            var algorithm, enc_obj, iv_bot_name, e_bot_name, iv_bot_username, e_bot_username, iv_http_api_token, e_http_api_token;
            
            algorithm = "AES-GCM";
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, bot_name);
            iv_bot_name = enc_obj.iv; 
            e_bot_name = enc_obj.encrypted;

            enc_obj = await aesEncryptJSON(algorithm, aes_key, bot_username);
            iv_bot_username = enc_obj.iv; 
            e_bot_username = enc_obj.encrypted;
            
            enc_obj = await aesEncryptJSON(algorithm, aes_key, http_api_token);
            iv_http_api_token = enc_obj.iv; 
            e_http_api_token = enc_obj.encrypted;
            
            // Clear AES key from RAM after used //
            aes_key = null;
            
            // Generate new rolling key //            
            await prepareRollingKey(${_key_len});
                        
            //-- Fill encrypted data --//
            document.getElementById("algorithm").value = algorithm;
            document.getElementById("iv_bot_name").value = iv_bot_name;
            document.getElementById("e_bot_name").value = e_bot_name;
            document.getElementById("iv_bot_username").value = iv_bot_username;
            document.getElementById("e_bot_username").value = e_bot_username;
            document.getElementById("iv_http_api_token").value = iv_http_api_token;
            document.getElementById("e_http_api_token").value = e_http_api_token;
            //-- Clear data on the plain text fields --//
            document.getElementById("bot_name").value = "";
            document.getElementById("bot_username").value = "";
            document.getElementById("http_api_token").value = "";
        
	          document.getElementById("oper_mode").value = "S";
	          document.getElementById("frmTgBot").action = "/admin/save_telegram_bot";
	          document.getElementById("frmTgBot").submit();
				  }
				  else {
				    alert("Secure key is lost, operation cannot proceed, return to home page.");
				    goHome();
				  }
        }
      }
      
      function dataSetOk() {
        var bot_name = allTrim(document.getElementById("bot_name").value);
        var bot_username = allTrim(document.getElementById("bot_username").value);
        var http_api_token = allTrim(document.getElementById("http_api_token").value);
        
        if (bot_name == "" && bot_username == "" && http_api_token == "") {
          return true;
        }
        
        if (bot_name != "" && bot_username != "" && http_api_token != "") {
          return true;
        }
        
        if (bot_name == "") {
          alert("Telegram bot name is missing, please give it before saving.");
          document.getElementById("bot_name").focus();
          return false;        
        }
        else if (bot_username == "") {
          alert("Telegram bot username is missing, please give it before saving.");
          document.getElementById("bot_username").focus();
          return false;        
        }      
        else if (http_api_token == "") {
          alert("HTTP API token is missing, please give it before saving.");
          document.getElementById("http_api_token").focus();
          return false;
        }
        else {
          alert("System issue is found, process cannot proceed.");
          return false;  
        }      
      }
      
      async function goBack() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frmTgBot").action = "/system_setup";
          document.getElementById("frmTgBot").submit();          
        }
        catch(e) {
          alert(e.message);
        }
      }
      
      async function goHome() {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frmTgBot").action = "/message";
          document.getElementById("frmTgBot").submit();          
        }
        catch(e) {
          alert(e.message);
        }
      }    
      
      function logout() {
        window.location.href = "/logout_msg";
      } 
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
    
  return html;  
}


function _printTelegramBotProfileInputForm() {
  var html;
  
  try {
    html = `
    <form id="frmTgBot" name="frmTgBot" action="" method="post">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="algorithm" name="algorithm" value="">
    <input type=hidden id="iv_bot_name" name="iv_bot_name" value="">
    <input type=hidden id="e_bot_name" name="e_bot_name" value="">
    <input type=hidden id="iv_bot_username" name="iv_bot_username" value="">
    <input type=hidden id="e_bot_username" name="e_bot_username" value="">
    <input type=hidden id="iv_http_api_token" name="iv_http_api_token" value="">
    <input type=hidden id="e_http_api_token" name="e_http_api_token" value="">
    <input type=hidden id="roll_rec" name="roll_rec" value="">
    <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
    <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
        
    <div data-role="page">
      <div data-role="header" style="overflow:hidden;" data-position="fixed">  
        <a href="javascript:goBack();" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>		
        <h1>Telegram Bot</h1>
        <a href="javascript:goHome();" data-icon="home" class="ui-btn-right" data-ajax="false">Home</a>
      </div>
      
      <div data-role="main" class="ui-content">
        <label for="bot_name">Telegram bot name:</label>
        <input type="text" id="bot_name" name="bot_name" value="">
        <label for="bot_username">Bot username:</label>      
        <input type="text" id="bot_username" name="bot_username" value="">
        <label for="http_api_token">HTTP API Token:</label>      
        <input type="text" id="http_api_token" name="http_api_token" value="">      
        <br>
        <input type="button" id="save" name="save" value="Save" onClick="saveTgBotProfile();">
        <br>
        <b>Remark:</b>
        <br>
        If you don't know how to create a Telegram bot, please refer to this link: &nbsp;
        <br>
        <a href="https://core.telegram.org/bots">Bots: An introduction for developers</a>
      </div>
    </div>  
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.getTelegramBotProfileSMSLIB = async function(msg_pool, user_id, sess_code) {
  let conn, buffer, tg_bot_profile, algorithm, aes_key;
  
  try {
		conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
		
		aes_key = await msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
		
		buffer = await telecom.getTelegramBotProfile(conn);			
		let bot_name = buffer.bot_name;
		let bot_username = buffer.bot_username;
		let http_api_token = buffer.http_api_token;
		let iv_bot_name = "";
		let e_bot_name = "";
		let iv_bot_username = "";
		let e_bot_username = "";
		let iv_http_api_token = "";
		let e_http_api_token = "";
		let enc_obj;
		
		algorithm = "AES-GCM";
		
		enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, bot_name);
		iv_bot_name = enc_obj.iv;
		e_bot_name = enc_obj.encrypted;

		enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, bot_username);
		iv_bot_username = enc_obj.iv;
		e_bot_username = enc_obj.encrypted;
		
		enc_obj = await cipher.aesEncryptBase64(algorithm, aes_key, http_api_token);
		iv_http_api_token = enc_obj.iv;
		e_http_api_token = enc_obj.encrypted;
				
		tg_bot_profile = {algorithm: algorithm, iv_bot_name: iv_bot_name, bot_name: e_bot_name, iv_bot_username: iv_bot_username, bot_username: e_bot_username, iv_http_api_token: iv_http_api_token, http_api_token: e_http_api_token};		
	}
	catch(e) {
		throw e;
	}
	finally {
		dbs.releasePoolConn(conn);
	}
  
  return tg_bot_profile;	
}


exports.printTelegramBotProfileInputForm = async function(msg_pool, sess_code) {
  let conn, html;
  
  try {
    conn = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    html = wev.printHeader("Telegram Bot Profile");
    html += await _printTelegramBotProfileJS(conn, sess_code);
    html += _printTelegramBotProfileInputForm();
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;  
}


exports.decryptTelegramProfileData = async function(algorithm, aes_key, enc_data) {
	let bot_name, bot_username, http_api_token, result;
	
	try {
		bot_name = await cipher.aesDecryptJSON(algorithm, aes_key, enc_data.iv_bot_name, enc_data.e_bot_name);
		bot_username = await cipher.aesDecryptJSON(algorithm, aes_key, enc_data.iv_bot_username, enc_data.e_bot_username);
		http_api_token = await cipher.aesDecryptJSON(algorithm, aes_key, enc_data.iv_http_api_token, enc_data.e_http_api_token);
		
		result = {bot_name: bot_name, bot_username: bot_username, http_api_token: http_api_token};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


async function _getUserIdByName(conn_msg, user) {
  var sql, param, data, user_id;
  
  try {
    //-- No deactivated user will be considered. Prevent hackers use deactivated users to infiltrate the system. --//
    sql = `SELECT user_id ` +
          `  FROM user_list ` +
          `  WHERE user_name = ? ` +
          `    AND status <> 'D'`;
          
    param = [user];
    data = JSON.parse(await dbs.sqlQuery(conn_msg, sql, param));
    
    if (data.length > 0) {
      user_id = data[0].user_id;
    }
    else {
      user_id = 0;
    }      
  }
  catch(e) {
    throw e;
  }
  
  return user_id;
}


async function _isUserInValidSession(conn_pda, user_id, sess_code) {
  var sql, param, data, is_valid;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM web_session ` +
          `  WHERE user_id = ? ` +
          `    AND sess_code = ? ` +
          `    AND status = 'A'`;
          
    param = [user_id, sess_code];
    data = JSON.parse(await dbs.sqlQuery(conn_pda, sql, param));
    is_valid = (parseInt(data[0].cnt, 10) > 0)? true : false;           
  }
  catch(e) {
    throw e;
  }
  
  return is_valid;
}


exports.getUserIdByName = async function(msg_pool, pda_pool, user, sess_code) {
  var conn_msg, conn_pda, user_id;
  
  try {
    conn_msg = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    conn_pda = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    //-- Step 1: Get user ID from user list stored on database 'msgdb' --//
    user_id = await _getUserIdByName(conn_msg, user);
    
    if (user_id > 0) {
      //-- Step 2: Check whether the user is in valid login session on database 'pdadb' --// 
      user_id = (await _isUserInValidSession(conn_pda, user_id, sess_code))? user_id : 0;      
    }
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn_msg);
    dbs.releasePoolConn(conn_pda);
  }
  
  return user_id;
}


async function _getFeatures(conn) {
  var sql, data;
  var features = [];
  
  try {
    sql = `SELECT b.feature_url, b.feature_icon, a.list_order ` +
          `  FROM feature_list a, feature_store b ` +
          `  WHERE a.feature_id = b.feature_id ` +
          `  ORDER BY a.list_order`;
          
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    
    for (var i = 0; i < data.length; i++) {
      features.push({url: data[i].feature_url, icon: data[i].feature_icon});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return features;
}


function _printSelectToolsJS() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/crypto-lib.js"></script>
    <script src="/js/common_lib.js"></script>
    
    <script>
      async function runFeature(url) {
        try {
          await prepareRollingKey(${_key_len});
          document.getElementById("frmLeap").action = url;
          document.getElementById("frmLeap").submit();
        }
        catch(e) {
          alert(e.message);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _printSelectToolsForm(conn_msg, user_role, features) {
  var html, company_name, copy_right, spaces, panel, panel_btn, PDA_BG_COLOR;
  
  try {
    company_name = await wev.getDecoyCompanyName(conn_msg);
    copy_right = await wev.getDecoySiteCopyRight(conn_msg);
    PDA_BG_COLOR = wev.getGlobalValue('PDA_BG_COLOR');
    spaces = "&nbsp;".repeat(2);
         
    //-- If login user is system administrator, then he/she has right to maintain decoy site settings. --//
    if (user_role == 2) {
      panel = `
      <div data-role="panel" data-position-fixed="true" data-position="left" data-display="overlay" id="setup">
        <div data-role="main" class="ui-content">
          <ul data-role="listview">
            <li data-role="list-divider" style="color:darkgreen;">System Administration</li>
            <li><a href="javascript:runFeature('/admin/feature_setup');" data-ajax="false">Feature Setup</a></li>
          </ul>
        </div>
      </div>        
      `;
      
      panel_btn = `
      <a href="#setup" data-icon="bars" class="ui-btn-left">Setup</a>
      `;
    } 
    else {
      panel = '';
      panel_btn = '';
    }
    
    //-- Important: 'data-ajax="false"' must be set for links with dynamic content. Otherwise, unexpected result such as invalid javascript --//
    //--            content and expired passed parameters value will be obtained.                                                           --//    
    html = `
    <style>
      .image-style {
        display: inline-block;
      } 
            
      img:hover,
      .img-style:hover img {
        border: 1px solid #000;
        background-color: #000;
        cursor: url(), pointer;
      }      
    </style>
    
    
    <div data-role="page" id="mainpage" style="background-color:${PDA_BG_COLOR}">
      ${panel}
      
      <div data-role="header" style="overflow:hidden;" data-position="fixed">
        ${panel_btn}
        <h1>${company_name}</h1>
        <a href="/logout_pda" data-icon="power" class="ui-btn-right" data-ajax="false">Quit</a>					
      </div>	
  
      <div data-role="main" class="ui-body-d ui-content">
    `;
    
    for (var i = 0; i < features.length; i++) {
      var this_url = features[i].url;
      var this_icon = features[i].icon;
      
      //-- Note: style property must be declared explicitly to let it change image hovering icon --//
      html += `
        <img src="${this_icon}" height="100px" onClick="runFeature('${this_url}');" class="image-style">
        ${spaces}
      `;
    } 
    
    html += `
      <div data-role="footer" data-position="fixed">
        <table width="100%" cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr><td align=center><font size="2px">${copy_right}</font></td></tr>
        </tbody>
        </table>
      </div> 
    </div> 
    
    <form id='frmLeap' name='frmLeap' action='' method='POST'>
      <input type=hidden id="roll_rec" name="roll_rec" value="">
      <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
      <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">
    </form>               
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printSelectToolsForm = async function(pda_pool, msg_pool, user_id) {
  var conn_pda, conn_msg, user_role, html;
  var features = [];
  
  try {
    conn_pda = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    conn_msg = await dbs.getPoolConn(msg_pool, dbs.selectCookie('MSG'));
    
    user_role = await msglib.getUserRole(conn_msg, user_id);
    features = await _getFeatures(conn_pda);
    
    html = wev.printHeader("Select Tools");
    html += _printSelectToolsJS();
    html += await _printSelectToolsForm(conn_msg, user_role, features);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn_pda);
    dbs.releasePoolConn(conn_msg);
  }
  
  return html;
}


async function _getNotesList(conn, user_id, list_filter) {
  var sql, param, data, filter;
  var result = [];
  
  try {
    if (wev.allTrim(list_filter) != "") {
      var sqlcomm = [];
      var keywords = list_filter.split(" ");
      
      for (var i = 0; i < keywords.length; i++) {
        var this_keyword = wev.allTrim(keywords[i]);
        sqlcomm.push(`notes_title LIKE '%${this_keyword}%'`);        
      }
      
      filter = "AND (" + sqlcomm.join(' OR ') + ")";
    }
    else {
      filter = "";
    }
    
    sql = `SELECT notes_id, notes_title ` +
          `  FROM notes ` +
          `  WHERE user_id = ? ` +
          `    ${filter} ` +
          `  ORDER BY notes_title`;
          
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      result.push({notes_id: data[i].notes_id, notes_title: data[i].notes_title});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printNotesJS() {
  var html;
  
  try {
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/common_lib.js"></script>
    
    <script>
      function goSearch() {
        var filter = $('#list_filter').val();
        var url = window.location.href;
        var host = url.split('/');
        location.href = host[0] + '//' + host[2] + '/tools/notes?list_filter=' + filter;
      }
      
      function readNotes(notes_id, list_filter) {
        $('#op').val("R");
        $('#notes_id').val(notes_id);
        $('#lstfilter').val(list_filter);
        document.getElementById('frm_notes').action = "/tools/notes";
        document.getElementById('frm_notes').submit();
      }
      
      function editNotes(notes_id, list_filter) {
        $('#op').val("E");
        $('#notes_id').val(notes_id);
        $('#lstfilter').val(list_filter);
        document.getElementById('frm_notes').action = "/tools/notes";
        document.getElementById('frm_notes').submit();        
      }
      
      function deleteNotes(notes_id, list_filter) {
        if (confirm("Delete this notes?")) {
          $('#op').val("D");
          $('#notes_id').val(notes_id);
          $('#lstfilter').val(list_filter);
          document.getElementById('frm_notes').action = "/tools/notes";
          document.getElementById('frm_notes').submit();        
        }
      }
      
      function discard(list_filter) {
        var contents = allTrim($('#notes_content').val());
  
        if (contents != "") {
          if (confirm("Discard your new notes?")) {
            window.location.href = "/tools/notes?list_filter=" + list_filter; 
          }
        }
        else {
          window.location.href = "/tools/notes?list_filter=" + list_filter;
        }
      }
      
      function saveNotes() {
        if (dataSetValid()) {
          $('#oper_mode').val("S");
          document.getElementById('frm_notes').action = "/tools/notes";
          document.getElementById('frm_notes').submit();                  
        }
      }
      
      function dataSetValid() {
        var title = allTrim($('#notes_title').val());
        var contents = allTrim($('#notes_content').val());
      
        if (title == "") {
          alert("Please input notes title before saving");
          $('#notes_title').focus();
          return false;
        }
        
        if (title == "") {
          alert("Please input your notes before saving");
          $('#notes_content').focus();
          return false;
        }
        
        return true;
      }
      
      function addNewNotes(list_filter) {
        $('#op').val("A");
        $('#lstfilter').val(list_filter);
        document.getElementById('frm_notes').action = "/tools/notes";
        document.getElementById('frm_notes').submit();                          
      }
    </script>    
    `;  
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printNotesList(list_filter, notes_list) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_notes" name="frm_notes" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="oper_mode" name="oper_mode" value="">  
    <input type=hidden id="notes_id" name="notes_id" value="0">
    <input type=hidden id="lstfilter" name="lstfilter" value="">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="/select_tools" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>
        <h1>Notes</h1>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead></thead>
        <tbody>
          <tr>
            <td width=80%>
              <input type=text id="list_filter" name="list_filter" value="${list_filter}">
            </td>
            <td align=center valign=center>
              <input type=button data-icon="search" data-iconpos="notext" id="search" name="search" onClick="goSearch()">
            </td>
          </tr>
        </tbody>
        </table>
        
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed">
        <thead>
          <tr style="background-color:lightblue">
            <td width=75% align=center><b>Title</b></td>
            <td align=center><b>Delete</b></td>
          </tr>
        </thead>
        <tbody>    
    `;
    
    for (var i = 0; i < notes_list.length; i++) {
      var this_notes_id = notes_list[i].notes_id;
      var this_notes_title = notes_list[i].notes_title;
      
      html += `
          <tr style="background-color:lightyellow">
            <td style="word-wrap:break-word"><a href="javascript:readNotes(${this_notes_id}, '${list_filter}')">${this_notes_title}</a></td>
            <td align=center valign=center><input type=button id="kill_notes" name="kill_notes" data-icon="delete" data-iconpos="notext" onClick="deleteNotes(${this_notes_id}, '${list_filter}')">
          </tr>      
      `;      
    }
    
    if (notes_list.length == 0) {
      html += `
          <tr style="background-color:lightgray">
            <td colspan=2>No Record</td>
          </tr>      
      `;
    }
      
    html += `
          <tr style="background-color:lightblue">
            <td colspan=2 align=center>&nbsp;</td>
          </tr>        
        </tbody>
        </table>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center>
              <input type=button id="add_notes" name="add_notes" value="Add New Notes" data-icon="plus" onClick="addNewNotes('${list_filter}')">
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printNotesList = async function(pda_pool, user_id, list_filter) {
  var conn, html;
  var notes_list = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    notes_list = await _getNotesList(conn, user_id, list_filter);
    
    html = wev.printHeader("Notes");
    html += _printNotesJS();
    html += _printNotesList(list_filter, notes_list);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getNotesDetails(conn, user_id, notes_id) {
  var sql, param, data;
  var result = {};
  
  try {
    //-- Note: 'user_id' is used to verify the owner of the notes record, it is for security measure. --//
    sql = `SELECT notes_title, notes_content ` +
          `  FROM notes ` +
          `  WHERE notes_id = ? ` +
          `    AND user_id = ?`;
          
    param = [notes_id, user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
      result = {id: notes_id, title: data[0].notes_title, content: data[0].notes_content};
    }
    else {
      throw new Error("Notes record is not found.");
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printNotesDetails(op, notes_dtl, lstfilter) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    //-- Replace 'carriage return', 'tab' and 'space' characters with HTML equivalent codes globally --//
    notes_dtl.content = notes_dtl.content.replace(/\n/g, "<br>").replace(/\t/g, "&#9").replace(/ /g, "&nbsp;"); 
    
    html = `
    <form id="frm_notes" name="frm_notes" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="notes_id" name="notes_id" value="${notes_dtl.notes_id}">
    <input type=hidden id="lstfilter" name="lstfilter" value="${lstfilter}">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="/tools/notes?list_filter=${lstfilter}" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Read Notes</h1>
      </div>
      
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellspacing=1>
        <thead></thead>
        <tbody>
          <tr>
            <td width=50% align=center>
              <input type=button id="edit" name="edit" data-icon="gear" value="Edit" onClick="editNotes(${notes_dtl.id}, '${lstfilter}')">          
            </td>
            <td width=50% align=center>
              <input type=button id="edit" name="edit" data-icon="delete" value="Delete" onClick="deleteNotes(${notes_dtl.id}, '${lstfilter}')">
            </td>
          </tr>
        </tbody>
        </table>
        <br>
        
        <table width=100% cellspacing=1 cellspacing=1 style="table-layout:fixed;">
        <thead></thead>
        <tbody>
          <tr style="background-color: lightblue">
            <td style="word-wrap:break-word;"><b>${notes_dtl.title}</b></td> 
          </tr>
          <tr style="background-color: lightyellow">
            <td style="word-wrap:break-word;">${notes_dtl.content}</td> 
          </tr>
          <tr style="background-color: lightblue">
            <td>&nbsp;</td> 
          </tr>        
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printEditNotesForm(op, notes_dtl, lstfilter) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_notes" name="frm_notes" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="notes_id" name="notes_id" value="${notes_dtl.id}">
    <input type=hidden id="lstfilter" name="lstfilter" value="${lstfilter}">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="" onClick="readNotes(${notes_dtl.id}, '${lstfilter}')" data-icon="back" class="ui-btn-left">Back</a>
        <h1>Edit Notes</h1>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <label for="notes_title"><b>Title:</b></label>
        <input type=text id="notes_title" name="notes_title" value="${notes_dtl.title}" maxlength=256>
        <br>
        <label for="notes_content"><b>Notes:</b></label>
        <textarea id="notes_content" name="notes_content">${notes_dtl.content}</textarea>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center>
              <input type=button id="save" name="save" value="Save Notes" data-icon="plus" onClick="saveNotes()">
            </td>
          </tr>
        </tbody>
        </table>
      </div>    
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _modifyNotes(conn, user_id, notes_id, notes_title, notes_content) {
  var sql, param;
  
  try {
    //-- Note: 'user_id' is used to safe guard the update record, so that it can't be amended by --//
    //--       other users except the record owner.                                              --//
    sql = `UPDATE notes ` +
          `  SET notes_title = ?, ` +
          `      notes_content = ?, ` +
          `      update_date = CURRENT_TIMESTAMP() ` +
          `  WHERE notes_id = ? ` +
          `    AND user_id = ?`;
          
    param = [notes_title, notes_content, notes_id, user_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e;
  }  
}


async function _deleteNotes(conn, user_id, notes_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM notes ` +
          `  WHERE notes_id = ? ` +
          `    AND user_id = ?`;
    
    param = [notes_id, user_id];
    await dbs.sqlExec(conn, sql, param);
  }
  catch(e) {
    throw e;
  }
}


function _printNewNotesForm(op, user_id, lstfilter) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_notes" name="frm_notes" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="lstfilter" name="lstfilter" value="${lstfilter}">
      
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:discard('${lstfilter}')" data-icon="back" data-ajax="false">Discard</a>
        <h1>Add Notes</h1>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <label for="notes_title"><b>Title:</b></label>
        <input type=text id="notes_title" name="notes_title" value="" maxlength=256>
        <br>
        <label for="notes_content"><b>Notes:</b></label>
        <textarea id="notes_content" name="notes_content"></textarea>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center>
              <input type=button id="save" name="save" value="Save Notes" data-icon="plus" onClick="saveNotes()">
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html; 
}


async function _addNewNotes(conn, user_id, notes_title, notes_content) {
  var sql, param, data, notes_id;
  
  try {
    sql = `INSERT INTO notes ` +
          `(user_id, notes_title, notes_content, create_date) ` +
          `VALUES ` +
          `(?, ?, ?, CURRENT_TIMESTAMP())`;
          
    param = [user_id, notes_title, notes_content];
    await dbs.sqlExec(conn, sql, param);       
    
    //-- Get the notes_id for the newly added notes record --//
    sql = `SELECT LAST_INSERT_ID() AS notes_id`;
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    notes_id = data[0].notes_id;
  }
  catch(e) {
    throw e;
  }
  
  return notes_id;
}


exports.notesOperation = async function(pda_pool, op, oper_mode, user_id, notes_id, notes_title, notes_content, lstfilter) {
  var conn, html;
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    if (op == 'A') {
      if (oper_mode == 'S') {
        var notes_id = await _addNewNotes(conn, user_id, notes_title, notes_content);
        
        var notes_dtl = await _getNotesDetails(conn, user_id, notes_id);        
        html = wev.printHeader("Notes");
        html += _printNotesJS();
        html += _printNotesDetails('R', notes_dtl, lstfilter);                  
      }
      else {
        html = wev.printHeader("Notes");
        html += _printNotesJS();
        html += _printNewNotesForm(op, user_id, lstfilter);
      }
    }
    else if (op == 'E') {
      if (oper_mode == 'S') {
        await _modifyNotes(conn, user_id, notes_id, notes_title, notes_content);
                 
        var notes_dtl = await _getNotesDetails(conn, user_id, notes_id);        
        html = wev.printHeader("Notes");
        html += _printNotesJS();
        html += _printNotesDetails('R', notes_dtl, lstfilter);        
      }
      else {
        var notes_dtl = await _getNotesDetails(conn, user_id, notes_id);
        
        html = wev.printHeader("Notes");
        html += _printNotesJS();
        html += _printEditNotesForm(op, notes_dtl, lstfilter);         
      }
    }
    else if (op == 'D') {
      await _deleteNotes(conn, user_id, notes_id);      
      
      var notes_list = await _getNotesList(conn, user_id, lstfilter);      
      html = wev.printHeader("Notes");
      html += _printNotesJS();
      html += _printNotesList(lstfilter, notes_list);          
    }
    else if (op == 'R') {
      var notes_dtl = await _getNotesDetails(conn, user_id, notes_id);
      
      html = wev.printHeader("Notes");
      html += _printNotesJS();
      html += _printNotesDetails(op, notes_dtl, lstfilter);
    }    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _getCurrentYearAndMonth(conn) {
  var sql, data;
  var result = {year: 0, month: 0};
  
  try {
    sql = `SELECT YEAR(CURRENT_TIMESTAMP()) AS year, MONTH(CURRENT_TIMESTAMP()) AS month`;
    data = JSON.parse(await dbs.sqlQuery(conn, sql));    
    result = {year: data[0].year, month: data[0].month};
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printSchedulerJS(op, oper_mode, reminder_list) {
  var html, is_reminder_exist, go_first_active_event;
  
  try {
    op = (typeof(op) != "string")? "" : op;
    oper_mode = (typeof(oper_mode) != "string")? "" : oper_mode;
    reminder_list = (Array.isArray(reminder_list))? reminder_list : [];
    
    is_reminder_exist = (op == 'E' && reminder_list.length > 0)? 1 : 0;
    
    if (op == 'L') {
      go_first_active_event = `
      $(document).on("pageinit", function() {
        $(function() {
          $('html,body').animate({scrollTop: $('#first_active_event').offset().top}, 400);
        })
      });          
      `;
    }
    
    html = `
    <link rel="stylesheet" href="/js/jquery.mobile-1.4.5.min.css">
    <link rel="stylesheet" href="/js/jquery-ui-min.css">
    <link rel="stylesheet" type="text/css" href="/js/DateTimePicker.min.css"/>  
    <link rel="shortcut icon" href="/favicon.ico">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/jquery.mobile-1.4.5.min.js"></script>
    <script src="/js/DateTimePicker.min.js"></script>
    <!--[if lt IE 9]>
    <link rel="stylesheet" type="text/css" href="/js/DateTimePicker-ltie9.min.css"/>
    <script type="text/javascript" src="/js/DateTimePicker-ltie9.min.js"></script>
    <![endif]-->
    <script src="/js/common_lib.js"></script>
    
    <script>
      var current_op = "${op}";
      var is_reminder_exist = ${is_reminder_exist};
  
      ${go_first_active_event}
    
      $(document).on("pagebeforeshow", function() {
        $('#dt_box').DateTimePicker({
          mode: "datetime",
          dateTimeFormat: "yyyy-MM-dd HH:mm"
        });
      });
      
      if (current_op == "A" || current_op == "E") {
        if (current_op == "A" || (current_op == "E" && is_reminder_exist == 1)) {    
          $(document).on("pagebeforeshow", function() {
            addReminder('rd_row_1');
          });
        }
        else {
          $(document).on("pagebeforeshow", function() {
            removeReminder('rd_row_1');
          });      
        }
      }
      
      $(function() {
        $('#sch').on("swiperight", swiperightHandler);
        
        function swiperightHandler(event) {
          goPrevMonth();
        }
      });
      
      $(function() {
        $('#sch').on("swipeleft", swipeleftHandler);
        
        function swipeleftHandler(event) {
          goNextMonth();
        }
      });
                    
      function goPrevMonth() {
        var this_year = parseInt($('#what_year').val(), 10);
        var this_month = parseInt($('#what_month').val(), 10);
        
        this_month = this_month - 1;
        if (this_month <= 0) {
          this_year = this_year - 1;
          this_month = 12;
        }
        
        $('#what_year').val(this_year);
        $('#what_month').val(this_month);
        //$('#frm_sch').submit();      
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();
      }
      
      function goNextMonth() {
        var this_year = parseInt($('#what_year').val(), 10);
        var this_month = parseInt($('#what_month').val(), 10);
        
        this_month = this_month + 1;
        if (this_month > 12) {
          this_year = this_year + 1;
          this_month = 1;
        }
    
        $('#what_year').val(this_year);
        $('#what_month').val(this_month);
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                  
      }
      
      function addEvent(date) {
        date = allTrim(date);
      
        //-- if 'date' is blank, assume it is today --//
        if (date == "" || typeof(date) == "undefined") {
          date = stripSecondAway(sayCurrentDateTime(), "DT");         // All functions are defined on common_lib.js
        }
        else {
          if (!date.match(/:/)) {
            var time = stripSecondAway(sayCurrentTime(), "T");        // All functions are defined on common_lib.js 
            date = date + " " + time;
          }
        }
              
        $('#op').val('A');
        $('#event_start').val(date);
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                          
      }
      
      function readEvent(event_id) {
        $('#op').val('R');
        $('#event_id').val(event_id);
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                  
      }    
      
      function returnCurrentMonth() {
        //$('#op').val('');
        //$('#what_year').val(0);
        //$('#what_month').val(0);
        //$('#frm_sch').submit();
        window.location.href = "/tools/scheduler?what_year=0&what_month=0";            
      }
      
      function goBack(year, month, op, event_id) {
        window.location.href = "/tools/scheduler?what_year=" + year + "&what_month=" + month + "&op=" + op + "&event_id=" + event_id;
      }
      
      function removeReminder(rd_row) {
        $('#reminder_header').hide();
        $('#' + rd_row).hide();
        $('#add_reminder_btn').show();
        $('#has_reminder').val(0);
      }
      
      function addReminder(rd_row) {
        $('#reminder_header').show();
        $('#' + rd_row).show();
        $('#add_reminder_btn').hide();
        $('#has_reminder').val(1);
      }
      
      function saveEvent() {
        if (dataSetValid() == true) {
          $('#oper_mode').val('S');
          //$('#frm_sch').submit();
          document.getElementById('frm_sch').action = "/tools/scheduler";
          document.getElementById('frm_sch').submit();                                            
        }
      }
      
      function dataSetValid() {
        var this_event_title = allTrim($('#event_title').val());
        var this_event_start = allTrim($('#event_start').val());
        var this_event_end = allTrim($('#event_end').val());
        var has_reminder = parseInt($('#has_reminder'), 10);
        var this_rd_value_1 = parseInt($('#rd_value_1'), 10);
        
        if (this_event_title == "") {
          alert("Please input event title before saving");
          $('#event_title').focus();
          return false;
        }
        
        if (this_event_start == "") {
          alert("Please input event starting date and time before saving");
          $('#event_start').focus();
          return false;        
        }
  
        if (this_event_end == "") {
          alert("Please input event ending date and time before saving");
          $('#event_end').focus();
          return false;        
        }
        
        if (has_reminder >= 1 && this_rd_value_1 <= 0) {
          alert("Reminder value must be a positive integer");
          $('#rd_value_1').focus();
          return false;
        }
        
        return true;
      }
      
      function editEvent() {
        $('#op').val('E');
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                    
      }
      
      function deleteEvent() {
        if (confirm("Delete this event?")) {
          $('#op').val('D');
          $('#oper_mode').val('S');
          //$('#frm_sch').submit();
          document.getElementById('frm_sch').action = "/tools/scheduler";
          document.getElementById('frm_sch').submit();                                                      
        }
      }
      
      function schedule() {
        $('#op').val('L');
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                                
      }
      
      function search() {
        $('#op').val('S');
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                          
      }
      
      function goSearch() {
        var s_txt = allTrim($('#search_phase').val());
        
        if (s_txt != "") {
          //$('#frm_sch').submit();
          document.getElementById('frm_sch').action = "/tools/scheduler";
          document.getElementById('frm_sch').submit();                                                      
        }
      }
      
      function searchAgain(s_str) {
        $('#search_phase').val(s_str);
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                    
      }
      
      function goBackSearchResult() {
        $('#op').val('S');
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                    
      }
      
      function goBackEventList() {
        $('#op').val('L');
        //$('#frm_sch').submit();
        document.getElementById('frm_sch').action = "/tools/scheduler";
        document.getElementById('frm_sch').submit();                                                          
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


function _printSchedulerStyleSection() {
  var html;
  
  try {
    html = `
    <style>
      .ui-panel.ui-panel-open {
        position:fixed;
      }
      
      .ui-panel-inner {
        position: absolute;
        top: 1px;
        left: 0;
        right: 0;
        bottom: 0px;
        overflow: scroll;
        -webkit-overflow-scrolling: touch;
      }    
    </style>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _getDateInfo(conn, first_date) {
  var sql, param, data;
  var result = {last_date: '', offset: 0, month: ''};
  
  try {
    //-- Note: Day of the week index for the date (1 = Sunday, 2 = Monday, ..., 7 = Saturday). i.e. offset --//
    sql = `SELECT LAST_DAY(?) AS last_date, DAYOFWEEK(?) AS dow, MONTHNAME(?) AS month`;
    param = [first_date, first_date, first_date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = {last_date: data[0].last_date, offset: data[0].dow, month: data[0].month};
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


async function _getDay(conn, date) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT DAYOFMONTH(?) AS day`;
    param = [date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = parseInt(data[0].day, 10);
  }
  catch(e) {
    //-- last resort: Assume date format is yyyy-mm-dd --//
    var date_parts = date.split('-');
    result = Number(date_parts[2]);
    
    if (isNaN(result) || result < 1 || result > 31) {
      throw new Error(`Unable to get day from ${date}`);
    } 
  }
  
  return result;
}


async function _isToday(conn, date) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT DATEDIFF(?, CURRENT_DATE()) AS date_diff`;
    param = [date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = (data[0].date_diff == 0)? true : false; 
  }
  catch(e) {
    //-- Assume it is not today --//
    result = false;
  }
  
  return result;
}


async function _getEventsInThisDate(conn, user_id, date) {
  var sql, param, data;
  var result = [];
  
  try {
    sql = `SELECT event_id, event_title ` + 
          `  FROM schedule_event ` +
          `  WHERE user_id = ? ` +
          `    AND ? BETWEEN DATE(ev_start) AND DATE(ev_end) ` +
          `  ORDER BY ev_start`;
          
    param = [user_id, date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      result.push({event_id: data[i].event_id, event_title: data[i].event_title});
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result; 
}


async function _gotoNextDate(conn, date) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT DATE_FORMAT(ADDDATE(?, 1), '%Y-%m-%d') AS next_date`;
    param = [date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = data[0].next_date;
  }
  catch(e) {
    throw e;
  }
  
  return result; 
}


async function _lastDateHasPassed(conn, date, last_date) {
  var sql, param, data, result;
  
  try {
    sql = `SELECT DATEDIFF(?, ?) AS date_diff`;
    param = [date, last_date];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    result = (data[0].date_diff > 0)? true : false;
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _printCalendar(conn, user_id, what_year, what_month) {
  var html, panel, month, first_date, last_date, date_pt, weekday_pt, offset, stop_run, start, end, pda_bg_color;
  var date_info = {last_date: '', offset: 0, month: ''};
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    first_date = what_year + '-' + wev.padLeft(what_month, 2, '0') + '-01';
    date_info = await _getDateInfo(conn, first_date);
    last_date = date_info.last_date;
    offset = date_info.offset;
    month = date_info.month;
    
    panel = `
    <div data-role="panel" data-position-fixed="true" data-position="right" data-display="overlay" id="sch_func">
      <div data-role="main" class="ui-content">
        <ul data-role="listview">
          <li><a href="javascript:schedule()" data-ajax="false">Event List</a></li>
          <li><a href="javascript:search()" data-ajax="false">Search</a></li>
        </ul>
      </div>
    </div>    
    `;

    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="event_id" name="event_id" value="">
    <input type=hidden id="event_start" name="event_start" value="">
    
    <div id="sch" data-role="page" style="background-color:${pda_bg_color}">
      ${panel}
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="/select_tools" data-icon="home" class="ui-btn-left" data-ajax="false">Home</a>        
        <h1>Schedular</h1>
        <a href="#sch_func" data-icon="bars" class="ui-btn-right" data-ajax="false">Menu</a>
      </div>
    
      <div data-role="main" class="ui-body-d ui-content">
        <table width=100% cellspacing=1 cellpadding=1 style="table-layout:fixed;">
        <thead>
          <tr style="background-color:lightblue">
            <td colspan=7 align=center nowrap>
              <table width=100% cellspacing=0 cellpadding=0 style="table-layout:fixed;">
              <thead>
                <tr>
                  <td width=25% align=center>
                    <input type=button onClick="javascript:goPrevMonth();" data-icon="arrow-l" data-iconpos="notext" data-ajax="false">
                  </td>  
                  <td width=50% align=center><b>${month} ${what_year}</b></td>
                  <td width=25% align=center>
                    <input type=button onClick="javascript:goNextMonth();" data-icon="arrow-r" data-iconpos="notext" data-ajax="false">
                  </td>
                </tr>
              </thead>
              </table>
            </td>  
          </tr>
          <tr style="background-color:lightblue">
            <td width=14% align=center valign=center>S</td>        
            <td width=14% align=center valign=center>M</td>
            <td width=14% align=center valign=center>T</td>
            <td width=14% align=center valign=center>W</td>
            <td width=14% align=center valign=center>T</td>
            <td width=14% align=center valign=center>F</td>
            <td width=14% align=center valign=center>S</td>
          </tr>                
        </thead>
        
        <tbody>    
    `;
    
    date_pt = first_date;
    start = (offset == 1)? true : false;     // Specially handle the case which the first day of the month is Sunday.
    end = false;
    stop_run = false;
    
    while (!stop_run) {
      html += `
        <tr>
      `;  
      
      for (weekday_pt = 1; weekday_pt <= 7; weekday_pt++) {
        if (start && !end) {
          var this_day = await _getDay(conn, date_pt);
          var cell_color = (await _isToday(conn, date_pt))? 'background-color:#F4F7CE;' : 'background-color:#D0F8FF';
          var events = await _getEventsInThisDate(conn, user_id, date_pt);      // Note: 'events' is an array.
          var all_events = (events.length > 0)? "<table width=100% cellspacing=0 cellpadding=0 style='table-layout:fixed;'><thead></thead><tbody>" : '';
          var idx = 1;
          var link_color = 'black';            
          
          for (var i = 0; i < events.length; i++) {
            var this_event_id = events[i].event_id;
            var this_event_title = (unicodeStrLen.get(events[i].event_title) > 5)? unicodeSubstring(events[i].event_title, 0, 5) + '...' : events[i].event_title;
            link_color = (idx > 1)? '#003ADE' : 'black';              // blue : black
            var link = `<a href='javascript:readEvent(${this_event_id})' style='font-size: 9px; color:${link_color}'>${this_event_title}</a>`;
          
            all_events += `
            <tr>
              <td valign=top>${link}</td>            
            </tr>
            <tr>
              <td height='4px'></td>
            </tr>            
            `;
          
            idx++;
            if (idx > 2) {
              idx = 1;
            }          
          }
                      
          all_events += (events.length > 0)? "</tbody></table>" : '';
          
          html += `
          <td valign=top style="word-wrap:break-word; ${cell_color}">
            <a href="javascript:addEvent('${date_pt}')"><b>${this_day}</b></a>
            <br>
            ${all_events}
            <br>
          </td>          
          `;
          
          date_pt = await _gotoNextDate(conn, date_pt);        
          if (await _lastDateHasPassed(conn, date_pt, last_date)) {
            end = true;
            stop_run = true;
          }          
        }
        else {
          if (!start) {
            //-- A day before the first date of the month --//
            var pt = offset - 1;
            if (pt < 1) {
              pt = 7;
            }
          
            if (weekday_pt == pt) {
              start = 1;
            }
  
            html += `
            <td>&nbsp;</td>  
            `;
          }
          
          if (end) {
            html += `
            <td>&nbsp;</td>  
            `;
          }            
        }
      }
      
      html += `
      </tr>
      `;    
    }
    
    html += `
        </tbody>
        </table>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=0 cellpadding=0 style="table-layout:fixed;">
        <thead>
          <tr>
            <td width=50% align=center>
              <input type=button onClick="addEvent()" data-icon="plus" data-ajax="false" value="Add Event">
            </td>
            <td width=50% align=center>
              <input type=button onClick="returnCurrentMonth()" data-icon="refresh" data-ajax="false" value="Today">
            </td>          
          </tr>
        </thead>
        </table>
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printCalendar = async function(pda_pool, user_id, what_year, what_month, op, event_id, call_by) {
  var conn, html, has_reminder;
  var oper_mode = "";
  var event_dtl = {};
  var reminder_list = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    what_year = (isNaN(what_year))? 0 : parseInt(what_year, 10);
    what_month = (isNaN(what_month))? 0 : parseInt(what_month, 10);
    
    //-- Note: This calendar system cannot handle date before 01 January 1752 --//       
    if (what_year <= 0 || what_year < 1752 || what_month < 1 || what_month > 12) {
      var today = await _getCurrentYearAndMonth(conn);
      what_year = today.year;
      what_month = today.month;
    }
        
    html = wev.printHeader("scheduler");
    if (op == "R" && event_id > 0) {
      event_dtl = await _getEventDetail(conn, event_id);
      reminder_list = await _getReminderListForEvent(conn, event_id);
      has_reminder = (reminder_list.length > 0)? 1 : 0; 
  
      html += _printSchedulerJS(op, oper_mode, reminder_list);
      html += _printReadEventForm(op, "", what_year, what_month, call_by, "", event_id, has_reminder, event_dtl, reminder_list);    
    }      
    else {  
      html += _printSchedulerJS(op, oper_mode, reminder_list);
      html += _printSchedulerStyleSection();
      html += await _printCalendar(conn, user_id, what_year, what_month);  
    }  
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


function _printAddEventForm(op, what_year, what_month, event_title, event_start, event_end) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="has_reminder" name="has_reminder" value="1">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack(${what_year}, ${what_month})" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Add Event</h1>
      </div>
    
      <div data-role="main" class="ui-content">
        <label for="event_title"><b>Title:</b></label>
        <input type=text id="event_title" name="event_title" value="${event_title}" maxlength=256>
        <hr>
        
        <label for="event_start" style="display:inline"><b>Starts:</b></label>
        <input type=text id="event_start" name="event_start" value="${event_start}" data-field="datetime" data-startend="start" data-startendelem=".event_end" readonly>
        <label for="event_end" style="display:inline"><b>Ends:</b></label>
        <input type=text id="event_end" name="event_end" value="${event_end}" data-field="datetime" data-startend="end" data-startendelem=".event_start" readonly>
        <hr>
        
        <label for="event_detail"><b>Details:</b></label>
        <textarea id="event_detail" name="event_detail"></textarea>
        <hr>
        
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr id="reminder_header">
            <td colspan=3><b>Reminder:</b></td>
          </tr>
        
          <tr id="rd_row_1">
            <td width="20%">
              <input type=number id="rd_value_1" name="rd_value_1" value="30" min="0">
            </td>
            <td>
              <select id="rd_unit_1" name="rd_unit_1">
                <option value="minute">Minutes before</option>
                <option value="hour">Hours before</option>
                <option value="day">Days before</option>
              </select>
            </td>
            <td width="15%" align=center>
              <input type=button id="rd_remove_1" name="rd_remove_1" data-icon="delete" data-iconpos="notext" onClick="removeReminder('rd_row_1')">
            </td>
          </tr>
          
          <tr id="add_reminder_btn">
            <td colspan=3>
              <a href="javascript:addReminder('rd_row_1')">Add Reminder</a>
            </td>
          </tr>
        </tbody>
        </table>
        <hr>
        
        <div id="dt_box"></div>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead></thead>
        <tbody>
          <tr>
            <td width=50% align=center valign=center>
              <input type=button id="save" name="save" data-icon="plus" value="Save Event" onClick="saveEvent()">
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printAddEventForm = async function(pda_pool, user_id, op, oper_mode, what_year, what_month, event_start, event_end, event_title, event_detail) {
  var conn, html;
  var reminder_list = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    if (wev.allTrim(event_start) == "") {
      event_start = await wev.getCurrentDateTime(conn, {no_sec: true});
    }
    else {
      if (!event_start.match(/:/)) {
        event_start = event_start + " " + (await wev.getCurrentTime(conn, {no_sec: true}));
      }
    }
    
    if (wev.allTrim(event_end) == "") {
      event_end = await wev.setHoursLater(conn, event_start, 1);           // Assume event duration is one hour.           
    }
    
    //-- Note: Database schema for an event can hold multiple reminders, but here I only implement one reminder for an event. --//
    html = wev.printHeader("Add Scheduler Event");
    html += _printSchedulerJS(op, oper_mode, reminder_list);
    html += _printAddEventForm(op, what_year, what_month, event_title, event_start, event_end);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _addEvent(conn, user_id, event_title, event_detail, event_start, event_end) {
  var sql, param, data;
  var event_id = 0;
  
  try {
    sql = `INSERT INTO schedule_event ` +
          `(user_id, event_title, event_detail, ev_start, ev_end) ` +
          `VALUES ` +
          `(?, ?, ?, ?, ?)`;
          
    param = [user_id, event_title, event_detail, event_start, event_end];
    await dbs.sqlExec(conn, sql, param);      
    
    sql = `SELECT LAST_INSERT_ID() AS event_id`;
    data = JSON.parse(await dbs.sqlQuery(conn, sql));
    event_id = data[0].event_id;
  }
  catch(e) {
    throw e;
  }
  
  return event_id;  
}


async function _addReminder(conn, event_id, reminder) {
  var sql, param;
  
  try {
    for (var i = 0; i < reminder.length; i++) {
      var this_rd_value = parseInt(reminder[i].rd_value, 10);
      var this_rd_unit = reminder[i].rd_unit;
      
      sql = `INSERT INTO schedule_reminder ` +
            `(event_id, remind_before, remind_unit, has_informed) ` +
            `VALUES ` +
            `(?, ?, ?, 0)`;
            
      param = [event_id, this_rd_value, this_rd_unit];
      await dbs.sqlExec(conn, sql, param);      
    }
  }
  catch(e) {
    throw e;    
  }
}


exports.addNewEvent = async function(pda_pool, user_id, event_title, event_detail, event_start, event_end, reminder) {
  var conn, event_id;
  var sql_tx_on = false;
  var retval = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      event_id = await _addEvent(conn, user_id, event_title, event_detail, event_start, event_end);
      
      if (event_id > 0 && reminder.length > 0) {
        await _addReminder(conn, event_id, reminder);
      }
      
      if (event_id > 0) {
        await dbs.commitTransaction(conn);
      }
      else {
        retval = {ok: false, msg: 'Unable to retrieve newly added event ID by unknown reason'};        
        await dbs.rollbackTransaction(conn);
      }
    }
    else {
      retval = {ok: false, msg: 'Unable to start SQL transaction session'};
    }
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e; 
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _getEventDetail(conn, event_id) {
  var sql, param, data;
  var result = {};
  
  try {
    sql = `SELECT event_title, event_detail, DATE_FORMAT(ev_start, '%Y-%m-%d %H:%i') AS ev_start, DATE_FORMAT(ev_end, '%Y-%m-%d %H:%i') AS ev_end ` +
          `  FROM schedule_event ` +
          `  WHERE event_id = ?`;
          
    param = [event_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));      
    
    if (data.length > 0) {    
      result = {event_title: data[0].event_title, event_detail: data[0].event_detail, ev_start: data[0].ev_start, ev_end: data[0].ev_end};
    }
    else {
      throw new Error("No such event record.");
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _getReminderListForEvent(conn, event_id) {
  var sql, param, data;
  var result = [];
  
  try {
    sql = `SELECT reminder_id, remind_before, remind_unit ` +
          `  FROM schedule_reminder ` +
          `  WHERE event_id = ?`;
    
    param = [event_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));

    for (var i = 0; i < data.length; i++) {
      result.push({reminder_id: data[i].reminder_id, remind_before: data[i].remind_before, remind_unit: data[i].remind_unit});
    }    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printEditEventForm(op, oper_mode, what_year, what_month, event_id, has_reminder, event_dtl, reminder_list, call_by) {
  var html, pda_bg_color, idx, back_link;
  var interval = [];
  
  try {
    if (call_by == "event_search") {
      back_link = `javascript:goBackSearchResult()`;
    }
    else if (call_by == "event_list") {
      back_link = `javascript:goBackEventList()`;
    }
    else {
      back_link = `javascript:goBack(${what_year}, ${what_month}, 'R', ${event_id})`;
    }
    
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="event_id" name="event_id" value="${event_id}">
    <input type=hidden id="has_reminder" name="has_reminder" value="${has_reminder}">
    <input type=hidden id="call_by" name="call_by" value="${call_by}">  
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="${back_link}" data-icon="back" style="ui-btn-left" data-ajax="false">Back</a>
        <h1>Edit Event</h1>
      </div>
    
      <div data-role="main" class="ui-content">
        <label for="event_title"><b>Title:</b></label>
        <input type=text id="event_title" name="event_title" value="${event_dtl.event_title}" maxlength=256>
        <hr>
        
        <label for="event_start" style="display:inline"><b>Starts:</b></label>
        <input type=text id="event_start" name="event_start" value="${event_dtl.ev_start}" data-field="datetime" data-startend="start" data-startendelem=".event_end" readonly>
        <label for="event_end" style="display:inline"><b>Ends:</b></label>
        <input type=text id="event_end" name="event_end" value="${event_dtl.ev_end}" data-field="datetime" data-startend="end" data-startendelem=".event_start" readonly>
        <hr>
        
        <label for="event_detail"><b>Details:</b></label>
        <textarea id="event_detail" name="event_detail">${event_dtl.event_detail}</textarea>
        <hr>
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr id="reminder_header">
            <td colspan=3><b>Reminder:</b></td>
          </tr>    
    `;

    interval.push({opt_value: 'minute', opt_desc: 'Minutes before'});
    interval.push({opt_value: 'hour', opt_desc: 'Hours before'});
    interval.push({opt_value: 'day', opt_desc: 'Days before'});    
    //-- Note: Although currently users can just put one reminder to an event, it may be enhanced later to let users add multiple reminders. --//
    idx = 1;
    for (var i = 0; i < reminder_list.length; i++) {
      var this_rd_id = reminder_list[i].reminder_id;
      var this_rd_value = parseInt(reminder_list[i].remind_before, 10);
      var this_rd_unit = reminder_list[i].remind_unit;
      
      var this_options = '';
      for (var k = 0; k < interval.length; k++) {
        var this_opt_value = interval[k].opt_value;
        var this_opt_desc = interval[k].opt_desc;        
        var selected = (this_opt_value == this_rd_unit)? "selected" : "";
        this_options += `<option value='${this_opt_value}' ${selected}>${this_opt_desc}</option>`; 
      }

      html += `
          <tr id="rd_row_${idx}">
            <td width="20%">
              <input type=hidden id="rd_id_${idx}" name="rd_id_${idx}" value="${this_rd_id}">
              <input type=number id="rd_value_${idx}" name="rd_value_${idx}" value="${this_rd_value}" min="0">
            </td>
            <td>
              <select id="rd_unit_${idx}" name="rd_unit_${idx}">
                ${this_options}
              </select>
            </td>
            <td width="15%" align=center>
              <input type=button id="rd_remove_${idx}" name="rd_remove_${idx}" data-icon="delete" data-iconpos="notext" onClick="removeReminder('rd_row_${idx}')">
            </td>
          </tr>      
      `;
      
      idx++;      
    }
    
    if (reminder_list.length == 0) {
      html += `
          <tr id="rd_row_1">
            <td width="20%">
              <input type=number id="rd_value_1" name="rd_value_1" value="30" min="0">
            </td>
            <td>
              <select id="rd_unit_1" name="rd_unit_1">
                <option value="minute">Minutes before</option>
                <option value="hour">Hours before</option>
                <option value="day">Days before</option>
              </select>
            </td>
            <td width="15%" align=center>
              <input type=button id="rd_remove_1" name="rd_remove_1" data-icon="delete" data-iconpos="notext" onClick="removeReminder('rd_row_1')">
            </td>
          </tr>
      `;
    }

    html += `
          <tr id="add_reminder_btn">
            <td colspan=3>
              <a href="javascript:addReminder('rd_row_1')">Add Reminder</a>
            </td>
          </tr>
        </tbody>
        </table>    
        <hr>
        
        <div id="dt_box"></div>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td align=center>
              <input type=button data-icon="plus" value="Update Event" onClick="saveEvent()">
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>      
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}
 

exports.printEditEventForm = async function(pda_pool, user_id, op, oper_mode, what_year, what_month, event_id, has_reminder, call_by) {
  var conn, html;
  var event_dtl = {};
  var reminder_list = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    event_dtl = await _getEventDetail(conn, event_id);
    reminder_list = await _getReminderListForEvent(conn, event_id);
    
    html = wev.printHeader("Edit Scheduler Event");
    html += _printSchedulerJS(op, oper_mode, reminder_list);
    html += _printEditEventForm(op, oper_mode, what_year, what_month, event_id, has_reminder, event_dtl, reminder_list, call_by);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


function _printReadEventForm(op, oper_mode, what_year, what_month, call_by, search_phase, event_id, has_reminder, event_dtl, reminder_list) {
  var html, back_link, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
        
    if (call_by == "event_search") {
      back_link = `javascript:goBackSearchResult()`;
    }
    else if (call_by == "event_list") {
      back_link = `javascript:goBackEventList()`;
    }
    else {
      back_link = `javascript:goBack(${what_year}, ${what_month})`;
    }
        
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="event_id" name="event_id" value="${event_id}">
    <input type=hidden id="search_phase" name="search_phase" value="${search_phase}">
    <input type=hidden id="call_by" name="call_by" value="${call_by}">
  
    <div data-role="page" style="background-color:${pda_bg_color}">  
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="${back_link}" data-icon="back" class="ui-btn-left" data-ajax="false">Back</a>
        <h1>Event</h1>
      </div>
      
      <div data-role="main" class="ui-content">
        <b>Title: </b>${event_dtl.event_title}
        <hr>
        <table width=100% cellspacing=0 cellpadding=0>
          <thead></thead>
          <tbody>
            <tr>
              <td width=10% nowrap><b>Start:&nbsp;</b></td>
              <td>${event_dtl.ev_start}</td>
            </tr>
            <tr>
              <td><b>End:</b></td>
              <td>${event_dtl.ev_end}</td>          
            </tr>
          </tbody>
        </table>
        <hr>
        <b>Details:</b><br>
        ${event_dtl.event_detail}
        <hr>
    `;
    
    if (reminder_list.length > 0) {
      html += `
      <table width=100% cellspacing=0 cellpadding=0>
        <thead></thead>
        <tbody>
          <tr>
            <td><b>Reminder:</b></td>
          </tr>      
      `;
      
      for (var i = 0; i < reminder_list.length; i++) {
        var this_remind_before = parseInt(reminder_list[i].remind_before, 10);
        var this_remind_unit = (this_remind_before > 1)? wev.allTrim(reminder_list[i].remind_unit) + 's' : wev.allTrim(reminder_list[i].remind_unit);
        
        html += `
        <tr>
          <td>${this_remind_before} ${this_remind_unit} before</td>
        </tr>        
        `;         
      }
      
      html += `
        </tbody>
      </table>          
      `;
    }
    else {
      html += `
      <b>No reminder</b>
      `;
    }
    
    html += `
        <hr>
      </div>
      
      <div data-role="footer" data-position="fixed" data-tap-toggle="false">
        <table width=100% cellspacing=0 cellpadding=0>
          <thead></thead>
          <tbody>
            <tr>
              <td width=50% align=center>
                <input type=button data-icon="edit" value="Edit" onClick="editEvent();">
              </td>
              <td width=50% align=center>
                <input type=button data-icon="delete" value="Delete" onClick="deleteEvent();">
              </td>            
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.printReadEventForm = async function(pda_pool, user_id, op, oper_mode, what_year, what_month, event_id, has_reminder, call_by, search_phase) {
  var conn, html;
  var event_dtl = {};
  var reminder_list = [];

  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    event_dtl = await _getEventDetail(conn, event_id);
    reminder_list = await _getReminderListForEvent(conn, event_id);

    html = wev.printHeader("Read Event");
    html += _printSchedulerJS(op, oper_mode, reminder_list);
    html += _printReadEventForm(op, oper_mode, what_year, what_month, call_by, search_phase, event_id, has_reminder, event_dtl, reminder_list);    
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _modifyEvent(conn, event_id, event_title, event_detail, event_start, event_end) {
  var sql, param;
  
  try {
    sql = `UPDATE schedule_event ` +
          `  SET event_title = ?, ` +
          `      event_detail = ?, ` +
          `      ev_start = ?, ` +
          `      ev_end = ? ` +
          `  WHERE event_id = ?`;
          
    param = [event_title, event_detail, event_start, event_end, event_id];
    await dbs.sqlExec(conn, sql, param);      
  }
  catch(e) {
    throw e; 
  }
}


async function _modifyEventReminder(conn, event_id, reminder) {
  var sql, param;
  
  try {
    //-- Step 1: Firstly, remove all existing event reminder records --//
    await _deleteReminder(conn, event_id);
        
    //-- Step 2: Create reminder(s) of the event --//
    for (var i = 0; i < reminder.length; i++) {
      var this_rd_value = parseInt(reminder[i].rd_value, 10);
      var this_rd_unit = reminder[i].rd_unit;

      //-- Note: Since 'has_informed' flag is saved as 0, it means the reminder may be triggered again, even --//
      //--       informed message has been sent before.                                                      --//      
      sql = `INSERT INTO schedule_reminder ` +
            `(event_id, remind_before, remind_unit, has_informed) ` +
            `VALUES ` +
            `(?, ?, ?, 0)`;
            
      param = [event_id, this_rd_value, this_rd_unit];
      await dbs.sqlExec(conn, sql, param);      
    }
  }
  catch(e) {
    throw e; 
  }  
}


exports.updateEvent = async function(pda_pool, user_id, event_id, event_title, event_detail, event_start, event_end, reminder) {
  var conn;
  var sql_tx_on = false;
  var retval = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      await _modifyEvent(conn, event_id, event_title, event_detail, event_start, event_end);
      await _modifyEventReminder(conn, event_id, reminder);
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: "Unable to start SQL transaction session, event update process is aborted."};
    }
  }
  catch(e) {
    if (sql_tx_on) {await dbs.rollbackTransaction(conn);}
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _deleteEventRecord(conn, event_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM schedule_event ` +
          `  WHERE event_id = ?`;
          
    param = [event_id];
    await dbs.sqlExec(conn, sql, param);                    
  }
  catch(e) {
    throw e;
  }
}


async function _deleteReminder(conn, event_id) {
  var sql, param;
  
  try {
    sql = `DELETE FROM schedule_reminder ` +
          `  WHERE event_id = ?`;
          
    param = [event_id];
    await dbs.sqlExec(conn, sql, param);          
  }
  catch(e) {
    throw e;
  }  
}


exports.deleteEvent = async function(pda_pool, event_id) {
  var conn;
  var sql_tx_on = false;
  var retval = {ok: true, msg: ''};
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    if (await dbs.startTransaction(conn)) {
      sql_tx_on = true;
      
      await _deleteEventRecord(conn, event_id);
      await _deleteReminder(conn, event_id);
      
      await dbs.commitTransaction(conn);
    }
    else {
      retval = {ok: false, msg: "Unable to start SQL transaction session, event record deletion process is aborted."};
    }    
  }
  catch(e) {
    if (sql_tx_on) {
      await dbs.rollbackTransaction(conn);
    }
    
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return retval;
}


async function _getEventList(conn, user_id) {
  var sql, param, data;
  var event_list = [];
  
  try {
    sql = `SELECT event_id, event_title, DATE_FORMAT(ev_start, '%Y-%m-%d %H:%i') AS ev_start, ` +
          `       CASE ` +
          `         WHEN ev_start < CURRENT_TIMESTAMP() THEN 1 ` +
          `         ELSE 0 ` +
          `       END AS has_passed ` +
          `  FROM schedule_event ` +
          `  WHERE user_id = ? ` +
          `  ORDER BY ev_start`;
    
    param = [user_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    for (var i = 0; i < data.length; i++) {
      event_list.push({event_id: data[i].event_id, event_title: data[i].event_title, ev_start: data[i].ev_start, has_passed: data[i].has_passed});
    } 
  }
  catch(e) {
    throw e;
  }
  
  return event_list;  
}


function _printEventList(op, what_year, what_month, event_list) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="event_id" name="event_id" value="0">
    <input type=hidden id="call_by" name="call_by" value="event_list">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack(${what_year}, ${what_month})" data-icon="back" style="ui-btn-left" data-ajax="false">Back</a>
        <h1>Event List</h1>
      </div>
    
      <div data-role="content" style="ui-content">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead>
          <tr style="background-color:lightblue">
            <td width=20% align=center><b>Date</b></td>
            <td align=center><b>Event</b></td>
          </tr>
        </thead>
        
        <tbody>    
    `;
    
    if (event_list.length > 0) {
      var first_active_event_found = false;

      for (var i = 0; i < event_list.length; i++) {
        var this_event_id = event_list[i].event_id;
        var this_event_title = event_list[i].event_title;
        var this_ev_start = event_list[i].ev_start;
        var this_has_passed = (parseInt(event_list[i].has_passed, 10) == 1)? true : false;
        var tr_bg_color = (this_has_passed)? 'lightgray' : 'lightyellow';
        var tr_id = '';
        
        if (!this_has_passed && !first_active_event_found) {
          tr_id = "id=first_active_event";
          first_active_event_found = true;
        } 
        
        html += `
        <tr ${tr_id} style="background-color:${tr_bg_color}">
          <td align=center nowrap><a href="javascript:readEvent(${this_event_id})">${this_ev_start}</a></td>
          <td><a href="javascript:readEvent(${this_event_id})">${this_event_title}</a></td>
        </tr>
        `;
      }      
    }
    else {
      html += `
      <tr style="background-color:lightgray">
        <td colspan=2>No event record</td>
      </tr>      
      `;
    }
    
    html += `
          <tr style="background-color:lightblue">
            <td colspan=2 align=center>End</td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
    </form>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printEventList = async function(pda_pool, op, oper_mode, user_id, what_year, what_month) {
  var conn, html;
  var event_list = [];
  var reminder_list = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    event_list = await _getEventList(conn, user_id);
    
    html = wev.printHeader("Event List");
    html += _printSchedulerJS(op, oper_mode, reminder_list);
    html += _printEventList(op, what_year, what_month, event_list);
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }  
  
  return html;
}


function _printSearchForm(op, what_year, what_month) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="oper_mode" name="oper_mode" value="">
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
  
    <div data-role="page" style="background-color:${pda_bg_color};">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:goBack(${what_year}, ${what_month})" data-icon="back" style="ui-btn-left" data-ajax="false">Back</a>
        <h1>Event Search</h1>      
      </div>
    
      <div data-role="content" style="ui-content">
        <!-- Note: ASCII semicolon is NOT equal to semicolon in other languages or UTF-8 encoded semicolon -->
        <label for="search_phase"><b>Search keyword(s) separated by semicolon:</b></label>
        <input type=text id="search_phase" name="search_phase">
        <br>
        <input type=button id="go" name="go" value="Go" data-icon="search" onClick="goSearch()">
      </div>
    </div>
    </form>    
    `;    
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printSearchForm = async function(op, what_year, what_month) {
  var html;
  
  try {
    html = wev.printHeader("Event Search");
    html += _printSchedulerJS(op, "", []);
    html += _printSearchForm(op, what_year, what_month);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}


async function _searchEvents(conn, user_id, search_phase) {
  var sql, param, data;
  var events = new SimpleHashTable();
  var keywords = [];
  var buffer = [];
  var result = [];
  
  try {
    keywords = search_phase.split(";");
    
    for (var i = 0; i < keywords.length; i++) {
      var this_keyword = wev.allTrim(keywords[i]);
      
      sql = `SELECT event_id, event_title, DATE_FORMAT(ev_start, '%Y-%m-%d %H:%i') AS ev_start ` +
            `  FROM schedule_event ` +
            `  WHERE user_id = ? ` +
            `    AND (event_title LIKE '%${this_keyword}%' ` +
            `     OR event_detail LIKE '%${this_keyword}%') ` +
            `  ORDER BY ev_start DESC`;
      
      param = [user_id];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      for (var k = 0; k < data.length; k++) {
        var this_event_id = data[k].event_id;
        
        //-- Avoid event duplication in search result --//
        if (!events.containsKey(this_event_id)) {
          buffer.push({event_id: data[k].event_id, event_title: data[k].event_title, ev_start: data[k].ev_start});     
          events.put(this_event_id, data[k].event_title);
        }
      }      
    }
    
    //-- Sort in reverse order, the newest event go first. --//
    //-- Rules: If sort function return positive value, then ev2 is kept before ev1. --//
    //--        If sort function return negative value, then ev1 is kept before ev2. --//
    //--        If sort function return a zero, then order of ev1 and ev2 is remains --//
    //--        the same.                                                            --//  
    result = buffer.sort((ev1, ev2) => (ev1.ev_start < ev2.ev_start)? 1 : (ev1.ev_start > ev2.ev_start)? -1 : 0);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function _printSearchResult(op, what_year, what_month, search_phase, search_records) {
  var html, pda_bg_color;
  
  try {
    pda_bg_color = wev.getGlobalValue('PDA_BG_COLOR');
    
    html = `
    <form id="frm_sch" name="frm_sch" action="" method="post" data-ajax="false">
    <input type=hidden id="op" name="op" value="${op}">
    <input type=hidden id="search_phase" name="search_phase" value="${search_phase}">  
    <input type=hidden id="what_year" name="what_year" value="${what_year}">
    <input type=hidden id="what_month" name="what_month" value="${what_month}">
    <input type=hidden id="event_id" name="event_id" value="0">
    <input type=hidden id="call_by" name="call_by" value="event_search">
    
    <div data-role="page" style="background-color:${pda_bg_color}">
      <div data-role="header" data-position="fixed" data-tap-toggle="false">
        <a href="javascript:searchAgain('')" data-icon="back" style="ui-btn-left" data-ajax="false">Back</a>
        <h1>Search Result</h1>
        <a href="javascript:goBack(${what_year}, ${what_month})" data-icon="calendar" style="ui-btn-right" data-ajax="false">Calender</a>
      </div>
  
      <div data-role="content" style="ui-content">
        <table width=100% cellspacing=1 cellpadding=1>
        <thead>
          <tr style="background-color:lightblue">
            <td width=20% align=center><b>Date</b></td>
            <td align=center><b>Event</b></td>        
          </tr>
        </thead>
        
        <tbody>    
    `;

    if (search_records.length > 0) {
      for (var i = 0; i < search_records.length; i++) {
        var this_event_id = search_records[i].event_id;
        var this_event_title = search_records[i].event_title;
        var this_ev_start = search_records[i].ev_start;
        var this_target = `javascript:readEvent(${this_event_id})`;
          
        html += `
        <tr style="background-color:lightyellow">
          <td align=center nowrap><a href="${this_target}">${this_ev_start}</a></td>
          <td><a href="${this_target}">${this_event_title}</a></td>
        </tr>        
        `;      
      }
    }
    else {
      html += `
      <tr style="background-color:lightgray">
        <td colspan=2>Nothing is found</td>
      </tr>      
      `;
    }
    
    html += `
        </tbody>
        </table>
      </div>
    </div>
    </form>      
    `;
  }  
  catch(e) {
    throw e;
  }
  
  return html;
}


exports.printSearchResult = async function(pda_pool, op, user_id, what_year, what_month, search_phase) {
  var conn, html;
  var search_records = [];
  
  try {
    conn = await dbs.getPoolConn(pda_pool, dbs.selectCookie('PDA'));
    
    search_records = await _searchEvents(conn, user_id, search_phase);
    
    html = wev.printHeader("Search Result");
    html += _printSchedulerJS(op, "", []);
    html += _printSearchResult(op, what_year, what_month, search_phase, search_records);  
  }
  catch(e) {
    throw e;
  }
  finally {
    dbs.releasePoolConn(conn);
  }
  
  return html;
}


async function _switchToPage(url, param, method, message) {
  let html;
  
  try {
    html = `
    <!doctype html>
    <html>
      <head>
        <script type="text/javascript" src='/js/jquery.min.js'></script>
        <script type="text/javascript" src="/js/js.cookie.min.js"></script>
        <script type="text/javascript" src='/js/crypto-lib.js'></script>               
        <script type="text/javascript" src='/js/common_lib.js'></script>
                        
        <script>
          $(document).ready(function() {
            let message = "${message}";
          
            if (typeof(message) == "string") {
              if (message.trim() != "") {
                alert(message);
              }
            }
            
            switchPage();
          });
          
          async function switchPage() {
            await prepareRollingKey(${_key_len});
            document.getElementById("frmLeap").submit();  
          }
        </script>
      </head>
      
      <body>
        <form id="frmLeap" name="frmLeap" action="${url}" method="${method}">
          <input type=hidden id="roll_rec" name="roll_rec" value="">
          <input type=hidden id="iv_roll_rec" name="iv_roll_rec" value="">
          <input type=hidden id="roll_rec_sum" name="roll_rec_sum" value="">`;
      
    if (typeof(param) == "object" && param != null) {     
      for (let key in param) {
        // Check if the property is actually on the object itself
        // and not inherited from the prototype chain
        if (Object.hasOwnProperty.call(param, key)) {
          let value = param[key];
          html += `
          <input type=hidden id="${key}" name="${key}" value="${value}">
          `
        }
      }            
    }
                
    html += `         
        </form>        
      </body>        
    </html>`;
  }
  catch(e) {
    throw e;
  }
  
  return html;  
}


exports.switchToPage = async function(url, param, method, message) {
  let html;
  
  try {
    html = await _switchToPage(url, param, method, message);
  }
  catch(e) {
    throw e;
  }
  
  return html;
}
