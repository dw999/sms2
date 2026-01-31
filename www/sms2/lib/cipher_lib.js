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
// File name: cipher_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2019-11-15      DW              It contains all encryption and decryption functions for node.js back-end.
// 
// V1.0.01       2022-09-10      DW              Add RSA related functions, such as key pair generation, public key encryption,
//                                               and private key decryption.
//
// V1.0.02       2023-10-10      DW              Add and renew some AES and RSA functions.
//
// V1.0.03       2023-11-19      DW              Fix a bug on '_rsaDrawKeyPair', it can now provide a valid RSA key pair randomly. 
//
// V1.0.04       2023-11-26      DW              Incrase default RSA key length from 2048 to 4096 bits.
//
// V1.0.05       2024-01-12      DW              Add functions 'covertHashObjToIV' and 'convertBase64IVtoIV'.
//
// V1.0.06       2024-02-11      DW              Third party library 'crypto-js' is phased out, and related functions 'encrypt_str'
//                                               and 'decrypt_str' are frozen.
//
// V1.0.07       2024-03-01      DW              Increase entropy of AES key and IV by using functions '_grindKey' and '_getIv'. Now,
//                                               passphase longer than 32 characters is meaningful.  
//
// V1.0.08       2024-03-14      DW              Add function 'aesDecryptWithKeyJSON', which is a preperation to use a post-quantum 
//                                               computing era cryptographic method "Crystrals Kyber" later.
//
// V1.0.09       2024-03-20      DW              Add functions 'generateKyberKeyPair' and 'generateKyberKeyPairBase64'.
//
// V1.0.10       2024-04-16      DW              Add function 'getKyberClientModule'.
//
// V1.0.11       2024-06-07      DW              Rewrite function 'getKyberClientModule' to replace Crystals Kyber library used on
//                                               front-end from 'dajiaji/crystals-kyber-js' to 'Dashlane/pqc.js', so that it can be
//                                               hold on SMS server. 
//
// V1.0.12       2024-09-17      DW              1. Cryptographic method Crystals Kyber has been finalised, and used NPM library 
//                                                  'dajiaji/crystals-kyber-js' has been updated and renamed as 'dajiaji/mlkem'. 
//                                                  SMS programs and installation scripts are changed accordingly.
//                                               2. Clean up this module to remove no longer used coding. 
//
// V1.0.13       2024-10-10      DW              Add function 'makeHash', which is used to create hash of user password. Since node
//                                               library 'bcrypt' depends on many unsupported libraries and at least one has serious
//                                               technical issue. Therefore, functions depend on 'bcrypt' will be phased out gradually,
//                                               and replaced by functions using library 'hash-wasm'. 'makeHash' is one of them.
//
// V1.0.14       2024-10-18      DW              Fix bugs on function 'makeHash'.  
//
// V1.0.15       2024-10-22      DW              Rewrite functions 'encryptPassword' and 'isPasswordMatch' by using 3rd party library
//                                               'hash-wasm' and phase out library 'bcrypt'.
//
// V1.0.16       2025-12-26      DW              Adjust parameters of argon2id on function 'encryptPassword' to harden password security.
//
// V1.0.17       2026-01-29      DW              Refine scope of variables declare in this library.
//#################################################################################################################################

"use strict";
const decoder = require('arraybuffer-encoding');
const hashwasm = require('hash-wasm'); 
//const bcrypt = require('bcrypt');
const crypto = require('node:crypto');
const { MlKem1024 } = require("mlkem");
const util = require('util');
const dbs = require('../lib/db_lib.js');
const wev = require('../lib/webenv_lib.js');


function _generateTrueRandomStr(option, max_len) {
	let result = "";
	
	try {
		//*-- Valid options are: 'A' = Alphanumeric, 'N' = Numeric only, 'S' = English characters only. --*//
	  if (typeof(option) != 'string') {
	    option = 'A';  
	  }
	  else {
	    option = wev.allTrim(option);
	    
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
 		
		let stop_run = false;
		
		while (!stop_run) {
			let buffer = "";			
			const randomArray = new Uint8Array(max_len);
			crypto.getRandomValues(randomArray);
			
			for (const num of randomArray) {
				if (option == 'A') {
					if ((num >= 48 && num <= 57) || (num >= 65 && num <= 90) || (num >= 97 && num <= 122)) {
						buffer += String.fromCharCode(num);
					}
				}
				else if (option == 'N') {
					if (num >= 48 && num <= 57) {
						buffer += String.fromCharCode(num);
					}					
				}
				else {
					if ((num >= 65 && num <= 90) || (num >= 97 && num <= 122)) {
						buffer += String.fromCharCode(num);
					}					
				}			 
			}
			
			result += buffer;
			
			if (result.length >= max_len) {
				result = result.substr(0, max_len);
				stop_run = true;
			}
		} 
	}
	catch(e) {
    throw e;		
	}
	
	return result;
}


exports.generateTrueRandomStr = function(option, max_len) {
	let result = "";
	
	try {
		result = _generateTrueRandomStr(option, max_len);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


/*
exports.encryptPassword = function(password) {
  let salt, hash;
  
  try {
	  salt = bcrypt.genSaltSync(10);
	  hash = bcrypt.hashSync(password, salt);
  }
  catch(e) {
    throw e;
  }

	return hash;
}


exports.isPasswordMatch = function(password, passwd_hash) {
	return bcrypt.compareSync(password, passwd_hash);
}
*/ 


exports.encryptPassword = async function(password) {
  let result = "";
  
  try {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
  
    result = await hashwasm.argon2id({
      password: password,
      salt,                  // salt is a buffer containing random bytes
      parallelism: 8,
      iterations: 3,
      memorySize: 131072,    // use 128MB memory
      hashLength: 32,        // output size = 32 bytes
      outputType: 'encoded', // return standard encoded string containing parameters needed to verify the key
    });    
  }
  catch(e) {
    throw e;
  }
  
  return result;
} 


exports.isPasswordMatch = async function(password, hash) {
  let result;
  
  try {
    result = await hashwasm.argon2Verify({
      password: password,
      hash: hash
    });
  }
  catch(e) {
    throw e;
  }  
  
  return result;
}


function _arrayBufferToBase64String(arrayBuffer) {
  let byteArray = new Uint8Array(arrayBuffer)
  let byteString = '';
  
  try {
	  for (let i=0; i<byteArray.byteLength; i++) {
	    byteString += String.fromCharCode(byteArray[i]);
	  }
  }
  catch(e) {
		throw e;
	}
  
  return btoa(byteString);
}


exports.arrayBufferToBase64String = function(arrayBuffer) {
	let result = '';
	
	try {
		result = _arrayBufferToBase64String(arrayBuffer);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _base64StringToArrayBuffer(b64str) {
  let byteStr;
  let bytes;

  try {
		byteStr = atob(b64str);
		bytes = new Uint8Array(byteStr.length);
		
	  for (let i = 0; i < byteStr.length; i++) {
	    bytes[i] = byteStr.charCodeAt(i);
	  }
  }
  catch(e) {
		throw e;
	}
  
  return bytes.buffer;
}


exports.base64StringToArrayBuffer = function(b64str) {
	let result;
	
	try {
		result = _base64StringToArrayBuffer(b64str);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _textToArrayBuffer(str) {
  let buf = unescape(encodeURIComponent(str)); // 2 bytes for each char
  let bufView = new Uint8Array(buf.length);
  
  try {
	  for (let i=0; i < buf.length; i++) {
	    bufView[i] = buf.charCodeAt(i);
	  }
  }
  catch(e) {
		throw e;
	}
  
  return bufView;
}


function _convertPemToBinary(pem) {
  let lines = pem.split('\n');
  let encoded = '';

  try {   
	  for (let i = 0; i < lines.length; i++) {
	    if (lines[i].trim().length > 0 &&
	        lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 && 
	        lines[i].indexOf('-BEGIN PRIVATE KEY-') < 0 &&
	        lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
	        lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
	        lines[i].indexOf('-END PUBLIC KEY-') < 0 &&
	        lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
	        lines[i].indexOf('-END PRIVATE KEY-') < 0 &&
	        lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
	      encoded += lines[i].trim();
	    }
	  }
  }
  catch(e) {
		throw e;
	}
    
  return _base64StringToArrayBuffer(encoded);
}


//-- Note: For asymmetric RSA key pairs only --//
async function _importKeyFromPem(keyType, pem, algorithm, exportable, usages) {
  let format, header, footer, result;
  
  try {
    switch (keyType) {
      case 'public':
        format = 'spki';
        header = '-----BEGIN PUBLIC KEY-----';
        footer = '-----END PUBLIC KEY-----';
        break;
        
      case 'private':
        format = 'pkcs8';
        header = '-----BEGIN PRIVATE KEY-----';
        footer = '-----END PRIVATE KEY-----';
        break;
    }
    
    //let keyData = decoder.Base64.Decode(
    //    pem.trim()
    //    .slice(header.length, -1 * footer.length)
    //    .replaceAll('\n', '')
    //);
    
    let keyData = _convertPemToBinary(pem);
        
    result = await crypto.subtle.importKey(format, keyData, algorithm, exportable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.importKeyFromPem = async function(keyType, pem, algorithm, exportable, usages) {
  let result;
  
  try {
    result = await _importKeyFromPem(keyType, pem, algorithm, exportable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _pemFromKey(keyType, key) {
  let format, header, footer, pem;
  
  try {
    switch (keyType) {
      case 'public':
        format = 'spki';
        header = '-----BEGIN PUBLIC KEY-----';
        footer = '-----END PUBLIC KEY-----';
        break;
        
      case 'private':
        format = 'pkcs8';
        header = '-----BEGIN PRIVATE KEY-----';
        footer = '-----END PRIVATE KEY-----';
        break;
    }
    
    const keyData = await crypto.subtle.exportKey(format, key);
    pem = [
      header,
      decoder.Base64.Encode(keyData).replace(/(.{64})/g, '$1\n'),
      footer
    ].join('\n');
  }
  catch(e) {
    throw e;
  }
  
  return pem;
}


exports.pemFromKey = async function(keyType, key) {
  let pem;
  
  try {
    pem = await _pemFromKey(keyType, key);
  }
  catch(e) {
    throw e;
  }  
  
  return pem;
} 


exports.rsaEncrypt = async function(algorithm, publicKey, plaintext) {
	let result, text;
	
	try {
		text = new TextEncoder().encode(plaintext);
    result = await crypto.subtle.encrypt(algorithm, publicKey, text);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.rsaDecrypt = async function(algorithm, privateKey, encrypted) {
	let result, decrypted;
	
	try {
		decrypted = await crypto.subtle.decrypt(algorithm, privateKey, encrypted);
    result = new TextDecoder("utf-8").decode(decrypted);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.digestData = async function(algorithm, data) {
	let result, buffer;
	
	try {
		if (typeof(algorithm) != "string") {
			algorithm = "SHA-256";
		}
		else {
			algorithm = algorithm.toUpperCase().trim();
			if (algorithm != "SHA-1" && algorithm != "SHA-256" && algorithm != "SHA-384" && algorithm != "SHA-512") {
				algorithm = "SHA-256";
			}
		}
		
		buffer = await crypto.subtle.digest(algorithm, _textToArrayBuffer(data));
		result = _arrayBufferToBase64String(buffer);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.generateSignKeyPair = async function(algorithm, extractable) {
	let usage, result;
	
	try {
		extractable = (typeof(extractable) != "boolean")? false : extractable;
		
		if (typeof(algorithm) != "object") {
			throw new Error("Invalid algorithm format is found.");
		}
		else {
			let alg_name = algorithm.name;
			
			if (alg_name != "RSASSA-PKCS1-v1_5" && alg_name != "RSA-PSS" && alg_name != "ECDSA") {
				throw new Error("Invalid algorithm is given.");
			}
		}
		
    usage = ['sign', 'verify'];

    // Generate a new key pair for calculating signatures with RSA
    const key_pair = await _generateKeyPairRSA(algorithm, extractable, usage);
    
    result = {public: key_pair.publicKey, private: key_pair.privateKey};    
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.createSignature = async function(algorithm, sign_key, text) {
	let result;
	
	try {
		result = await crypto.subtle.sign(
        // Name of the algorithm and RSA padding. This uses PKCS#1 v1.5
        // For RSA-PSS, you would pass a dictionary like this one instead:
        // `{name: 'RSA-PSS', saltLength: 32}`
        // The value of saltLength should match the length in bytes of the digest:
        // for example, when using SHA-256, the length is 32 (bytes)
        algorithm,
        // Signatures are calculated with the private key
        sign_key,
        // Message to sign
        text
    );
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.verifySignature = async function(algorithm, verify_key, signature, original_text) {
	let result;
	
	try {
		result = await crypto.subtle.verify(
        // Name of the algorithm and RSA padding
        // This is the same dictionary passed to the sign method
        algorithm,
        // Public key, used to verify the signature
        verify_key,
        // Signature (as a buffer)
        signature,
        // Original message that was signed
        original_text
    );
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _convertObjectToBase64Str(object) {
	let result;
	
	try {
    result = Buffer.from(JSON.stringify(object)).toString("base64");		
	}
	catch(e) {
		throw e;
	}
	
	return result;  
}


exports.convertObjectToBase64Str = function(object) {
	let result;
	
	try {
    result = _convertObjectToBase64Str(object);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function _convertBase64StrToObject(base64str) {
	let result;
	
	try {
    let json = Buffer.from(base64str, "base64").toString();
    result = JSON.parse(json);		
	}
	catch(e) {
		throw e;
	}
	
	return result;  
}


exports.convertBase64StrToObject = function(base64str) {
	let result;
	
	try {
    result = _convertBase64StrToObject(base64str);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.convertBase64StrToUint8Array = function(base64str) {
  let object, objstr, result;
  
  try {
    object = _convertBase64StrToObject(base64str);
    objstr = JSON.stringify(object);
    result = _convertJsonObjStrToUint8Array(objstr);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _addNewRsaKeyPair(conn, rsa_keys) {
	let sql, param, id, stop_run, cnt, action;
	
	try {
		stop_run = false;
		cnt = 0;
		
		while (!stop_run) {		
			id = _generateTrueRandomStr('A', 16);
			
			if (await _rsaKeyExist(conn, id)) {
        cnt++;
        if (cnt > 3) {
					action = "UPDATE";
					stop_run = true;
				}				
			}
			else {
				action = "ADD";
				stop_run = true;
			}
	  }
	  
	  if (action == "ADD") {
			sql = `INSERT INTO rsa_keypair ` +
			      `(key_id, public_key, private_key, algorithm, add_datetime) ` +
			      `VALUES ` +
			      `(?, ?, ?, ?, NOW())`;
			      
			param = [id, rsa_keys.public, rsa_keys.private, rsa_keys.algorithm];     
			await dbs.sqlExec(conn, sql, param); 
		}
		else {
			sql = `UPDATE rsa_keypair ` +
			      `  SET public_key = ?, ` +
			      `      private_key = ?, ` +
			      `      algorithm = ?, ` +
			      `      add_datetime = NOW() ` +
			      `  WHERE key_id = ?`;
			      
			param = [rsa_keys.public, rsa_keys.private, rsa_keys.algorithm, id];
			await dbs.sqlExec(conn, sql, param);      
		}	  
	}
	catch(e) {
		throw e;
	}	
	
	return id;
}


exports.addNewRsaKeyPair = async function(conn, rsa_keys) {
	let result;
	
	try {
		result = await _addNewRsaKeyPair(conn, rsa_keys);
	}
	catch(e) {
		throw e;
	}
	
	return result;
} 


async function _rsaKeyPairPoolSize(conn, days) {
  let sql, data, param, size;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` +
          `  FROM rsa_keypair ` +
          `  WHERE DATEDIFF(NOW(), add_datetime) <= ?`;
    
    param = [days];      
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    size = data[0].cnt;          
  }
  catch(e) {
    throw e;
  }
  
  return size;
}


async function _rsaDrawKeyPair(conn, days) {
  let result = {key_id: '', algorithm: '', public: '', private: ''};
  let chooser = '';
  let stop_run, cnt, loop_cnt, sql, param, data, get_last_one; 
   
  try {
    cnt = 0;
    loop_cnt = 0;
    stop_run = false;
    get_last_one = false;
    
    while (!stop_run) {
      let char = String.fromCharCode(Math.floor(Math.random() * 123));
      if ((char >= '0' && char <= '9') || (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')) {
        chooser = char;
        stop_run = true;
      }      
      
      loop_cnt++;
      if (loop_cnt >= 20) {
        stop_run = true;
      }
    }

    if (chooser != '') {
      sql = `SELECT key_id, algorithm, public_key, private_key ` +
            `  FROM rsa_keypair ` + 
            `  WHERE key_id LIKE ? ` + 
            `    AND DATEDIFF(NOW(), add_datetime) <= ?`;
            
      param = ['%'+chooser+'%', days];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
            
      if (data.length > 0) {
        let i = (data.length == 1)? 0 : Math.floor(Math.random() * data.length);
        result = {key_id: data[i].key_id, algorithm: data[i].algorithm, public: data[i].public_key, private: data[i].private_key};
      }
      else {
        get_last_one = true;
      }
    }
    else {
      get_last_one = true;
    }   

    if (get_last_one) {
      // This is the last resort. However, don't use very old RSA key pair. //
      sql = `SELECT key_id, algorithm, public_key, private_key ` +
            `  FROM rsa_keypair ` + 
            `  WHERE DATEDIFF(NOW(), add_datetime) <= ? ` +
            `  ORDER BY add_datetime DESC ` + 
            `  LIMIT 0,1`; 
      
      param = [days];
      data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
      
      if (data.length > 0) {
        result = {key_id: data[0].key_id, algorithm: data[0].algorithm, public: data[0].public_key, private: data[0].private_key};
			}
			else {
				// If the last resort is fail, try to generate a new RSA key pair. //
				result = await _rsaGenerateKeyPair(conn, null, days)
			}
    } 
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _rsaKeyExist(conn, key_id) {
  let sql, param, data, result;
  
  try {
    sql = `SELECT COUNT(*) AS cnt ` + 
          `  FROM rsa_keypair ` +
          `  WHERE key_id = ?`;
          
    param = [key_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    result = (data[0].cnt > 0)? true : false;          
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _rsaGenerateKeyPair(conn, algorithm, days) {
  let result = {key_id: '', algorithm: '', public: '', private: ''};
  let sql, param, data, key_id, stop_run, loop_cnt;
  
  try {
		if (typeof(algorithm) != "object" || typeof(algorithm) == "undefined" || algorithm == null) {
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
	  }
		let extractable = true;
		let usage = ['encrypt', 'decrypt'];
    let key_pair = await _generateKeyPairRSA(algorithm, extractable, usage);
    
    if (typeof(key_pair) != "undefined" && key_pair != null) {
      loop_cnt = 0;
      stop_run = false;
      // Note: RSA public key, private key and algorithm are objects, which must be converted into base64 strings //
      //       before save to the database.                                                                       //
		  let rsa_key_strs = {public: '', private: '', algorithm: ''};
		  let pub_key_pem = await _pemFromKey('public', key_pair.public);
		  let pri_key_pem = await _pemFromKey('private', key_pair.private);
		  rsa_key_strs.public = _convertObjectToBase64Str(pub_key_pem);
		  rsa_key_strs.private = _convertObjectToBase64Str(pri_key_pem);
		  rsa_key_strs.algorithm = _convertObjectToBase64Str(key_pair.algorithm);
            
      let key_id = await _addNewRsaKeyPair(conn, rsa_key_strs);
      result = {key_id: key_id, algorithm: rsa_key_strs.algorithm, public: rsa_key_strs.public, private: rsa_key_strs.private};      
    }
    else {
      if (await _rsaKeyPairPoolSize(conn, days) > 0) {
        //-- The last resort --//
        sql = `SELECT key_id, public_key, private_key, algorithm ` +
              `  FROM rsa_keypair ` + 
              `  WHERE DATEDIFF(NOW(), add_datetime) <= ? ` +
              `  ORDER BY add_datetime DESC ` + 
              `  LIMIT 0,1`; 
        
        param = [days];
        data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
        
        result = {key_id: data[0].key_id, algorithm: data[0].algorithm, public: data[0].public_key, private: data[0].private_key};        
      }
      else {
        throw new Error('Unable to generate RSA key pair');
      }
    }
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.getKeyPairRSA = async function(conn, algorithm, days) {
  let result = {key_id: '', algorithm: '', public: '', private: ''};
  
  try {
		if (parseInt(days, 10) <= 0 || isNaN(parseInt(days, 10))) {
			days = 5;
		} 
		
    //-- Determine whether RSA key pair pool large enough to draw. If it has or more RSA key pairs, then     --//
    //-- select one from the pool randomly. Otherwise, generate a new RSA key pair to the pool, and use this --//
    //-- newly created RSA key pair.                                                                         --// 
    let key_pool_size = wev.getGlobalValue('RSA_KEY_POOL_SIZE');
    key_pool_size = (parseInt(key_pool_size, 10) > 0)? key_pool_size : 50;
    
    if (await _rsaKeyPairPoolSize(conn, days) >= key_pool_size) {
      result = await _rsaDrawKeyPair(conn, days);
    }  
    else {
      result = await _rsaGenerateKeyPair(conn, algorithm, days);
    }      
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _generateKeyPairRSA(algorithm, extractable, usage) {
  let result;
  
  try {		
		result = await crypto.subtle.generateKey(algorithm, extractable, usage);
	}
	catch(e) {
		throw e;
	}
  
  return result;	
}


exports.generateRsaKeyPair = async function(algorithm, extractable) {
	let result, usage;
	
	try {
		extractable = (typeof(extractable) != "boolean")? false : extractable;
		
		if (typeof(algorithm) != "object" || typeof(algorithm) == "undefined" || algorithm == null) { 		    
			// Default algorithm is a 4096-bit key pair for encryption with RSA-OAEP //
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
	  }
		
    usage = ['encrypt', 'decrypt'];
    
    const key_pair = await _generateKeyPairRSA(algorithm, extractable, usage)
    
    result = {public: key_pair.publicKey, private: key_pair.privateKey, algorithm: algorithm};    		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.getPrivateKeyRSA = async function(conn, key_id) {
  let result;
  
  try {
		let key_obj = await _getKeyObjectRSA(conn, key_id);
		result = {private: key_obj.private, algorithm: key_obj.algorithm};
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.getPublicKeyRSA = async function(conn, key_id) {
	let result;
	
	try {
		let key_obj = await _getKeyObjectRSA(conn, key_id);
		result = {public: key_obj.public, algorithm: key_obj.algorithm};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.getKeyObjectRSA = async function(conn, key_id) {
  let result;
  
  try {
		result = await _getKeyObjectRSA(conn, key_id);
	}
	catch(e) {
		throw e;
	}
	
	return result;	
}


async function _getKeyObjectRSA(conn, key_id) {
	let sql, param, data, result;
	
	try {
		sql = `SELECT public_key, private_key, algorithm ` +
		      `  FROM rsa_keypair ` +
		      `  WHERE key_id = ?`;

    param = [key_id];
    data = JSON.parse(await dbs.sqlQuery(conn, sql, param));
    
    if (data.length > 0) {
			result = {public: data[0].public_key, private: data[0].private_key, algorithm: data[0].algorithm};
		}
		else {
			throw new Error("Invalid RSA key ID is given");
		}
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


//-- Note: For symmetric key only --//
async function _importSymmeticKey(data, algorithm, extractable, usages) {
  let result;  
  
  try {
    //-- For symmetric keys, set 'format' to 'raw' to import the key's data as-is. --//
    result = await crypto.subtle.importKey(
               'raw',
               data,
               {
                 name: algorithm
               },
               extractable, 
               usages
             );  
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.importSymmeticKey = async function(data, algorithm, extractable, usages) {
  let result;
  
  try {
    result = await _importSymmeticKey(data, algorithm, extractable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
} 


async function _grindKey(password, difficulty) {
  try {
    if (typeof(difficulty) != "number") {
      difficulty = 10;
    }
    else {
      if (Number.isInteger(difficulty)) {
        if (difficulty < 1 || difficulty > 10) {
          difficulty = 10;
        }
      }
      else {
        difficulty = 10;
      } 
    }
    
    return await _pbkdf2(password, password + password, Math.pow(2, difficulty), 32, 'SHA-256');
  }
  catch(e) {
    throw e;
  }
}


function _base64Encode(u8) {
  try {
    return btoa(String.fromCharCode.apply(null, u8));
  }
  catch(e) {
    throw e;
  }
}

function _base64Decode(str) {
  try {
    return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
  }
  catch(e) {
    throw e;
  }
}


async function _getIv(password, data) {
  try {
    const randomData = _base64Encode(crypto.getRandomValues(new Uint8Array(16)));
    return await _pbkdf2(password + randomData, data + (new Date().getTime().toString()), 1, 16, 'SHA-256');
  }
  catch(e) {
    throw e;
  }
}


async function _pbkdf2(message, salt, iterations, keyLen, algorithm) {
  try {
    const msgBuffer = new TextEncoder('utf-8').encode(message);
    const msgUint8Array = new Uint8Array(msgBuffer);
    const saltBuffer = new TextEncoder('utf-8').encode(salt);
    const saltUint8Array = new Uint8Array(saltBuffer);
  
    const key = await crypto.subtle.importKey('raw', msgUint8Array, {
      name: 'PBKDF2'
    }, false, ['deriveBits']);
  
    const buffer = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: saltUint8Array,
      iterations: iterations,
      hash: algorithm
    }, key, keyLen * 8);
  
    return new Uint8Array(buffer);
  }
  catch(e) {
    throw e;
  }
}


/*
async function _importSymmeticKeyByPassword(passphase, algorithm, extractable, usages) {
  let result;  
  
  try {
		let rawPassphase = new Uint8Array(32);		
		let passBuffer = new util.TextEncoder("utf-8").encode(passphase);
	
	  for (let i = 0; i < passBuffer.length && i < 32; i++) {
			rawPassphase[i] = passBuffer[i];
		} 
				
    result = await _importSymmeticKey(rawPassphase.buffer, algorithm, extractable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}
*/


async function _importSymmeticKeyByPassword(passphase, algorithm, extractable, usages) {
  let result;  
  
  try {
    // Notes: 
    // 1. If the 'difficulty' of '_grindKey' is changed, all data encrypted by previous value 
    //    of 'difficulty' cannot be decrypted again. i.e. If it is changed, data migration
    //    is needed.
    // 2. Since 'difficulty' will increase number of iteration on '_grindKey' expoentially, 
    //    so system performance will be affected if it is too large. Valid values are integers
    //    from 1 to 10.
    // 3. The value of 'difficulty' of '_grindKey' in back-end library (i.e. this one) must match 
    //    the value of 'difficulty' of 'grindKey' in front-end library (i.e. crypto-lib.js). The 
    //    reason is same as point (1) mentioned before.    
    let hash_key = await _grindKey(passphase, 3); 				
    result = await _importSymmeticKey(hash_key, algorithm, extractable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.importSymmeticKeyByPassword = async function(password, algorithm, extractable, usages) {
  let result;
  
  try {
    result = await _importSymmeticKeyByPassword(password, algorithm, extractable, usages);
  }
  catch(e) {
    throw e;
  }
  
  return result;
} 


async function _aesDecrypt(algorithm, passphase, iv, encrypted) {
	let result = '';
	
	try {
		const key = await _importSymmeticKeyByPassword(passphase, algorithm, false, ["encrypt", "decrypt"]);
		
		const decrypted = await crypto.subtle.decrypt(
			{name: algorithm, iv: iv}, key, encrypted
		);

    result = new util.TextDecoder('utf-8').decode(decrypted);
	}
	catch(e) {
		throw e;
	}
	
	return result;
} 


exports.aesDecrypt = async function(algorithm, passphase, iv, encrypted) {
  let result = '';
  
  try {
    result = await _aesDecrypt(algorithm, passphase, iv, encrypted);
  }
  catch(e) {
    throw e;
  }

  return result;
}


async function _aesEncrypt(algorithm, passphase, text) {
	let result = {};
	
	try {
    const iv = await _getIv(passphase, text);
		
		const key = await _importSymmeticKeyByPassword(passphase, algorithm, false, ["encrypt", "decrypt"]);
		
		const plaintext = new util.TextEncoder().encode(text);
		
		const encrypted = await crypto.subtle.encrypt(
		  {
        name: algorithm,
        iv: iv,
        length: 256
      },
      key,
      plaintext
		);
		
		// Note: 'key' is CryptoKey object, 'iv' is an UintArray, and 'encrypted' is a structured ArrayBuffer. //
		result = {key: key, iv: iv, encrypted: encrypted};
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


exports.aesEncrypt = async function(algorithm, passphase, text) {
  let result = {};
  
  try {
    result = await _aesEncrypt(algorithm, passphase, text); 
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.aesEncryptBase64 = async function(algorithm, passphase, text) {
  let result = {iv: '', encrypted: ''};
  
  try {
    let enc_obj = await _aesEncrypt(algorithm, passphase, text);
    let iv_b64 = _convertObjectToBase64Str(enc_obj.iv);
    let encrypted_b64 = _arrayBufferToBase64String(enc_obj.encrypted);

    result = {iv: iv_b64, encrypted: encrypted_b64};    
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function _convertArrayBufferToJsonStr(array_buffer) {
  let result;
  
  try {
    let u8a = new Uint8Array(array_buffer);
    result = JSON.stringify(u8a);
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


exports.aesEncryptJSON = async function(algorithm, passphase, text) {
  let result = {iv: '', encrypted: ''};
  
  try {
    let enc_obj = await _aesEncrypt(algorithm, passphase, text);
    let iv = enc_obj.iv;                    // It is an Uint8Array
    let encrypted = enc_obj.encrypted;      // It is an ArrayBuffer             
    let iv_json = JSON.stringify(iv);
    let encrypted_json = _convertArrayBufferToJsonStr(encrypted);
    // Note: 1. The data 'enc_obj.key' doesn't include on the 'result'.                                        //
    //       2. 'iv_json' and 'encrypted_json' are stringified JSON object. Actually they are both Uint8Array. //
    result = {iv: iv_json, encrypted: encrypted_json};
    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


// 'c_iv' and 'c_encrypted' are JSON object strings //
exports.aesDecryptJSON = async function(algorithm, passphase, c_iv, c_encrypted) {
  let result = '';
  
  try {
    let iv = _convertJsonObjStrToUint8Array(c_iv);
    let encrypted = _convertJsonObjStrToUint8Array(c_encrypted);        
    result = await _aesDecrypt(algorithm, passphase, iv, encrypted);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _aesDecryptWithKey(algorithm, key, iv, encrypted) {
	let result = '';
	
	try {
		const decrypted = await crypto.subtle.decrypt(
			{name: algorithm, iv: iv}, key, encrypted
		);

    result = new util.TextDecoder('utf-8').decode(decrypted);
	}
	catch(e) {
		throw e;
	}
	
	return result;
} 


exports.aesDecryptWithKeyJSON = async function(algorithm, hash_key, c_iv, c_encrypted) {
  let result;
  
  try {
    let iv = _convertJsonObjStrToUint8Array(c_iv);
    let encrypted = _convertJsonObjStrToUint8Array(c_encrypted);    
    let key = await _importSymmeticKey(hash_key, algorithm, false, ["decrypt"]);
    result = await _aesDecryptWithKey(algorithm, key, iv, encrypted);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


// 'iv_b64' and 'encrypted_b64' are Uint8Array objects in base64 format string //
exports.aesDecryptBase64 = async function(algorithm, passphase, iv_b64, encrypted_b64) {
  let result = '';
  
  try {
    let iv = _convertBase64IVtoIV(iv_b64);
    let encrypted = _base64StringToArrayBuffer(encrypted_b64);
    result = await _aesDecrypt(algorithm, passphase, iv, encrypted);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


// Note: This function has a limitation of given 'obj', which must be in
//       format {'0': number0, '1': number1, ....., '15': number15}. 
function _convertHashObjectToIV(obj) {
  let obj_keys, obj_values, result;
  
  try {
    if (typeof(obj) != "object") {
      throw new Error("The given parameter is not an object.");
    }
    else {
      obj_keys = Object.keys(obj);
      obj_values = Object.values(obj);
      if (obj_keys.length != 16) {
        throw new Error("The given object is invalid.");  
      }
      else {
        result = new Uint8Array(obj_keys.length);
        
        for (let i = 0; i < obj_keys.length; i++) {
          if (isNaN(obj_values[i])) {
            throw new Error("The given object value is invalid.");
          }
          else {
            result[i] = obj_values[i];
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


exports.convertHashObjectToIV = function(obj) {
  let result;
  
  try {
    result = _convertHashObjectToIV(obj);
  }
  catch(e) {
    throw e;
  }
  
  return result;
} 


function _convertBase64IVtoIV(iv_b64) {
  let iv_obj, result;
  
  try {
    iv_obj = _convertBase64StrToObject(iv_b64);
    result = _convertHashObjectToIV(iv_obj);
  }
  catch(e) {
    throw e;
  }
  
  return result;    
}

exports.convertBase64IVtoIV = function(iv_b64) {
  let iv_obj, result;
  
  try {
    result = _convertBase64IVtoIV(iv_b64);
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


// Note: This function is just used to handle JSON objects with the following format, others are likely to give out //
//       incorrect result.                                                                                          // 
//                                                                                                                  //
//       Required JSON format: {"0": <number0>, "1": <number1>, "2": <number2>, ....., "n": <numbe rn>}             //  
function _convertJsonObjStrToUint8Array(json_obj_str) {
  let json_obj, obj_keys, obj_values, result;
  
  try {
		// Note: Since 'json_obj_str' is in JSON string format, we need to convert it into an object, then retrieve back //
		//       data into a Uint8Array.                                                                                 //
		json_obj = JSON.parse(json_obj_str);
    obj_keys = Object.keys(json_obj);
    obj_values = Object.values(json_obj);    
		result = new Uint8Array(obj_keys.length);

    for (let i = 0; i < obj_keys.length; i++) {
      if (isNaN(obj_keys[i]) || isNaN(obj_values[i])) {
        throw new Error("The given object is invalid.");
      }
      else {
        result[i] = obj_values[i];
      }
    }
  }
  catch(e) {
    throw e;
  }  
  
  return result;
}


exports.convertJsonObjStrToUint8Array = function(json_obj_str) {
  let result;
  
  try {
    result = _convertJsonObjStrToUint8Array(json_obj_str);    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function _generateKyberKeyPair() {
  let result = {pkey: '', skey: ''};
  
  try {
    let kem = new MlKem1024();
    // pkey is public key, and skey is secret key. //
    let [pkey, skey] = await kem.generateKeyPair(); 
    
    result = {pkey: pkey, skey: skey};
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.generateKyberKeyPair = async function() {
  let result = {pkey: '', skey: ''};
  
  try {
    result = await _generateKyberKeyPair();
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.generateKyberKeyPairBase64 = async function() {
  let result = {pkey: '', skey: ''};
  
  try {
    let key_pair = await _generateKyberKeyPair();
    let pkey_b64 = wev.base64Encode(key_pair.pkey);
    let skey_b64 = wev.base64Encode(key_pair.skey);
    
    result = {pkey: pkey_b64, skey: skey_b64};
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


exports.kyberDecap = async function(ct, skey) {
  let kem, shared_key;
  
  try {
    kem = new MlKem1024();
    shared_key = await kem.decap(ct, skey);
  }
  catch(e) {
    throw e;
  }
  
  return shared_key;
}


exports.getKyberClientModule = function() {
  let js;
  
  try {
    js = `
    <script type="module">
      // Start from mlkem 2.5.0, it can be called locally. //
      import { MlKem1024 } from "/js/mlkem/esm/mod.js";
      //import { MlKem1024 } from "https://esm.sh/mlkem";

      function base64Encode(u8) {
        return btoa(String.fromCharCode.apply(null, u8))
      }
              
      function base64Decode(str) {
        return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)))
      }

      globalThis.generateSharedCipherKey = async function(pkey_b64) {
        try {
          const pkey = base64Decode(pkey_b64);

          const kem = new MlKem1024();
          const [ct, skey] = await kem.encap(pkey);
              
          const ct_b64 = base64Encode(ct);
          const skey_b64 = base64Encode(skey);              
          const secret = {ct: ct_b64, sk: skey_b64};
          return secret;
        } 
        catch (err) {
          console.log(err);
          alert(err);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return js;
}


/* 
 * 2024-09-18 DW: Since backend Crystals-Kyber (ML-KEM) library has been updated, this front-end library 
 * can't be used anymore.
 *  
exports.getKyberClientModule = function() {
  let js;
  
  try {
    js = `
    <script type="module">
      import kemBuilder from '/js/pqc-kem-kyber1024.js';

      function base64Encode(u8) {
        return btoa(String.fromCharCode.apply(null, u8))
      }
              
      function base64Decode(str) {
        return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)))
      }

      globalThis.generateSharedCipherKey = async function(pkey_b64) {
        try {
          const pkey = base64Decode(pkey_b64);

          const kem = await kemBuilder();
          const {ciphertext, sharedSecret: sharedkey} = await kem.encapsulate(pkey);

          const ciphertext_b64 = base64Encode(ciphertext);
          const sharedkey_b64 = base64Encode(sharedkey);              
          const secret = {ct: ciphertext_b64, sk: sharedkey_b64};

          return secret;
        } 
        catch (err) {
          console.log(err);
          alert(err);
        }
      }
    </script>    
    `;
  }
  catch(e) {
    throw e;
  }
  
  return js;
}
*/
