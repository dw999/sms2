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
// File name: crypto-lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2023-06-30      DW              Javascript library for front-end cryptographic operations.
//
// V1.0.01       2024-01-15      DW              - Add functions 'convertHashObjectToIV' and 'convertBase64IVtoIV'.
//                                               - Set 'AES-GCM' as default method for AES-256 encryption and decryption. 
//
// V1.0.02       2024-03-01      DW              Increase entropy of AES key and IV by using functions 'grindKey' and 'getIv'. Now,
//                                               passphase longer than 32 characters is meaningful. 
//
// V1.0.03       2024-03-14      DW              Add functions 'aesEncryptWithKeyJSON' and 'symmeticEncryptWithKey', which is a 
//                                               preperation to use a post-quantum computing era cryptographic method "Crystrals
//                                               Kyber" later.
//
// V1.0.04       2025-12-04      DW              Add function 'prepareRollingKey', the rolling key mechanism is used for MITM attacking 
//                                               detection and prevention.  
//#################################################################################################################################


function generateTrueRandomStr(option, max_len) {
	let result = "";
	
	try {
		//*-- Valid options are: 'A' = Alphanumeric, 'N' = Numeric only, 'S' = English characters only. --*//
	  if (typeof(option) != 'string') {
	    option = 'A';  
	  }
	  else {
	    option = option.trim();
	    
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
			window.crypto.getRandomValues(randomArray);
			
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


//-- Note: 1. Valid values of algorithm are 'AES-GCM' and 'AES-CBC'. --//
//--       2. Data type of 'text' should be a non empty string.      --// 
async function aesEncrypt(algorithm, passphase, text) {
  let result = {};
  
  try {
		if (typeof(algorithm) == "string") {
		  algorithm = algorithm.toUpperCase().trim();
		  
		  if (algorithm != "AES-CBC" && algorithm != "AES-GCM") {
				algorithm = "AES-GCM";
			} 
		}
		else {
			algorithm = "AES-GCM";
		}

    const iv = await getIv(passphase, text);
    // Notes: 
    // 1. If the 'difficulty' of 'grindKey' is changed, all data encrypted by previous value 
    //    of 'difficulty' cannot be decrypted again. i.e. If it is changed, data migration
    //    is needed.
    // 2. Since 'difficulty' will increase number of iteration on 'grindKey' expoentially, 
    //    so system performance will be affected if it is too large. Valid values are integers
    //    from 1 to 10.		
    // 3. The value of 'difficulty' of 'grindKey' in front-end library (i.e. this one) must match 
    //    the value of 'difficulty' of '_grindKey' in back-end library (i.e. cipher_lib.js). The 
    //    reason is same as point (1) mentioned before.
    const hash_key = await grindKey(passphase, 3);		
		const plaintext = new TextEncoder().encode(text);
		
		const key = await window.crypto.subtle.importKey(
		  "raw", hash_key, {name: algorithm}, false, 
		  ["encrypt", "decrypt"]
		);
		
		const encrypted = await window.crypto.subtle.encrypt(
		  {
        name: algorithm,
        iv: iv,
        length: 256
      },
      key,
      plaintext
		);
		
		result = {key: key, iv: iv, encrypted: encrypted};		
	}
	catch(e) {
		throw e;
	}
  
  return result;
}


async function aesDecrypt(algorithm, passphase, iv, encrypted) {
  let result = '';
  
  try {
		if (typeof(algorithm) == "string") {
		  algorithm = algorithm.toUpperCase().trim();
		  
		  if (algorithm != "AES-CBC" && algorithm != "AES-GCM") {
				algorithm = "AES-GCM";
			} 
		}
		else {
			algorithm = "AES-GCM";
		}

    // Notes: 
    // 1. If the 'difficulty' of 'grindKey' is changed, all data encrypted by previous value 
    //    of 'difficulty' cannot be decrypted again. i.e. If it is changed, data migration
    //    is needed.
    // 2. Since 'difficulty' will increase number of iteration on 'grindKey' expoentially, 
    //    so system performance will be affected if it is too large. Valid values are integers
    //    from 1 to 10.		
    // 3. The value of 'difficulty' of 'grindKey' in front-end library (i.e. this one) must match 
    //    the value of 'difficulty' of '_grindKey' in back-end library (i.e. cipher_lib.js). The 
    //    reason is same as point (1) mentioned before.		    
    const hash_key = await grindKey(passphase, 3);
				
		const key = await window.crypto.subtle.importKey(
		  "raw", hash_key, {name: algorithm}, false, 
		  ["encrypt", "decrypt"]
		);
		
		const decrypted = await window.crypto.subtle.decrypt(
			{name: algorithm, iv: iv}, key, encrypted
		);
		
		result = (new TextDecoder('utf-8')).decode(decrypted);
	}
	catch(e) {
		throw e;
	}
  
  return result;
}


async function aesDecryptBase64(algorithm, passphase, iv_b64, encrypted_b64) {
  let result = '';
  
  try {
    let iv = convertBase64IVtoIV(iv_b64);
    let encrypted = base64StringToArrayBuffer(encrypted_b64);
    
    result = await aesDecrypt(algorithm, passphase, iv, encrypted);    
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


async function aesEncryptJSON(algorithm, passphase, text) {
  let result = {};
  
  try {
    let enc_obj = await aesEncrypt(algorithm, passphase, text);
    let iv = enc_obj.iv;                    // It is an Uint8Array
    let encrypted = enc_obj.encrypted;      // It is an ArrayBuffer             
    let iv_json = convertObjectToJsonStr(iv);
    let encrypted_json = convertArrayBufferToJsonStr(encrypted);
    // Note: 1. The data 'enc_obj.key' doesn't include on the 'result'.                                        //
    //       2. 'iv_json' and 'encrypted_json' are stringified JSON object. Actually they are both Uint8Array. //
    result = {iv: iv_json, encrypted: encrypted_json};
  }
  catch(e) {
    throw e;
  }
    
  return result;
}


//-- Note: 1. Valid values of algorithm are 'AES-GCM' and 'AES-CBC'. --//
//--       2. Data type of 'text' should be a non empty string.      --// 
async function aesEncryptWithKeyJSON(algorithm, hash_key, text) {
  let result;	
	
	try {
		const plaintext = (new TextEncoder()).encode(text);
    const key = await importSymmeticKey(hash_key, algorithm, false, ['encrypt']);
		const iv = new Uint8Array(16);
		window.crypto.getRandomValues(iv);
		
		const encrypted = await window.crypto.subtle.encrypt(
			{name: algorithm, iv: iv}, key, plaintext
		);
    
    const iv_json = convertObjectToJsonStr(iv);
    const encrypted_json = convertArrayBufferToJsonStr(encrypted);
		
		result = {iv: iv_json, encrypted: encrypted_json};		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}



// 2024-02-05 DW: Since IV and encrypted message can't be converted to base64 string correctly in client side, //
// i.e. in web browsers. Therefore, function 'aesEncryptBase64' is frozen until this problem has been fixed.   // 
/*
async function aesEncryptBase64(algorithm, passphase, text) {
  let result = {};
  
  try {
    let enc_obj = await aesEncrypt(algorithm, passphase, text);
    let iv = enc_obj.iv;                    // It is an Uint8Array
    let encrypted = enc_obj.encrypted;      // It is an ArrayBuffer         
    let iv_b64 = convertUint8ArrayToBase64Str(enc_obj.iv);
    let encrypted_b64 = arrayBufferToBase64String(enc_obj.encrypted);
    // Note: 1. The data 'enc_obj.key' doesn't include on the 'result'.                      //
    //       2. 'iv_b64' and 'encrypted_b64' are Uint8Array objects in base64 format string. //
    result = {iv: iv_b64, encrypted: encrypted_b64};
  }
  catch(e) {
    throw e;
  }
  
  return result;
}
*/

//-- Note: 1. Valid values of algorithm are 'AES-GCM' and 'AES-CBC'. --//
//--       2. Data type of 'text' should be a non empty string.      --// 
async function symmeticEncrypt(algorithm, text) {
  let result;	
	
	try {
		const plaintext = (new TextEncoder()).encode(text);
		const key = await window.crypto.subtle.generateKey(
			{name: algorithm, length: 256},
			false, ['encrypt', 'decrypt']
		);
		const iv = new Uint8Array(16);
		window.crypto.getRandomValues(iv);
		
		const encrypted = await window.crypto.subtle.encrypt(
			{name: algorithm, iv: iv}, key, plaintext
		);
		
		result = {key: key, iv: iv, encrypted: encrypted};		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


//-- Note: 1. Valid values of algorithm are 'AES-GCM' and 'AES-CBC'. --//
//--       2. Data type of 'text' should be a non empty string.      --// 
//--       3. 'hash_key' is a Uint8Array(32) object.                 --// 
async function symmeticEncryptWithKey(algorithm, hash_key, text) {
  let result;	
	
	try {
		const plaintext = (new TextEncoder()).encode(text);
    const key = await importSymmeticKey(hash_key, algorithm, false, ['encrypt']);
		const iv = new Uint8Array(16);
		window.crypto.getRandomValues(iv);
		
		const encrypted = await window.crypto.subtle.encrypt(
			{name: algorithm, iv: iv}, key, plaintext
		);
		
		result = {key: key, iv: iv, encrypted: encrypted};		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


//-- Note: Valid values of algorithm are 'AES-GCM', 'AES-CBC' and 'AES-KW'. --//
async function symmeticDecrypt(algorithm, key, iv, encrypted) {
	let result;
	
	try {
		const decrypted = await window.crypto.subtle.decrypt(
			{name: algorithm, iv: iv}, key, encrypted
		);
		
		result = (new TextDecoder('utf-8')).decode(decrypted);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


//-- Note: 1. For symmetric key only.                     --//
//--       2. 3rd party library 'hash-wasm' must be used. --// 
async function buildSymmeticRawKey(hashwasm, passphase) {
	let result;
	
	try {
		const salt = new Uint8Array(16);
		window.crypto.getRandomValues(salt);
		const rawKey = await hashwasm.argon2id({
			outputType: 'binary',
			password: passphase,
			salt: salt,
			hashLength: 32,
			parallelism: 1,
			iterations: 3,
			memorySize: 4096,
		});
		
		result = rawKey;
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


//-- Note: For symmetric key only --//
async function importSymmeticKey(key, algorithm, extractable, usages) {
  let result;  
  
  try {
    //-- For symmetric keys, set 'format' to 'raw' to import the key as-is. --//
    //-- Note: 'key' is a 'Uint8Array' object, not text. Any 'result' is a  --//
    //--       'CryptoKey' object.                                          --//  
    result = await window.crypto.subtle.importKey(
               'raw',
               key,
               algorithm,
               extractable, 
               usages
             );  
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function arrayBufferToBase64String(arrayBuffer) {
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


function base64StringToArrayBuffer(b64str) {
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


function convertPemToBinary(pem) {
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
   
  return base64StringToArrayBuffer(encoded);
}


//-- Note: For asymmetric RSA key pairs only --//
async function importKeyFromPem(keyType, pem, algorithm, exportable, usages) {
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

    // Since "pem" has been converted to base64 string and then converted back to string, line
    // break characters are become string "\n", not carriage return characters. Therefore, it
    // needs to be processed here to avoid potential error on next step. 
    pem = pem.replace(/\\n/g, "\n"); 
        
    let keyData = convertPemToBinary(pem);
        
    result = await window.crypto.subtle.importKey(format, keyData, algorithm, exportable, usages);
  }
  catch(e) {
    throw e;    
  }
  
  return result;
}



async function pemFromKey(keyType, key, decoder) {
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


async function rsaEncrypt(algorithm, publicKey, plaintext) {
	let result, text;
	
	try {
		text = new TextEncoder().encode(plaintext);
    result = await window.crypto.subtle.encrypt(algorithm, publicKey, text);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


async function rsaDecrypt(algorithm, privateKey, encrypted) {
	let result, decrypted;
	
	try {
		decrypted = await window.crypto.subtle.decrypt(algorithm, privateKey, encrypted);
    result = new TextDecoder("utf-8").decode(decrypted);		
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


// Notes: 1. Assume passed 'msg' is not null or empty.
//        2. 'encoder' is an object created from library 'arraybuffer-encoding'.
// 
// Remark: This function is phased out, use 'digestData' instead.        
async function digestMessage(msg, encoder) {
	let message, result;
	
	try {
    message = (new TextEncoder()).encode(msg);
    result = encoder.Hex.Encode(await window.crypto.subtle.digest('SHA-256', message));
	}
	catch(e) {
		throw e;
	}           
  
  return result;
}


function textToArrayBuffer(str) {
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


async function digestData(algorithm, data) {
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
		
		buffer = await window.crypto.subtle.digest(algorithm, textToArrayBuffer(data));
		result = arrayBufferToBase64String(buffer);
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


function base64ToBytes(base64) {
	let result;
	
	try {
    const binString = atob(base64);  
    result = Uint8Array.from(binString, (m) => m.codePointAt(0));
  }
  catch(e) {
		throw e;
	}
	
	return result;
}


function bytesToBase64(bytes) {
	let result;
	
	try {
	  const binString = String.fromCodePoint(...bytes);
	  result = btoa(binString);
  }
  catch(e) {
		throw e;
	}
	
	return result;
}


function convertObjectToBase64Str(base64) {
	let result = '';
	
  try {
		result = new TextDecoder().decode(base64ToBytes(base64));
		result = result.replace(/\\n/g, "\n");      // To avoid potential error
		
		// To eliminate the openning and the closing '"' characters, they should not //
		// appear in a string.
		if (result.substring(0, 1) == '"' && result.substring(result.length - 1) == '"') {
			result = result.replace(/\"/g, '');
		}		
	}
	catch(e) {
	  throw e;	
	}	
	
	return result;
}
 

//-- Note: 'object' must be a Uint8Array --//
function convertUint8ArrayToBase64Str(object) {
  let byteString = '';
  
  try {
	  for (let i = 0; i < object.byteLength; i++) {
	    byteString += String.fromCharCode(object[i]);
	  }
  }
  catch(e) {
		throw e;
	}
  
  return btoa(byteString);
}


function convertBase64StrToObject(base64) {
	let result;
	
	try {
		let objstr = convertObjectToBase64Str(base64);
		result = JSON.parse(objstr);				
	}
	catch(e) {
		throw e;
	}
	
	return result;
}


async function verifySignature(algorithm, verify_key, signature, original_text) {
	let result;
	
	try {
		result = await window.crypto.subtle.verify(
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


// Note: This function has a limitation of given 'obj', which must be in
//       format {'0': number0, '1': number1, ....., '15': number15}. 
function convertHashObjectToIV(obj) {
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


function convertBase64IVtoIV(iv_b64) {
  let iv_obj, result;
  
  try {
    iv_obj = convertBase64StrToObject(iv_b64);
    result = convertHashObjectToIV(iv_obj);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function convertArrayBufferToUint8Array(array_buffer) {
  let result;
  
  try {
    result = new Uint8Array(array_buffer);
  }
  catch(e) {
    throw e;
  }
  
  return result;
}


function convertObjectToJsonStr(object) {
  let result;
  
  try {
    result = JSON.stringify(object);
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function convertArrayBufferToJsonStr(array_buffer) {
  let result;
  
  try {
    result = convertObjectToJsonStr(convertArrayBufferToUint8Array(array_buffer));
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


function base64Encode(u8) {
  return btoa(String.fromCharCode.apply(null, u8))
}

function base64Decode(str) {
  return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)))
}


async function grindKey(password, difficulty) {
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
    
    return await pbkdf2(password, password + password, Math.pow(2, difficulty), 32, 'SHA-256');
  }
  catch(e) {
    throw e;
  }
}


async function getIv(password, data) {
  try {
    const randomData = base64Encode(window.crypto.getRandomValues(new Uint8Array(16)))
    return await pbkdf2(password + randomData, data + (new Date().getTime().toString()), 1, 16, 'SHA-256')
  }
  catch(e) {
    throw e;
  }
}


async function pbkdf2(message, salt, iterations, keyLen, algorithm) {
  try {
    const msgBuffer = new TextEncoder('utf-8').encode(message);
    const msgUint8Array = new Uint8Array(msgBuffer);
    const saltBuffer = new TextEncoder('utf-8').encode(salt);
    const saltUint8Array = new Uint8Array(saltBuffer);
  
    const key = await window.crypto.subtle.importKey('raw', msgUint8Array, {
      name: 'PBKDF2'
    }, false, ['deriveBits']);
  
    const buffer = await window.crypto.subtle.deriveBits({
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


function getRandomInt(min, max) {
  let result = 0;
  
  try {
    if (Number.isInteger(min) == false || Number.isInteger(max) == false) {
      throw new Error("Invalid parameter is given");
    }
    
    if (min > max) {
      throw new Error("Given parameters are incorrect");
    } 
  
    min = Math.ceil(min);
    max = Math.floor(max);
    result = Math.floor(Math.random() * (max - min + 1)) + min;
  }
  catch(e) {
    throw e;
  }
  
  return result;  
}


async function prepareRollingKey(key_len) {
  let is_iOS, new_rolling_key, cur_rolling_key, aes_key, roll_rec, roll_rec_json, roll_rec_sum, enc_roll_rec;       
  
  try {
    is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
    aes_key = (is_iOS)? Cookies.get("aes_key") : getLocalStoredItem("aes_key");

    if (typeof(aes_key) == "string" && aes_key.length >= key_len) {    
      new_rolling_key = generateTrueRandomStr('A', getRandomInt(32, 64));      
      cur_rolling_key = (is_iOS)? Cookies.get("rolling_key") : getLocalStoredItem("rolling_key"); 
      
      roll_rec = {cur_rolling_key: cur_rolling_key, new_rolling_key: new_rolling_key};              
      roll_rec_json = JSON.stringify(roll_rec);           
      roll_rec_sum = await digestData("SHA-256", roll_rec_json);           
      enc_roll_rec = await aesEncryptJSON("AES-GCM", aes_key, roll_rec_json);
      
      document.getElementById("roll_rec").value = enc_roll_rec.encrypted;
      document.getElementById("iv_roll_rec").value = enc_roll_rec.iv;
      document.getElementById("roll_rec_sum").value = roll_rec_sum;   
      
      aes_key = null;    
    }
    else {
      throw new Error("Session key is lost or invalid!");
    }
  }
  catch(e) {
    throw e;
  }
}


async function switchToPage(form_id, url, key_len) {
  try {
    await prepareRollingKey(key_len);
    document.getElementById(form_id).action = url;
    document.getElementById(form_id).submit();
  }
  catch(e) {
    throw e;
  }
}
