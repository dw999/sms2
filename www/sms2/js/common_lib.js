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
// File name: common_lib.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2018-06-04      DW              Common Javascript library for node.js front-end.
// V1.0.01       2018-09-10      DW              Add non-jQuery scrolling function.
// V1.0.02       2018-09-19      DW              Add web browser local storage operating functions. Note: It seems that iOS doesn't
//                                               support local storage as well as other platforms.
// V1.0.03       2023-01-13      DW              Add functions padLeft, padRight, sayCurrentDateTime, sayCurrentTime, stripSecondAway
//                                               and sleep.
// V1.0.04       2024-03-05      DW              Add function processQuotationMarks. 
// V1.0.05       2024-03-20      DW              Add functions base64Encode and base64Decode. 
// V1.0.06       2026-01-29      DW              Refine scope of variables declare in this library.
//#################################################################################################################################

function allTrim(s) {
  if (typeof s != "string") { return s; }
      
  while (s.substring(0,1) == ' ') {
    s = s.substring(1, s.length);
  }
  while (s.substring(s.length-1, s.length) == ' ') {
    s = s.substring(0, s.length-1);
  }
      
  return s;
}      


function setLocalStoredItem(s_key, s_value) {
  let err = "";
  
  if (typeof(Storage) != undefined) {
    try {
      window.localStorage.setItem(s_key, s_value);  
    } catch(e) {
      err = e;
    }
  }
  else {
    err = "localStorage is not supported by this browser";
  }
  
  return err;
}


function getLocalStoredItem(s_key) {
  let result;
  
  if (typeof(Storage) != undefined) {
    try {
      result = window.localStorage.getItem(s_key);  
    } catch(e) {
      result = undefined;
    }      
  }
  else {
    result = undefined;
  }
  
  return result;
}


function deleteLocalStoredItem(s_key) {
  let err = "";
  
  if (typeof(Storage) != undefined) {
    try {
      window.localStorage.removeItem(s_key);  
    } catch(e) {
      err = e;
    }    
  }
  else {
    err = "Local storage is not supported by this browser";
  }
  
  return err;
}


function clearLocalStoredData() {
  let err = "";
  
  if (typeof(Storage) != undefined) {
    try {
      localStorage.clear();  
    } catch(e) {
      err = e;
    }    
  }
  else {
    err = "Local storage is not supported by this browser";
  }
  
  return err;
}


function padLeft(str, size, filler) {
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


function padRight(str, size, filler) {
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


function sayCurrentDateTime() {
  let today, curr_datetime;
  
  try {
    today = new Date();
    curr_datetime = today.getFullYear() + "-" + padLeft(today.getMonth() + 1, 2, "0") + "-" + padLeft(today.getDate(), 2, "0") + " " + 
                    padLeft(today.getHours(), 2, "0") + ":" + padLeft(today.getMinutes(), 2, "0") + ":" + padLeft(today.getSeconds(), 2, "0");                        
  }
  catch(e) {
    throw e;
  }
  
  return curr_datetime;  
} 


function sayCurrentTime() {
  let today, curr_time;
  
  try {
    today = new Date();
    curr_time = padLeft(today.getHours(), 2, "0") + ":" + padLeft(today.getMinutes(), 2, "0") + ":" + padLeft(today.getSeconds(), 2, "0");                        
  }
  catch(e) {
    throw e;
  }
  
  return curr_time;  
} 


function stripSecondAway(date_time, type) {
  let dt_parts, time, time_parts, result;
  
  try {
    if (type == "DT") {        // Data type is DATETIME
      dt_parts = date_time.split(" ");
      time = allTrim(dt_parts[1]);
      time_parts = time.split(":");    
      result = dt_parts[0] + " " + time_parts[0] + ":" + time_parts[1];
    }
    else {                     // Then assume data type is TIME  
      time = allTrim(date_time);
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


//--------------- 
// Note: Calling function must be an async function, and keyword 'await' must be used. Please see demo below:
//
// e.g.) async function demo(sec) {
//         .... do something;
//         await sleep(sec * 1000);
//       } 
//--------------- 
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function _getRandomInt(max) {
	return Math.floor(Math.random() * Math.floor(max));
}


//-- This function is phased out, and replaced by generateTrueRandomStr in crypto-lib.js --//
function _generateRandomStr(option, max_len) {
  let result = '';
  let ascii_list = new Array();
  let max_ascii_value = 0; 
  let stop_run = 0;
  let cnt = 0;

	//*-- Valid options are: 'A' = Alphanumeric, 'N' = Numeric only, 'S' = English characters only. --*//
  if (typeof(option) != 'string') {
    option = 'A';  
  }
  else {
    option = allTrim(option);
    
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
    for (let i = 48; i <= 57; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 57;    
  } 
  else if (option == 'S') {
    for (let i = 65; i <= 90; i++) {
    	ascii_list.push(i);
    }

    for (let i = 97; i <= 122; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 122;
  }
  else {
    for (let i = 48; i <= 57; i++) {
    	ascii_list.push(i);
    }

    for (let i = 65; i <= 90; i++) {
    	ascii_list.push(i);
    }

    for (let i = 97; i <= 122; i++) {
    	ascii_list.push(i);
    }

    max_ascii_value = 122;
  }
  
  while (stop_run == 0) {
    let this_ascii = _getRandomInt(max_ascii_value);
    let valid_value = 0;

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


//-- This function is phased out, and replaced by generateTrueRandomStr in crypto-lib.js --//
function generateRandomStr(option, max_len) {
  return _generateRandomStr(option, max_len);
}


function processQuotationMarks(text) {
  let result = text;
  
  result = result.replace(/"/g, '“');
  result = result.replace(/'/g, '‘');
  
  return result;
}


function base64Encode(u8) {
  return btoa(String.fromCharCode.apply(null, u8))
}


function base64Decode(str) {
  return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)))
}

