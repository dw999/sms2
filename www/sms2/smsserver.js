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
// File name: smsserver.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V2.0.00       2022-04-12      DW              A web based secure instant messaging system using technologies Node.js and websocket,
//                                               which is rebuilt from previous experience in order to achieve better performance and
//                                               handle more concurrent users. Previous version is developed by Perl and stateless 
//                                               periodic query method, which is proved with poor performance and unable to handle 
//                                               large concurrent user connections.
// 
// V2.0.01       2022-08-01      DW              Use RabbitMQ broker to inform users on all SMS server instances to refresh messages.
//
// V2.0.02       2022-08-29      DW              Use database pool to speed up database connection operations. 
//
// V2.0.03       2022-08-31      DW              Add an additional encryption layer (AES-256) for all text messages exchange between  
//                                               client and server sides. 
//
// V2.0.04       2022-09-10      DW              Try to add an additional encryption layer (RSA 2048 bit) in login process to protect   
//                                               sent user name and password.
//
// V2.0.05       2022-09-22      DW              After more than 10 days study, I can't find a suitable RSA library on browser side
//                                               to encrypt data and pass to the back-end decrypt successfully. Therefore, RSA encryption
//                                               approaching is given up now, but use AES-256 encryption method to protect sent data
//                                               in the login process. It is not ideal, but better than nothing.   
//
// V2.0.06       2023-04-27      DW              Fix a bug on "/join_us", "add_user" and "input_user_data" by escape passed token.
//
// V2.0.07       2023-08-08      DW              Standardize all console output messages format issued from this module with date and time. 
//
// V2.0.08       2023-10-13      DW              - Use RSA encryption to protect client generated AES key in login process. However, Firefox
//                                                 can't run the newly added javascript program, so I drop Firefox support for SMS 2.x.
//                                               - Use client generated AES key to encrypt and decrypt uploading and downloading messages
//                                                 sending to and received from the server, instead to use session code stored on the cookie.
//                                               - Use RSA encryption to protect request-to-join function.
//                                               - Use RSA encryption to protect user creation functions (for all connection modes). 
//
// V2.0.09       2023-11-16      DW              - Replace 'generateRandomStr' by 'cipher.generateTrueRandomStr' for session code generation
//                                                 on webenv_lib.js
//                                               - Refine websocket upgrade request processing.
//
// V2.0.10       2023-12-10      DW              Freeze a protential dangerous unused function '/push_aes_key'.
//
// V2.0.11       2024-01-22      DW              Replace all AES-256 encryption and decryption functions by built-in libraries from
//                                               Node.js and Web Crypto APIs. i.e. No third party cryptographic libraries are used.
//
// V2.0.12       2024-03-21      DW              Use a post quantum computing era cryptographic method 'Crystals Kyber' to protect the
//                                               RSA encrypted session key generated on client side as login to the SMS. RSA method may be 
//                                               removed later when quantum computer is widely used and RSA is no longer secure, but now
//                                               RSA is used in parallel with Crystals Kyber method.
//
// V2.0.13       2024-04-16      DW              Use 'Crystals Kyber' method to protect processes "request to join" and "user creation".
//
// V2.0.14       2024-04-30      DW              Fix a bug on route '/add_private_group', which show message deletion period as message
//                                               deletion option is 'off'. Now, I set deletion option to 'on' by default.
//
// V2.0.15       2025-06-24      DW              Include 'user_id' into session validation checking.
//#################################################################################################################################
  
"use strict";
const express = require('express');
const ws = require('ws');
const cookie = require('cookie');      // Important note: 'cookie' is required for websocket upgrade checking process, don't remove it.              
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser');
const fileUpload = require('express-fileupload');
const SimpleHashTable = require('simple-hashtable');
const DeviceDetector = require('node-device-detector');
const ClientHints = require('node-device-detector/client-hints')
const wev = require('./lib/webenv_lib.js');
const smslib = require('./lib/sms_lib.js');
const msglib = require('./lib/msg_lib.js');
const dbs = require('./lib/db_lib.js');
const cipher = require('./lib/cipher_lib.js');
//-- Notificator to pass notices to all SMS server instances via RabbitMQ broker. --//
//-- Note: RabbitMQ broker login parameters are put on the file './etc/config.js' --//
const notificator = require('./lib/notificatorSingleton');

//-- Define constants --//
const COOKIE_PDA = 'PDA_USER';
const COOKIE_MSG = 'MSG_USER';
const COMP_NAME = 'PDA Tools Corp.';


var port = 8444;
var host = '127.0.0.1';
process.argv.forEach((val, index) => {
  if (val.match(/port=/i)) {
  	var params = val.split("=");
  	var data = parseInt(params[1], 10);
  	if (data > 0 && data <= 65535) {
      port = data;
  	}
  }
  
  if (val.match(/ip=/i)) {
    var params = val.split("=");
    var data = params[1];
    if (isValidIp(data)) {
      host = data;
    }
  }
});


function isValidIp(ip) {
  var valid = true;
  var abcd = ip.split(".");
  
  if (abcd.length != 4) {
    valid = false;
  } 
  else {
    for (var i = 0; i < abcd.length; i++) {
      var data = parseInt(abcd[i], 10);
      
      if (isNaN(data)) {
        valid = false;
        break;
      }      
      else {
        if (data < 0 || data > 255) {
          valid = false;
          break;
        }
      }
    }
  }
  
  return valid;
}


const app = express();

//-- If true, the client’s IP address can be forwarded by the Nginx reverse proxy server. --//
app.set('trust proxy', true);

//-- Disable X-Powered-By header. Note: Disabling the X-Powered-By header does not prevent a sophisticated attacker from determining that an --//
//-- app is running Express. It may discourage a casual exploit, but there are other ways to determine an app is running Express.            --// 
app.disable('x-powered-by');

//-- Define static resources (such as library files) location for express --// 
app.use(express.static(__dirname));

//-- Web page parser to get POST parameters --//
app.use(bodyParser.json());  // for parsing application/json 
app.use(bodyParser.urlencoded({extended: true}));

//-- Cookie parser --//
app.use(cookieParser());

//-- For file uploading --//
app.use(fileUpload({
  useTempFiles: true,
  tempFileDir: '/tmp/'  
}));

//-- Define middleware for client device detection --//
//-- Consult the following URLs for more details:                                             --// 
//-- 1. https://github.com/sanchezzzhak/node-device-detector/blob/HEAD/docs/EXPRESS_SERVER.MD --//
//-- 2. https://www.npmjs.com/package/node-device-detector                                    --//  
const middlewareDetect = (req, res, next) => {
  const deviceDetector = new DeviceDetector;
  const clientHints = new ClientHints;
  const useragent = req.headers['user-agent']; 
  const clientHintsData = clientHints.parse(res.headers);

  req.useragent = useragent;
  req.device = deviceDetector.detect(useragent, clientHintsData);
  req.bot = deviceDetector.parseBot(useragent);
  next();
};

//-- attach middleware --//
app.use(middlewareDetect);

//-- Global variables --//
var clients = new SimpleHashTable();
//-- Open database pool --//
var msg_pool = dbs.createConnectionPool('COOKIE_MSG', 20);
var pda_pool = dbs.createConnectionPool('COOKIE_PDA', 20);


app.get('/', (req, res) => {
	let http_user_agent = req.headers['user-agent'];
  let message = "Firefox (include Tor browser) is not supported in this site, please use another web browser. You will be redirected to our recommanded site.";

  if (http_user_agent.match(/Firefox/gi)) {
		// 2023-10-13 by DW:                                                                                                      //
		// Since Firefox (include Tor browser) isn't compatible with newly added javascript programs, which are used for security //
		// enhancement. After balance the application compatibility and security, I make a hard decision to drop Firefox support  // 
		// until I find a way to get it done in Firefox.                                                                          //  
		let result = smslib.getRandomSiteForVisitor(msg_pool);
		
		result.then((url) => {		
			let html = `<script>
										alert("${message}"); 
										window.location.href = "${url}";
									</script>`;
	
			res.send(html);       
	  }).catch((error) => {
			let html = `<script>
										alert("${message}"); 
										window.location.href = "https://www.microsoft.com";
									</script>`;
	
			res.send(html);       			
		}); 
	}	
	else {
	  let result = smslib.showLoginPage(msg_pool);
	    
	  result.then((html) => {
	    res.send(html); 
	  }).catch((error) => {
	    smslib.consoleLog(error);
	    
      let html = `<script>
                    alert("Error is found, please try again. If this problem insists, contact us."); 
                    var url = window.location.href;
                    var host = url.split('/');
                    window.location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);    
	  });
  }
});


app.post('/go-login', (req, res) => {
  let oper_mode = req.body.oper_mode;
  let kyber_id = req.body.kyber_id;
  let kyber_ct = req.body.kyber_ct;                 // Secret text for Kyber to obtain the shared key (It is in base64 format)
	let key_id = req.body.key_id;  
  let keycode_iv = req.body.keycode_iv;             // IV of the RSA encrypted and AES-256 encrypted 'keycode' (It is a JSON string).
  let keycode = req.body.keycode;                   // RSA encrypted then AES-256 encrypted once more with Kyber secret key. (It is a JSON string). 
  let cs_public_sha256sum = req.body.cs_public_sha256sum;
  let aes_algorithm = req.body.aes_algorithm;       // AES-256 algorithm used
  let username = req.body.e_user;                   // AES-256 encrypted (it is a JSON string)                         
  let password = req.body.e_pass;                   // AES-256 encrypted (it is a JSON string)     
  let iv_user = req.body.iv_user;                   // Generated IV of AES-256 encryption for username (it is a JSON string)
  let iv_pass = req.body.iv_pass;                   // Generated IV of AES-256 encryption for password (it is a JSON string)
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  let decrypted_user, decrypted_pass;
  let err_msg = '';
    
  if (oper_mode == 'S') {
	  let result = smslib.checkClientSidePubKeySha256Sum(msg_pool, key_id, cs_public_sha256sum); 
	  result.then((is_valid) => {
			if (is_valid) {
				let result = smslib.extractClientAESkey(msg_pool, kyber_id, kyber_ct, aes_algorithm, key_id, keycode_iv, keycode);
				result.then((aes_key) => {		
			    //-- Decrypt 'username' and 'password' in here --// 
			    let result = cipher.aesDecryptJSON(aes_algorithm, aes_key, iv_user, username);
			    result.then((this_user) => {
						decrypted_user = this_user;
						
				    let result = cipher.aesDecryptJSON(aes_algorithm, aes_key, iv_pass, password);
				    result.then((this_pass) => {
							decrypted_pass = this_pass;
							
				      let result = smslib.authenticateLoginUser(msg_pool, pda_pool, decrypted_user, decrypted_pass, aes_key, http_user_agent, ip_addr);				      
				      result.then((data) => {
				        let ok = data.ok;
				        let msg = data.msg;
				        let url = data.url;
				        
				        if (ok == 1) {      
				          res.redirect(url);
				        }
				        else {
				          let html = `<script>
				                        alert("${msg}"); 
				                        var url = window.location.href;
				                        var host = url.split('/');
				                        location.href = host[0] + '//' + host[2] + '/';
				                      </script>`;
				      
				          res.send(html);        
				        }
				      }).catch((error) => {
				        smslib.consoleLog(error);
				  
				        let html = `<script>
				                      alert("Login process is failure, please try again."); 
				                      var url = window.location.href;
				                      var host = url.split('/');
				                      location.href = host[0] + '//' + host[2] + '/';
				                    </script>`;
				      
				        res.send(html);
				      });    
						}).catch((error) => {
				      err_msg = 'Password is lost due to decryption failure!';
				      smslib.consoleLog(err_msg);
				      
				      let html = `<script>
				                    alert("Password is lost on back-end processing, please try again."); 
				                    var url = window.location.href;
				                    var host = url.split('/');
				                    location.href = host[0] + '//' + host[2] + '/';
				                  </script>`;
				      
				      res.send(html);				      						
						});						
					}).catch((error) => {
			      err_msg = 'Username is lost due to decryption failure!';
			      smslib.consoleLog(err_msg);
			      
			      let html = `<script>
			                    alert("Username is lost on back-end processing, please try again."); 
			                    var url = window.location.href;
			                    var host = url.split('/');
			                    location.href = host[0] + '//' + host[2] + '/';
			                  </script>`;
			      
			      res.send(html);			      						
					});			    			    			    
				}).catch((error) => {
					smslib.consoleLog(error);
					
			    let html = `<script>
			                  alert("Unable to extract the client generated AES key. Error: ${error}"); 
			                  var url = window.location.href;
			                  var host = url.split('/');
			                  location.href = host[0] + '//' + host[2] + '/';
			                </script>`;
			  
			    res.send(html);                    															
				});
			}
			else {
		    let html = `<script>
		                  alert("Warning: The checksum of the public key is invalid, login process is aborted. You may be under Man-In-The-Middle attack!"); 
		                  var url = window.location.href;
		                  var host = url.split('/');
		                  location.href = host[0] + '//' + host[2] + '/';
		                </script>`;
		  
		    res.send(html);                    														
			}
		}).catch((error) => {
			smslib.consoleLog(error);
			
	    let html = `<script>
	                  alert("Login process is aborted due to error: ${error}"); 
	                  var url = window.location.href;
	                  var host = url.split('/');
	                  location.href = host[0] + '//' + host[2] + '/';
	                </script>`;
	  
	    res.send(html);                    															
		});
  }
  else {
    res.redirect('/');     
  }
});


app.get('/request-to-join', (req, res) => {
  let result = smslib.printRequestToJoinForm(msg_pool);
  result.then((html) => {
    res.send(html);
  }).catch((error) => {
    smslib.consoleLog(error);
    
    let html = `
    <script>
      alert("Sorry, system is very busy right now, please try again later."); 
      var url = window.location.href;
      var host = url.split('/');
      location.href = host[0] + '//' + host[2] + '/';
    </script>      
    `;
    
    res.send(html);
  });
});


app.post('/request-to-join', (req, res) => {
	let algorithm = req.body.algorithm;                     // AES algorithm 
	let iv_name = req.body.iv_name;
  let e_name = req.body.e_name;
  let iv_email = req.body.iv_email;
  let e_email = req.body.e_email;
  let iv_refer = req.body.iv_refer;
  let e_refer = req.body.e_refer;
  let iv_remark = req.body.iv_remark;
  let e_remark = req.body.e_remark;
  let oper_mode = req.body.oper_mode;
  let cs_public_sha256sum = req.body.cs_public_sha256sum;  
  let key_id = req.body.key_id;
  let key_iv = req.body.key_iv;
  let key = req.body.key;                                  // RSA encrypted JSON string then encrypted by AES-256 
  let kyber_id = req.body.kyber_id;
  let kyber_ct = req.body.kyber_ct;
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;  
  let data_set_ok = true;
  let name = '';
  let email = '';
  let refer = '';
  let remark = '';
  let tg_id = '';
    
  if (oper_mode == 'S') {
	  let result = smslib.checkClientSidePubKeySha256Sum(msg_pool, key_id, cs_public_sha256sum); 
	  result.then((is_valid) => {
			if (is_valid) {
				let result = smslib.extractClientAESkey(msg_pool, kyber_id, kyber_ct, algorithm, key_id, key_iv, key);
				result.then((aes_key) => {
			    //-- Decrypt data (begin) --//
			    let data = {iv_name: iv_name, e_name: e_name, iv_email: iv_email, e_email: e_email, iv_refer: iv_refer, e_refer: e_refer, 
						          iv_remark: iv_remark, e_remark: e_remark};
			              
			    let result = smslib.decryptRequestToJoinData(algorithm, aes_key, data);
			    
			    result.then((dec_obj) => {
						name = dec_obj.name;
						email = dec_obj.email;
						refer = dec_obj.refer;
						remark = dec_obj.remark;
						            
			      let result = msglib.checkReferrer(msg_pool, refer);
			      result.then((retval) => {
			        if (retval.is_trusted) {
			          if (email == refer && retval.user_role < 2) {
			            //-- Trusted user cannot self register a new user account, but system administrator is allowed to do so. --//
			            let html = `
			            <script>
			              alert("You should not self register a new user account."); 
			              var url = window.location.href;
			              var host = url.split('/');
			              location.href = host[0] + '//' + host[2] + '/';
			            </script>      
			            `;
			            
			            res.send(html);        
			          }
			          else {
			            tg_id = retval.tg_id;
			            
			            let result = msglib.saveApplicantInfo(msg_pool, name, email, refer, remark);
			            result.then((token) => {
			              if (token != '') {
			                
			                let result = msglib.informReferrerToApproval(msg_pool, name, refer, remark, token, tg_id);
			                result.then((html) => {
			                  res.send(html);
			                }).catch((error) => {
												smslib.consoleLog(error);
												
			                  let html = `
			                  <script>
			                    alert("Hi ${name}, the system fails to send your registration for approval, please try again"); 
			                    var url = window.location.href;
			                    var host = url.split('/');
			                    location.href = host[0] + '//' + host[2] + '/request-to-join';
			                  </script>                    
			                  `;
			                                  			                  
			                  let result = smslib.logSystemEvent(msg_pool, 0, error, 'Unable to inform referrer to approve applicant record', http_user_agent);
			                  result.then((ok) => {
			                    res.send(html);
			                  }).catch((error) => {
			                    res.send(html);
			                  });                
			                });              
			              }
			              else {
			                let html = `
			                <script>
			                  alert("Error is found during processing your registration, please try again."); 
			                  var url = window.location.href;
			                  var host = url.split('/');
			                  location.href = host[0] + '//' + host[2] + '/request-to-join';
			                </script>                    
			                `;
			                
			                res.send(html);
			              }
			            }).catch((error) => {
			              let html = `
			              <script>
			                alert("Hi ${name}, your registration is failure, please try again."); 
			                var url = window.location.href;
			                var host = url.split('/');
			                location.href = host[0] + '//' + host[2] + '/request-to-join';
			              </script>                    
			              `;
			              
			              smslib.consoleLog(error);              
			              let result = smslib.logSystemEvent(msg_pool, user_id, error, 'Unable to create applicant record', http_user_agent);
			              result.then((ok) => {
			                res.send(html);
			              }).catch((error) => {
			                smslib.consoleLog(error);
			                res.send(html);
			              });
			            });
			          }
			        }
			        else {
			          //-- Just pretend the registration is OK --//
			          let result = smslib.printRegistedOkPage(msg_pool, name);
			          result.then((html) => {
			            res.send(html);
			          }).catch((error) => {
			            smslib.consoleLog(error);
			            
			            let html = `
			            <script>
			              alert("Hi ${name}, your registration has been sent to approval."); 
			              var url = window.location.href;
			              var host = url.split('/');
			              location.href = host[0] + '//' + host[2] + '/';
			            </script>      
			            `;
			            
			            res.send(html);                    
			          });
			        }
			      }).catch((error) => {
			        smslib.consoleLog(error);
			        
			        let html = `
			        <script>
			          alert("System error is found during operation, please try again."); 
			          var url = window.location.href;
			          var host = url.split('/');
			          location.href = host[0] + '//' + host[2] + '/request-to-join';
			        </script>      
			        `;
			        
			        res.send(html);        
			      });      
					}).catch((error) => {
						smslib.consoleLog(error);
						
			      let html = `
			      <script>
			        alert("At least one data sent to the server is lost, please try again."); 
			        var url = window.location.href;
			        var host = url.split('/');
			        location.href = host[0] + '//' + host[2] + '/request-to-join';
			      </script>      
			      `;
			      
			      res.send(html);						
					});
				}).catch((error) => {
					smslib.consoleLog(error);
					
			    let html = `<script>
			                  alert("Client generated secure key is lost, please try again or contact your referrer."); 
			                  var url = window.location.href;
			                  var host = url.split('/');
			                  location.href = host[0] + '//' + host[2] + '/request-to-join';
			                </script>`;
			  
			    res.send(html);                    																				
				});
			}
			else {
		    let html = `<script>
		                  alert("Warning: The checksum of the public key is invalid, the process is aborted. You may be under Man-In-The-Middle attack!"); 
		                  var url = window.location.href;
		                  var host = url.split('/');
		                  location.href = host[0] + '//' + host[2] + '/request-to-join';
		                </script>`;
		  
		    res.send(html);                    																	
		  }				
		}).catch((error) => {
			smslib.consoleLog(error);
			
	    let html = `<script>
	                  alert("The process is aborted due to error, please try again or contact your referrer."); 
	                  var url = window.location.href;
	                  var host = url.split('/');
	                  location.href = host[0] + '//' + host[2] + '/request-to-join';
	                </script>`;
	  
	    res.send(html);                    																		
		});    
  }
  else {
    res.redirect('/'); 
  }
});


app.get('/join_us', (req, res) => {
  var decision = (typeof(req.query.S) == 'undefined')? '' : req.query.S;
  var token = (typeof(req.query.tk) == 'undefined')? '' : req.query.tk;
  
  if ((decision == 'A' || decision == 'R') && token != '') {
    //-- Note: 1. Original token contains no space characters, so that all space characters are actually '+'. --//
    //--       2. The saved token has been escaped. Therefore, the passed token must be escaped also.         --//              
    token = token.replace(/ /g, '+');
    token = escape(token);  
            
    if (!wev.sqlInjectionDetect(token)) { 
      var result = msglib.applicantApproval(msg_pool, decision, token);
      
      result.then((retval) => {
        if (retval.ok) {
          var msg = (decision == 'A')? "Applicant is accepted, and confirmation email has been sent to him/her." : "Applicant is rejected";
          
          var html = `
          <script>
            alert("${msg}"); 
            var url = window.location.href;
            var host = url.split('/');
            location.href = host[0] + '//' + host[2] + '/';
          </script>      
          `;
          
          res.send(html);                                                                                                      
        }
        else {
          var html = `
          <script>
            alert("${retval.msg}"); 
            var url = window.location.href;
            var host = url.split('/');
            location.href = host[0] + '//' + host[2] + '/';
          </script>      
          `;
          
          res.send(html);                                                          
        }                    
      }).catch((error) => {
        smslib.consoleLog(error);
        
        var html = `
        <script>
          alert("Error is found on applicant approval process. Error: ${error}"); 
          var url = window.location.href;
          var host = url.split('/');
          location.href = host[0] + '//' + host[2] + '/';
        </script>      
        `;
        
        res.send(html);                                    
      });                  
    }
    else {
      //-- The sign of SQL injection attack is found, switch this guy away. --//
      var result = smslib.selectSiteForHacker(msg_pool);
      
      result.then((url) => {
        res.redirect(url);
      }).catch((error) => {
        smslib.consoleLog(error);
        res.redirect('https://www.microsoft.com');
      });
    }
  }
  else {
    //-- Arbitrary attack is found, switch this guy away. --//
    var result = smslib.selectSiteForHacker(msg_pool);
    
    result.then((url) => {
      res.redirect(url);
    }).catch((error) => {
      smslib.consoleLog(error);
      res.redirect('https://www.microsoft.com');
    });
  }
});


app.get('/add_user', (req, res) => {
  let token = (typeof(req.query.tk) != 'string')? '' : req.query.tk;
	let http_user_agent = req.headers['user-agent'];

  if (http_user_agent.match(/Firefox/gi)) {
		// 2023-10-13 by DW:                                                                                                      //
		// Since Firefox (include Tor browser) isn't compatible with newly added javascript programs, which are used for security //
		// enhancement. After balance the application compatibility and security, I make a hard decision to drop Firefox support  // 
		// until I find a way to get it done in Firefox.                                                                          //
		res.redirect('/');  
	}	
	else {  
	  //-- Note: 1. Original token contains no space characters, so that all space characters are actually '+'. --//
	  //--       2. Stored token is on escaped format.                                                          --//
	  token = token.replace(/ /g, '+');
	  token = escape(token);
	
	  if (wev.allTrim(token) != '') {
	    if (!wev.sqlInjectionDetect(token)) {
	      let result = msglib.checkApplicantInfo(msg_pool, token);
	      
	      result.then((retval) => {        
	        if (retval.ok) {
	          res.redirect(`/input_user_data?apply_id=${retval.apply_id}&tk=${token}`);
	        }
	        else {
	          if (retval.err_type != 4) {
	            let html = `
	            <script>
	              alert("${retval.msg}"); 
	              var url = window.location.href;
	              var host = url.split('/');
	              location.href = host[0] + '//' + host[2] + '/';
	            </script>              
	            `;
	            
	            res.send(html);
	          }
	          else {            
	            //-- Hacker is guessing token randomly, switch this guy away. --//
	            let result = smslib.selectSiteForHacker(msg_pool);
	            
	            result.then((url) => {
	              let html = `
	              <script>
	                alert("${retval.msg}"); 
	                location.href = '${url}';
	              </script>              
	              `;
	              
	              res.send(html);
	            }).catch((error) => {
	              smslib.consoleLog(error);
	              
	              let html = `
	              <script>
	                alert("${retval.msg}"); 
	                location.href = 'https://www.microsoft.com';
	              </script>              
	              `;
	              
	              res.send(html);
	            });    
	          }        
	        }
	      }).catch((error) => {
	        smslib.consoleLog(error);
	        
	        let html = `
	        <script>
	          alert("System error is found, please try again later."); 
	          var url = window.location.href;
	          var host = url.split('/');
	          location.href = host[0] + '//' + host[2] + '/';
	        </script>              
	        `;
	        
	        res.send(html);
	      });      
	    }
	    else {
	      //-- The sign of SQL injection attack is found, switch this guy away. --//
	      let result = smslib.selectSiteForHacker(msg_pool);
	      
	      result.then((url) => {
	        res.redirect(url);
	      }).catch((error) => {
	        smslib.consoleLog(error);
	        res.redirect('https://www.microsoft.com');
	      });      
	    }
	  }
	  else {
	    //-- Arbitrary attack is found, switch this guy away. --//
	    let result = smslib.selectSiteForHacker(msg_pool);
	    
	    result.then((url) => {
	      res.redirect(url);
	    }).catch((error) => {
	      smslib.consoleLog(error);
	      res.redirect('https://www.microsoft.com');
	    });    
	  }
  }
});


app.get('/input_user_data', (req, res) => {
  let token = (typeof(req.query.tk) != 'string')? '' : req.query.tk;
  let apply_id = (typeof(req.query.apply_id) != 'string')? 0 : req.query.apply_id;
  
  //-- Note: 1. Original token contains no space characters, so that all space characters are actually '+'. --//
  //--       2. Stored token is in escaped format.                                                          --//
  token = token.replace(/ /g, '+');
  token = escape(token);
  
  if (wev.allTrim(token) != '' && apply_id > 0) {
    let result = msglib.verifyApplicantToken(msg_pool, token, apply_id);
    
    result.then((is_valid_token) => {
      if (is_valid_token) {
        let result = smslib.showUserCreationForm(msg_pool, token, apply_id);
        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          
          let html = `
          <script>
            alert("Unable to verify given data, please try again."); 
            var url = window.location.href;
            var host = url.split('/');
            location.href = host[0] + '//' + host[2] + '/';
          </script>              
          `;
          
          res.send(html);                
        });        
      }
      else {
        //-- Hacker is trying randomly, switch this guy away. --//
        let result = smslib.selectSiteForHacker(msg_pool);
        
        result.then((url) => {
          res.redirect(url);
        }).catch((error) => {
          smslib.consoleLog(error);
          res.redirect('https://www.microsoft.com');
        });                
      }      
    }).catch((error) => {
      smslib.consoleLog(error);
      
      let html = `
      <script>
        alert("System error is found during verification, please try again."); 
        var url = window.location.href;
        var host = url.split('/');
        location.href = host[0] + '//' + host[2] + '/';
      </script>              
      `;
      
      res.send(html);      
    });    
  }
  else {
    //-- Arbitrary attack is found, switch this guy away. --//
    let result = smslib.selectSiteForHacker(msg_pool);
    
    result.then((url) => {
      res.redirect(url);
    }).catch((error) => {
      smslib.consoleLog(error);
      res.redirect('https://www.microsoft.com');
    });        
  }
});


app.post('/create_user_acct', (req, res) => {
  let token = (typeof(req.body.token) != 'string')? '' : req.body.token;
  let apply_id = (typeof(req.body.apply_id) != 'string')? 0 : req.body.apply_id;
  let algorithm = (typeof(req.body.algorithm) != 'string')? '' : req.body.algorithm;         // AES-256 encryption algorithm used
  let iv_user = (typeof(req.body.iv_user) != 'string')? '' : req.body.iv_user;
  let e_user = (typeof(req.body.e_user) != 'string')? '' : req.body.e_user;
  let iv_alias = (typeof(req.body.iv_alias) != 'string')? '' : req.body.iv_alias;
  let e_alias = (typeof(req.body.e_alias) != 'string')? '' : req.body.e_alias;
  let iv_happy_passwd = (typeof(req.body.iv_happy_passwd) != 'string')? '' : req.body.iv_happy_passwd;
  let e_happy_passwd = (typeof(req.body.e_happy_passwd) != 'string')? '' : req.body.e_happy_passwd;
  let iv_unhappy_passwd = (typeof(req.body.iv_unhappy_passwd) != 'string')? '' : req.body.iv_unhappy_passwd;
  let e_unhappy_passwd = (typeof(req.body.e_unhappy_passwd) != 'string')? '' : req.body.e_unhappy_passwd;
  let iv_email = (typeof(req.body.iv_email) != 'string')? '' : req.body.iv_email;
  let e_email = (typeof(req.body.e_email) != 'string')? '' : req.body.e_email;
  let iv_name = (typeof(req.body.iv_name) != 'string')? '' : req.body.iv_name;
  let e_name = (typeof(req.body.e_name) != 'string')? '' : req.body.e_name;
  let cs_public_sha256sum = req.body.cs_public_sha256sum;  
  let key_id = req.body.key_id;
  let key_iv = req.body.key_iv;                            // IV of 'key'
  let key = req.body.key;                                  // AES encrypted for a RSA encrypted JSON string of the session AES key
  let kyber_id = req.body.kyber_id;
  let kyber_ct = req.body.kyber_ct;
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;    
  let user = '';
  let alias = '';
  let happy_passwd = '';
  let unhappy_passwd = '';
  let email = '';
  let name = '';
  let data_ok = true;
  
  //-- Note: Original token contains no space characters, so that all space characters are actually '+'. --//
  token = token.replace(/ /g, '+');
  
  if (token != '' && apply_id > 0) {
    let result = msglib.checkApplicantToken(msg_pool, token, apply_id);
    
    result.then((token_valid) => {
      if (token_valid) {
			  let result = smslib.checkClientSidePubKeySha256Sum(msg_pool, key_id, cs_public_sha256sum); 
			  result.then((is_valid) => {
					if (is_valid) {
            let result = smslib.extractClientAESkey(msg_pool, kyber_id, kyber_ct, algorithm, key_id, key_iv, key);
						result.then((aes_key) => {			
							//-- Decrypt user account data set in here --//				
							let data = {iv_user: iv_user, e_user: e_user, iv_alias: iv_alias, e_alias: e_alias, iv_happy_passwd: iv_happy_passwd,
								          e_happy_passwd: e_happy_passwd, iv_unhappy_passwd: iv_unhappy_passwd, e_unhappy_passwd: e_unhappy_passwd,
								          iv_email: iv_email, e_email: e_email, iv_name: iv_name, e_name: e_name};
							
							let result = smslib.decryptUserAccountDataSet(algorithm, aes_key, data);
							
							result.then((dec_obj) => {
							  user = dec_obj.user;
							  alias = dec_obj.alias;
							  happy_passwd = dec_obj.happy_passwd;
							  unhappy_passwd = dec_obj.unhappy_passwd;
							  email = dec_obj.email;
							  name = dec_obj.name;
							  
			          var result = msglib.goCreateUserAccount(msg_pool, apply_id, name, user, alias, email, happy_passwd, unhappy_passwd, http_user_agent, ip_addr);
			          
			          result.then((retval) => {
			            var html;
			            
			            if (retval.ok) {
			              html = `
			              <script>
			                alert("Your user account is created, you may login now."); 
			                var url = window.location.href;
			                var host = url.split('/');
			                location.href = host[0] + '//' + host[2] + '/';
			              </script>                    
			              `;
			              
			              res.send(html);                        
			            }
			            else {
			              if (retval.stage == 1) {
			                html = `
			                <script>
			                  alert("Your user account is created, but error is found, please contact your referrer."); 
			                  var url = window.location.href;
			                  var host = url.split('/');
			                  location.href = host[0] + '//' + host[2] + '/';
			                </script>                    
			                `;
			                
			                res.send(html);                                        
			              }
			              else {
			                html = `
			                <script>
			                  alert("Error: ${retval.msg} You may try again."); 
			                  var url = window.location.href;
			                  var host = url.split('/');
			                  location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
			                </script>                    
			                `;
			                
			                res.send(html);                                                        
			              } 
			            }                        
			          }).catch((error) => {
			            smslib.consoleLog(error);
			            
			            var html = `
			            <script>
			              alert("Error is found during user account creation, please try again."); 
			              var url = window.location.href;
			              var host = url.split('/');
			              location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
			            </script>                    
			            `;
			            
			            res.send(html);          
			          });          								
							}).catch((error) => {
								smslib.consoleLog(error);
								
			          let html = `
			          <script>
			            alert("At least one sent data is lost, please try again."); 
			            var url = window.location.href;
			            var host = url.split('/');
			            location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
			          </script>                    
			          `;
			          
			          res.send(html);          								
							});
						}).catch((error) => {
			        smslib.consoleLog(error);
			        				
		          let html = `
		          <script>
		            alert("Encryption key is lost, please try again."); 
		            var url = window.location.href;
		            var host = url.split('/');
		            location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
		          </script>                    
		          `;
		          
		          res.send(html);          							
						});
					}
					else {
				    let html = `<script>
				                  alert("Warning: The checksum of the public key is invalid, the process is aborted. You may be under Man-In-The-Middle attack!"); 
				                  var url = window.location.href;
				                  var host = url.split('/');
				                  location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
				                </script>`;
				  
				    res.send(html);                    																							
					}
				}).catch((error) => {
	        smslib.consoleLog(error);
	        				
          let html = `
          <script>
            alert("Unable to verify the public key, the process is aborted. Please try again."); 
            var url = window.location.href;
            var host = url.split('/');
            location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
          </script>                    
          `;
          
          res.send(html);          												
				}); 
      }
      else {
        //-- Hacker attacking is found, switch this guy away. --//
        var result = smslib.selectSiteForHacker(msg_pool);
        
        result.then((url) => {
          res.redirect(url);
        }).catch((error) => {
          smslib.consoleLog(error);
          res.redirect('https://www.microsoft.com');
        });                    
      }      
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `
      <script>
        alert("Unable to verify your application, please try again."); 
        var url = window.location.href;
        var host = url.split('/');
        location.href = host[0] + '//' + host[2] + '/input_user_data?tk=${token}&apply_id=${apply_id}';
      </script>                    
      `;
      
      res.send(html);
    });      
  }
  else {
    //-- Arbitrary attack is found, switch this guy away. --//
    var result = smslib.selectSiteForHacker(msg_pool);
    
    result.then((url) => {
      res.redirect(url);
    }).catch((error) => {
      smslib.consoleLog(error);
      res.redirect('https://www.microsoft.com');
    });            
  }
});


app.get('/pdatools', (req, res) => {  
  var user = (typeof(req.query.user) != "string")? "" : wev.allTrim(req.query.user);
  var sess_code = (typeof(req.query.sess_code) != "string")? "" : wev.allTrim(req.query.sess_code);
  
  if (user != "" && sess_code != "") {
    //-- Notes: 1. 'sess_code' is used to verify 'user'.                                                               --//
    //--        2. 'sess_code' is stored on table in database 'pdadb', but user profile is stored on database 'msgdb'. --//
    //--        3. Only SMS with login mode 0 or 3, or users in 'unhappy' status will land on this page.               --// 
    var result = smslib.getUserIdByName(msg_pool, pda_pool, user, sess_code);
    
    result.then((user_id) => {
      if (user_id > 0) {
        //-- Create cookie --// 
        var options = {path:'/', maxAge:86400000, httpOnly:true, secure:true};                // Note: Unit of maxAge is in 1/1000 second.
        var values = {user_id: user_id, sess_code: sess_code};
        values = JSON.stringify(values);
        res.cookie(COOKIE_PDA, values, options);                                              // Note: COOKIE_PDA = 'PDA_USER' 
        //-- Go to PDA tools selection page --//  
        res.redirect("/select_tools");          
      }
      else {
        var html = `<script>
                      alert("Unable to retrieve your profile, please login again."); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/';
                    </script>`;
      
        res.send(html);                            
      }      
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                    
    });    
  }
  else {
    res.redirect("/");
  }
});


app.get('/select_tools', (req, res) => {
  var cookie = req.cookies.PDA_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (user_id > 0 && sess_code != "") {
    var sess_checker = smslib.isSessionValid(pda_pool, user_id, sess_code, true, 'PDA');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = smslib.printSelectToolsForm(pda_pool, msg_pool, user_id);
        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Error is found build landing page, please login again. Error: ${error}"); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/';
                      </script>`;
        
          res.send(html);                              
        });        
      }
      else {
        //-- Invalid session, switch to login page. --//
        res.redirect("/");
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found as checking session validity, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                    
    });
  }
  else {
    res.redirect("/");
  }
});


//-- Note editor for the decoy site --//
app.get('/tools/notes', (req, res) => {
  var list_filter = (typeof(req.query.list_filter) != "string")? "" : req.query.list_filter;
  var cookie = req.cookies.PDA_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (user_id > 0 && sess_code != "") {
    var sess_checker = smslib.isSessionValid(pda_pool, user_id, sess_code, true, 'PDA');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = smslib.printNotesList(pda_pool, user_id, list_filter);
        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Error is found as build notes listing. Error: ${error}"); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/select_tools';
                      </script>`;
        
          res.send(html);                                        
        });        
      }
      else {
        //-- Invalid session, switch to login page. --//
        res.redirect("/");        
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found as checking session validity, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                          
    });    
  }
  else {
    res.redirect("/");
  }
});


app.post('/tools/notes', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;        // A = Add new notes, E = Modify notes, D = Delete notes, R = Read notes, others = List notes.
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;
  var notes_id  = (isNaN(parseInt(req.body.notes_id, 10)))? 0 : req.body.notes_id;    
  var notes_title = (typeof(req.body.notes_title) != "string")? "" : req.body.notes_title;
  var notes_content = (typeof(req.body.notes_content) != "string")? "" : req.body.notes_content;
  var lstfilter = (typeof(req.body.lstfilter) != "string")? "" : req.body.lstfilter;
  var cookie = req.cookies.PDA_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (user_id > 0 && sess_code != "") {
    var sess_checker = smslib.isSessionValid(pda_pool, user_id, sess_code, true, 'PDA');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (op == 'A' || op == 'E' || op == 'D' || op == 'R') {        
          var result = smslib.notesOperation(pda_pool, op, oper_mode, user_id, notes_id, notes_title, notes_content, lstfilter);
          
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            var html = `<script>
                          alert("Error: ${error}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/tools/notes?list_filter=' + lstfilter;
                        </script>`;
          
            res.send(html);                                                  
          })
        }
        else {
          res.redirect("/tools/notes");
        }
      }
      else {
        //-- Invalid session, switch to login page. --//
        res.redirect("/");                
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found as checking session validity, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                                
    });
  }
  else {
    res.redirect("/");
  }
});


//-- Scheduler for the decoy site --//
app.get('/tools/scheduler', (req, res) => {
  var what_year = (typeof(req.query.what_year) != "string")? 0 : req.query.what_year;
  var what_month = (typeof(req.query.what_month) != "string")? 0 : req.query.what_month;
  var op = (typeof(req.query.op) != "string")? "" : req.query.op;
  var event_id = (typeof(req.query.event_id) != "string")? 0 : req.query.event_id;
  var call_by = (typeof(req.query.call_by) != "string")? "" : req.query.call_by;                   // Call by who?   
  var cookie = req.cookies.PDA_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (user_id > 0 && sess_code != "") {
    var sess_checker = smslib.isSessionValid(pda_pool, user_id, sess_code, true, 'PDA');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = smslib.printCalendar(pda_pool, user_id, what_year, what_month, op, event_id, call_by);
        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Error is found as create scheduler page. Error: ${error}"); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/select_tools';
                      </script>`;
        
          res.send(html);                                                  
        });
      }
      else {
        //-- Invalid session, switch to login page. --//
        res.redirect("/");                        
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found as checking session validity, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                                      
    });
  }
  else {
    res.redirect("/");
  }
});


function _getEventReminder(op, req) {
  var result = [];
  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/rd_value_/)) {
      var idx = this_key;
      idx = parseInt(idx.replace(/rd_value_/, ""), 10); 
      
      if (idx > 0) {
        var this_rd_value = parseInt(req.body[this_key], 10);
        var this_rd_unit = wev.allTrim(req.body['rd_unit_' + idx]);
        var this_rd_id = (op == "E")? req.body['rd_id_' + idx] : 0;
        
        if (this_rd_value > 0 && this_rd_unit != "") {
          result.push({rd_value: this_rd_value, rd_unit: this_rd_unit, rd_id: this_rd_id});
        }
      } 
    }    
  }
  
  return result;
}


app.post('/tools/scheduler', (req, res) => {
  var what_year = (typeof(req.body.what_year) != "string")? 0 : req.body.what_year;
  var what_month = (typeof(req.body.what_month) != "string")? 0 : req.body.what_month;
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                                  // 'A' = Add new event, 'E' = Modify event, 'D' = Delete event, 'R' = Read event, 'L' = List events, 'S' = Search event, others = Show calender.
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;             // 'S' = Save
  var list_filter = (typeof(req.body.list_filter) != "string")? "" : req.body.list_filter;       // Key words filter on event's title for event searching.
  var search_phase = (typeof(req.body.search_phase) != "string")? "" : wev.allTrim(req.body.search_phase);    // Text phase is used for event searching.
  var event_id = (typeof(req.body.event_id) != "string")? 0 : req.body.event_id;
  var event_title = (typeof(req.body.event_title) != "string")? "" : req.body.event_title; 
  var event_detail = (typeof(req.body.event_detail) != "string")? "" : req.body.event_detail;
  var event_start = (typeof(req.body.event_start) != "string")? "" : req.body.event_start;
  var event_end = (typeof(req.body.event_end) != "string")? "" : req.body.event_end;
  var has_reminder = (typeof(req.body.has_reminder) != "string")? 0 : parseInt(req.body.has_reminder, 10);    // 0 = No reminder, 1 = has reminder.
  var reminder = (has_reminder == 1)? _getEventReminder(op, req) : [];
  var call_by = (typeof(req.body.call_by) != "string")? "" : req.body.call_by;                   // Call by who?   
  //-- Below variables are taken from the cookie --//  
  var cookie = req.cookies.PDA_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (user_id > 0 && sess_code != "") {
    var sess_checker = smslib.isSessionValid(pda_pool, user_id, sess_code, true, 'PDA');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (op == "A") {
          if (oper_mode == 'S') {
            var result = smslib.addNewEvent(pda_pool, user_id, event_title, event_detail, event_start, event_end, reminder);
            
            result.then((retval) => {
              if (retval.ok) {
                res.redirect(`/tools/scheduler?what_year=${what_year}&what_month=${what_month}`);
              }
              else {
                smslib.consoleLog(retval.msg);
                
                var html = `<script>
                              alert("Unable to add new event. Error: ${retval.msg}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                            </script>`;
              
                res.send(html);                                                                                  
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as adding new event. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                                  
            });            
          }
          else {
            var result = smslib.printAddEventForm(pda_pool, user_id, op, oper_mode, what_year, what_month, event_start, event_end, event_title, event_detail);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as build event adding form. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                    
            });            
          }
        }
        else if (op == "E") {
          if (oper_mode == "S") {
            var result = smslib.updateEvent(pda_pool, user_id, event_id, event_title, event_detail, event_start, event_end, reminder);
            
            result.then((retval) => {
              if (retval.ok) {
                res.redirect(`/tools/scheduler?what_year=${what_year}&what_month=${what_month}&op=R&event_id=${event_id}&call_by=${call_by}`);
              }
              else {
                smslib.consoleLog(retval.msg);
                
                var html = `<script>
                              alert("Error is found as update event. Error: ${retval.msg}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}&op=R&event_id=${event_id}';
                            </script>`;
              
                res.send(html);                                                                                  
              }              
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as update event. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}&op=R&event_id=${event_id}';
                          </script>`;
            
              res.send(html);                                                                  
            });              
          }
          else {
            var result = smslib.printEditEventForm(pda_pool, user_id, op, oper_mode, what_year, what_month, event_id, has_reminder, call_by);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as build event editing form. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                                  
            });
          }
        }
        else if (op == "D") {
          var result = smslib.deleteEvent(pda_pool, event_id);
          
          result.then((retval) => {
            if (retval.ok) {
              res.redirect(`/tools/scheduler?what_year=${what_year}&what_month=${what_month}`);
            }
            else {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as delete scheduled event. Error: ${retval.msg}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                                                
            }
          }).catch((error) => {
            smslib.consoleLog(error);
            
            var html = `<script>
                          alert("Unable to delete scheduled event. Error: ${error}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                        </script>`;
          
            res.send(html);                                                                                          
          });          
        }
        else if (op == "R") {
          var result = smslib.printReadEventForm(pda_pool, user_id, op, oper_mode, what_year, what_month, event_id, has_reminder, call_by, search_phase);
          
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            var html = `<script>
                          alert("Error is found as build event reading page. Error: ${error}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                        </script>`;
          
            res.send(html);                                                                              
          });
        }
        else if (op == "L") {
          var result = smslib.printEventList(pda_pool, op, oper_mode, user_id, what_year, what_month);
          
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            var html = `<script>
                          alert("Error is found as build event listing page. Error: ${error}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                        </script>`;
          
            res.send(html);                                                                                          
          });          
        }
        else if (op == "S") {
          if (search_phase != "") {
            var result = smslib.printSearchResult(pda_pool, op, user_id, what_year, what_month, search_phase);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as build event searching result. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                                                                                      
            });
          }
          else {
            var result = smslib.printSearchForm(op, what_year, what_month);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error is found as build event searching page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/tools/scheduler?what_year=${what_year}&what_month=${what_month}';
                          </script>`;
            
              res.send(html);                                                                                                        
            });            
          }
        }
        else {
          res.redirect(`/tools/scheduler?what_year=${what_year}&what_month=${what_month}`);
        }        
      }
      else {
        res.redirect("/");  
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      
      var html = `<script>
                    alert("Error is found as checking session validity, please login again. Error: ${error}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                                      
    });
  }
  else {
    res.redirect("/");
  }
});


app.get('/logon_agent', (req, res) => {
  var token = escape(req.query.tk);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  //-- Note: Original token contains no space characters, so that all '%20' are actually '+'. --//
  token = token.replace(/%20/g, '+');
  
  var result = smslib.finalizeLoginProcess(msg_pool, token, http_user_agent, ip_addr);  
  result.then((session) => {
    var ok = session.ok;
    var msg = session.msg;
    var user_id = session.user_id;
    var sess_code = session.sess_code;
    var url = session.url;
    
    if (ok) {
      //-- Create cookie --// 
      var options = {path:'/', maxAge:86400000, httpOnly:true, secure:true};                // Note: Unit of maxAge is in 1/1000 second.
      var values = {user_id: user_id, sess_code: sess_code};
      values = JSON.stringify(values);
      res.cookie(COOKIE_MSG, values, options);                                              // Note: COOKIE_MSG = 'MSG_USER' 
      //-- Go to the first messaging page --//  
      res.redirect(url);  
    }
    else {
      var html = `<script>
                    alert("${msg}"); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);              
    }
  }).catch((error) => {
    smslib.consoleLog(error);
    res.redirect('https://www.microsoft.com');        
  }); 
});


app.get('/message', (req, res) => {
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let result = smslib.showMessagePage(msg_pool, sess_code);
      
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
        
          let html = `<script>
                        alert("Error is found as create messaging page, please login again."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/';
                      </script>`;
    
          res.send(html); 
        });
      }
      else {
        let html = `<script>
                      alert("Session has expired, please login again."); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/';
                    </script>`;
    
        res.send(html); 
      }
    }).catch((error) => {
      smslib.consoleLog(error);

      let html = `<script>
                    alert("Unable to verify your identity, please login again."); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                  
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');
  }
});


app.post('/get_profile_data', (req, res) => {
  let option = req.body.option;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
				let result = smslib.getProfileData(msg_pool, user_id, sess_code, option);
				
				result.then((ret_data) => {
					res.send(JSON.stringify(ret_data));
				}).catch((error) => {
					let ret_data = JSON.stringify({ok: '0', msg: error, data: null});
					res.send(ret_data);
				});				
			}
			else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    				
			}
		}).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                			
		});
	}
	else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    		
	}	
});


app.get('/edit_alias', (req, res) => {
  let u_id = (typeof(req.query.u_id) == 'undefined')? 0 : parseInt(req.query.u_id, 10);       // 'u_id' is used for verification
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (user_id == u_id) {
          let result = smslib.printEditAliasForm(msg_pool, user_id, sess_code);
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            let html = `<script>
                          alert("Error is found, please try again. Error: ${error}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
  
            res.send(html);                       
          });          
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          let msg = `edit_alias (1): User ${user_id} tries to use this function to amend alias of another user ${u_id}! Check for it.`;          
          smslib.consoleLog(msg);
          let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }  
});


app.post('/edit_alias', (req, res) => {
	let algorithm = req.body.algorithm;
	let iv = req.body.iv;                            // IV in JSON string format 
  let e_alias = req.body.e_alias;                  // Encrypted alias in JSON string format
  let u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (user_id == u_id) {
						let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
						result.then((aes_key) => {
	            let result = cipher.aesDecryptJSON(algorithm, aes_key, iv, e_alias);
              result.then((alias) => {
	              let result = msglib.updateUserAlias(msg_pool, user_id, alias);
	              result.then((retval) => {
	                let html = '';
	                
	                if (retval.ok) {
	                  html = `<script>
	                            alert("Alias is updated"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/message';
	                          </script>`;
	                }
	                else {
	                  html = `<script>
	                            alert("${retval.msg}"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_alias?u_id=${u_id}';
	                          </script>`;
	                }   
	                
	                res.send(html);                             
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Error: ${error}, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/edit_alias?u_id=${u_id}';
	                            </script>`;
	      
	                res.send(html);                                         
	              }); 								
							}).catch((error) => {
								smslib.consoleLog(error);
								
	              let html = `<script>
	                            alert("The new alias is lost during decryption, please try again."); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_alias?u_id=${u_id}';
	                          </script>`;
	    
	              res.send(html);                                     
								
							}); 	            
						}).catch((error) => {
							smslib.consoleLog(error);

							let html = `<script>
														alert("Error: ${error}, please try again."); 
														var url = window.location.href;
														var host = url.split('/');
														location.href = host[0] + '//' + host[2] + '/edit_alias?u_id=${u_id}';
													</script>`;
		
							res.send(html);                                         							
						});
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `edit_alias (2): User ${user_id} tries to use this function to amend alias of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          }
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                        
  }
});


app.get('/edit_email', (req, res) => {
  let u_id = (typeof(req.query.u_id) == 'undefined')? 0 : parseInt(req.query.u_id, 10);       // 'u_id' is used for verification
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (user_id == u_id) {
          let result = smslib.printEditEmailForm(msg_pool, user_id, sess_code);
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            let html = `<script>
                          alert("Error is found, please try again."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
  
            res.send(html);                       
          });          
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          let msg = `edit_email (1): User ${user_id} tries to use this function to amend email of another user ${u_id}! Check for it.`;          
          smslib.consoleLog(msg);
          let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }  
});


app.post('/edit_email', (req, res) => {
	let algorithm = req.body.algorithm;
	let iv = req.body.iv;                       // In JSON string format
  let e_email = req.body.e_email;             // Encrypted and in JSON string format
  let u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (user_id == u_id) {
						let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
						result.then((aes_key) => {						
	            let result = cipher.aesDecryptJSON(algorithm, aes_key, iv, e_email); 
	            result.then((email) => {	              
	              let result = msglib.updateUserEmail(msg_pool, user_id, email);
	              result.then((retval) => {
	                let html = '';
	                
	                if (retval.ok) {
	                  html = `<script>
	                            alert("Email is updated"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/message';
	                          </script>`;
	                }
	                else {
	                  html = `<script>
	                            alert("${retval.msg}"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_email?u_id=${user_id}';
	                          </script>`;
	                }   
	                
	                res.send(html);                             
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Error: ${error}, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/edit_email?u_id=${user_id}';
	                            </script>`;
	      
	                res.send(html);                                         
	              }); 
	            }).catch((error) => {
  							smslib.consoleLog(error);
															
	              let html = `<script>
	                            alert("The new email is lost during decryption, please try again."); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_email?u_id=${user_id}';
	                          </script>`;
	    
	              res.send(html);                                     
	            });
						}).catch((error) => {
							smslib.consoleLog(error);

							let html = `<script>
														alert("Error: ${error}, please try again."); 
														var url = window.location.href;
														var host = url.split('/');
														location.href = host[0] + '//' + host[2] + '/edit_email?u_id=${u_id}';
													</script>`;
		
							res.send(html);                                         														
						});
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `edit_email (2): User ${user_id} tries to use this function to amend email of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          }
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                        
  }
});


app.get('/edit_tg_id', (req, res) => {
  let u_id = (typeof(req.query.u_id) == 'undefined')? 0 : parseInt(req.query.u_id, 10);       // 'u_id' is used for verification
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  let client_device_info = req.device;                 // Defined in the client device detection middleware
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (user_id == u_id) {
          let result = smslib.printEditTelegramIdForm(msg_pool, user_id, sess_code, client_device_info);
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            let html = `<script>
                          alert("Error is found, please try again."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
  
            res.send(html);                       
          });          
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          let msg = `edit_tg_id (1): User ${user_id} tries to use this function to amend Telegram ID of another user ${u_id}! Check for it.`;          
          smslib.consoleLog(msg);
          let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }  
});


app.post('/edit_tg_id', (req, res) => {
	let algorithm = req.body.algorithm;
	let iv = req.body.iv;                           // In JSON string format
  let e_tg_id = req.body.e_tg_id;                 // In JSON string format 
  let u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  let tg_id = '';

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (user_id == u_id) {
						let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
						result.then((aes_key) => {
	            let result = cipher.aesDecryptJSON(algorithm, aes_key, iv, e_tg_id);        	            
	            result.then((tg_id) => {
	              let result = msglib.updateUserTelegramId(msg_pool, user_id, tg_id);
	              result.then((retval) => {
	                let html = '';
	                
	                if (retval.ok) {
	                  html = `<script>
	                            alert("Telegram ID is updated"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/message';
	                          </script>`;
	                }
	                else {
	                  html = `<script>
	                            alert("${retval.msg}"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_tg_id?u_id=${user_id}';
	                          </script>`;
	                }   
	                
	                res.send(html);                             
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Error: ${error}, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/edit_tg_id?u_id=${user_id}';
	                            </script>`;
	      
	                res.send(html);                                         
	              }); 
	            }).catch((error) => {
								smslib.consoleLog(error);
								
	              let html = `<script>
	                            alert("The new Telegram ID is lost during decryption, please try again."); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_tg_id?u_id=${user_id}';
	                          </script>`;
	    
	              res.send(html);                                     
	            });
					  }).catch((error) => {
							smslib.consoleLog(error);
							
							let html = `<script>
														alert("Error: ${error}, please try again."); 
														var url = window.location.href;
														var host = url.split('/');
														location.href = host[0] + '//' + host[2] + '/edit_tg_id?u_id=${user_id}';
													</script>`;
		
							res.send(html);                                         							
						}); 
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `edit_tg_id (2): User ${user_id} tries to use this function to amend Telegram ID of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          }
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                        
  }
});


app.get('/edit_happy_passwd', (req, res) => {
  let u_id = (typeof(req.query.u_id) == 'undefined')? 0 : parseInt(req.query.u_id, 10);       // 'u_id' is used for verification
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (user_id == u_id) {
          let result = smslib.printEditHappyPasswdForm(msg_pool, user_id, sess_code);
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            let html = `<script>
                          alert("Error is found, please try again."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
  
            res.send(html);                       
          });          
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          let msg = `edit_happy_passwd (1): User ${user_id} tries to use this function to amend happy password of another user ${u_id}! Check for it.`;          
          smslib.consoleLog(msg);
          let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }  
});


app.post('/edit_happy_passwd', (req, res) => {
	let algorithm = req.body.algorithm;
	let iv = req.body.iv;                                  // In JSON string format
  let e_happy_passwd = req.body.e_happy_passwd;          // In JSON string format
  let u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (user_id == u_id) {
						let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
						result.then((aes_key) => {						
	            let result = cipher.aesDecryptJSON(algorithm, aes_key, iv, e_happy_passwd);	            
	            result.then((happy_passwd) => {	              
	              let result = msglib.updateUserHappyPassword(msg_pool, user_id, happy_passwd);
	              result.then((retval) => {
	                let html = '';
	                
	                if (retval.ok) {
	                  html = `<script>
	                            alert("Happy password is updated"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/message';
	                          </script>`;
	                }
	                else {
	                  html = `<script>
	                            alert("${retval.msg}"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_happy_passwd?u_id=${user_id}';
	                          </script>`;
	                }   
	                
	                res.send(html);                             
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Error: ${error}, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/edit_happy_passwd?u_id=${user_id}';
	                            </script>`;
	      
	                res.send(html);                                         
	              }); 
	            }).catch((error) => {
								smslib.consoleLog(error);
								
	              let html = `<script>
	                            alert("The new happy password is lost during decryption, please try again."); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_happy_passwd?u_id=${user_id}';
	                          </script>`;
	    
	              res.send(html);                                     
	            });
					  }).catch((error) => {
							smslib.consoleLog(error);
							
							let html = `<script>
														alert("Error: ${error}, please try again."); 
														var url = window.location.href;
														var host = url.split('/');
														location.href = host[0] + '//' + host[2] + '/edit_happy_passwd?u_id=${user_id}';
													</script>`;
		
							res.send(html);                                         							
						});
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `edit_happy_passwd (2): User ${user_id} tries to use this function to amend happy password of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          }
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                        
  }
});


app.get('/edit_unhappy_passwd', (req, res) => {
  let u_id = (typeof(req.query.u_id) == 'undefined')? 0 : parseInt(req.query.u_id, 10);       // 'u_id' is used for verification
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (user_id == u_id) {
          let result = smslib.printEditUnhappyPasswdForm(msg_pool, user_id, sess_code);
          result.then((html) => {
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            
            let html = `<script>
                          alert("Error is found, please try again."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
  
            res.send(html);                       
          });          
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          let msg = `edit_unhappy_passwd (1): User ${user_id} tries to use this function to amend unhappy password of another user ${u_id}! Check for it.`;          
          smslib.consoleLog(msg);
          let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }  
});


app.post('/edit_unhappy_passwd', (req, res) => {
	let algorithm = req.body.algorithm;
	let iv = req.body.iv;                                   // In JSON string format
  let e_unhappy_passwd = req.body.e_unhappy_passwd;       // Encrypted and in JSON string format
  let u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);         // 'u_id' is used for verification
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (user_id == u_id) {
						let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
						result.then((aes_key) => {											
	            let result = cipher.aesDecryptJSON(algorithm, aes_key, iv, e_unhappy_passwd);
	            
	            result.then((unhappy_passwd) => {
	              let result = msglib.updateUserUnhappyPassword(msg_pool, user_id, unhappy_passwd);
	              result.then((retval) => {
	                let html = '';
	                
	                if (retval.ok) {
	                  html = `<script>
	                            alert("Unhappy password is updated"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/message';
	                          </script>`;
	                }
	                else {
	                  html = `<script>
	                            alert("${retval.msg}"); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_unhappy_passwd?u_id=${user_id}';
	                          </script>`;
	                }   
	                
	                res.send(html);                             
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Error: ${error}, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/edit_unhappy_passwd?u_id=${user_id}';
	                            </script>`;
	      
	                res.send(html);                                         
	              }); 
	            }).catch((error) => {
								smslib.consoleLog(error);
								
	              let html = `<script>
	                            alert("The new unhappy password is lost during decryption, please try again."); 
	                            var url = window.location.href;
	                            var host = url.split('/');
	                            location.href = host[0] + '//' + host[2] + '/edit_unhappy_passwd?u_id=${user_id}';
	                          </script>`;
	    
	              res.send(html);                                     
	            });
					  }).catch((error) => {
							smslib.consoleLog(error);
							
							let html = `<script>
														alert("Error: ${error}, please try again."); 
														var url = window.location.href;
														var host = url.split('/');
														location.href = host[0] + '//' + host[2] + '/edit_unhappy_passwd?u_id=${user_id}';
													</script>`;
		
							res.send(html);                                         							
						});
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `edit_unhappy_passwd (2): User ${user_id} tries to use this function to amend unhappy password of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          }
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                        
  }
});


app.get('/add_group', (req, res) => {
  var group_name = (typeof(req.query.group_name) == 'undefined')? '' : decodeURI(req.query.group_name);
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = smslib.printAddGroupForm(user_id, group_name, sess_code);        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          var html = `<script>
                        alert("Error: ${error}, please try again."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;

          res.send(html);                                                   
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                            
  }  
});


app.post('/add_group', (req, res) => {
  var u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification  
  var oper_mode = req.body.oper_mode;
  var group_name = req.body.group_name;
  var msg_auto_delete = req.body.msg_auto_delete;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  var members = [];        // Note: Since given user alias list can't be verified at this moment, so it is just a proposed list, not the finalized list.
  
  //-- Collect alias of all proposed group member(s) here --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/member_/)) {
      var this_member = req.body[this_key];
      if (this_member.trim() != '') {
        members.push(this_member); 
      }
    }    
  }

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (u_id == user_id) {
            var result = msglib.createMessageGroup(msg_pool, user_id, group_name, msg_auto_delete, members, http_user_agent, ip_addr);
            
            result.then((retval) => {
              var html = '';
              
              if (retval.ok) {
                html = `<script>
                          alert("Message group is created successfully"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
              }
              else {
                group_name = encodeURI(group_name);
                
                html = `<script>
                          alert("${retval.msg}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/add_group?group_name=${group_name}';
                        </script>`;
              }   
              
              res.send(html);                             
            }).catch((error) => {
              smslib.consoleLog(error);              
              group_name = encodeURI(group_name);
              
              var html = `<script>
                            alert("Error: ${error}, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/add_group?group_name=${group_name}';
                          </script>`;
    
              res.send(html);                                                       
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_group: User ${user_id} tries to use this function to create a message group on behalf of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          } 
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                
  }
});


app.get('/add_private_group', (req, res) => {
  var group_name = (typeof(req.query.group_name) == 'undefined')? '' : decodeURI(req.query.group_name);
  var auto_delete = (typeof(req.query.auto_delete) == 'undefined')? 1 : parseInt(req.query.auto_delete, 10);
  var member = (typeof(req.query.member) == 'undefined')? '' : req.query.member;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = smslib.printAddPrivateGroupForm(user_id, group_name, auto_delete, member, sess_code);        
        result.then((html) => {
          res.send(html);
        }).catch((error) => {
          smslib.consoleLog(error);
          var html = `<script>
                        alert("Error: ${error}, please try again."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;

          res.send(html);                                                   
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                            
  }  
});


app.post('/add_private_group', (req, res) => {
  var u_id = (typeof(req.body.u_id) == 'undefined')? 0 : parseInt(req.body.u_id, 10);        // 'u_id' is used for verification  
  var group_name = req.body.group_name;
  var member = req.body.member;  
  var auto_delete = parseInt(req.body.auto_delete, 10);
  var delete_after = parseInt(req.body.delete_after, 10);  
  var oper_mode = req.body.oper_mode;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          if (u_id == user_id) {
            var result = msglib.createPrivateMessageGroup(msg_pool, user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr);
            
            result.then((retval) => {
              var html = '';
              
              if (retval.ok) {
                html = `<script>
                          alert("Private message group is created successfully"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
              }
              else {
                group_name = encodeURI(group_name);
                
                html = `<script>
                          alert("${retval.msg}"); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/add_private_group?group_name=${group_name}&auto_delete=${auto_delete}&member=${member}';
                        </script>`;
              }   
              
              res.send(html);                             
            }).catch((error) => {
              smslib.consoleLog(error);              
              group_name = encodeURI(group_name);
              
              var html = `<script>
                            alert("Error: ${error}, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/add_private_group?group_name=${group_name}&auto_delete=${auto_delete}&member=${member}';
                          </script>`;
    
              res.send(html);                                                       
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_private_group: User ${user_id} tries to use this function to create a private message group on behalf of another user ${u_id}! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                      
          } 
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');          
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');      
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                
  }
});


app.get('/delete_group_by_admin', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printDeleteGroupByAdminForm(msg_pool, user_id);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error ${error}: Unable to create web page."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);              
            });             
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `delete_group_by_admin (1): User ${user_id} tries to use this function to delete message group(s) but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }  
});


app.post('/delete_group_by_admin', (req, res) => {
  var oper_mode = req.body.oper_mode;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  var delete_groups = [];    
    
  //-- Collect user ID of all administrators to be demoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/group_id_/)) {
      var this_group_id = req.body[this_key];
      if (parseInt(this_group_id, 10) > 0) {
        delete_groups.push(parseInt(this_group_id, 10)); 
      }
    }    
  }

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          var checker = msglib.isSystemAdmin(msg_pool, user_id);
          
          checker.then((is_sys_admin) => {
            if (is_sys_admin) {
              var result = msglib.deleteGroupByAdmin(msg_pool, delete_groups);
              
              result.then((retval) => {
                //-- Note: Return web page is built within the function 'deleteGroupByAdmin', including minor error is found during operation. --// 
                res.send(retval.html);            
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error: ${error}, please try again."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/delete_group_by_admin';
                            </script>`;
      
                res.send(html);                                                                       
              });
            }
            else {
              //-- It is a suspicious activity, log it down and logout this user. --//
              var msg = `delete_group_by_admin (2): User ${user_id} tries to use this function to delete message group(s) but he/she is not system administrator! Check for it.`;          
              smslib.consoleLog(msg);
              var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
              result.then((ok) => {
                res.redirect('/logout_msg');  
              }).catch((error) => {
                smslib.consoleLog(error);
                res.redirect('/logout_msg');
              });                                                
            }
          }).catch((error) => {
            smslib.consoleLog(error);
                      
            var html = `<script>
                          alert("Unable to check whether you are system administrator, process is aborted."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
            
            res.send(html);            
          });
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');                    
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                  
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                        
  }
});


app.get('/promote_user', (req, res) => {
  var op = (typeof(req.query.op) == "undefined")? 1 : req.query.op; 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printPromoteSelectOperationForm(op);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error ${error}: Unable to create web page."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);              
            });             
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `promote_user: User ${user_id} tries to use this function to promote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }    
});


app.post('/promote_select_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Promotion user type is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/promote_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = smslib.printPromoteSelectUserForm(msg_pool, op);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error ${error}: Unable to create selection user list page."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/promote_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `promote_select_user: User ${user_id} tries to use this function to promote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }    
});


app.post('/promote_confirm_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  var promote_users = [];    
    
  //-- Collect user ID to be promoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/pm_user_id_/)) {
      var this_user_id = req.body[this_key];
      if (parseInt(this_user_id, 10) > 0) {
        promote_users.push(parseInt(this_user_id, 10)); 
      }
    }    
  }

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Promotion user type is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/promote_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = msglib.confirmPromoteSelectedUsers(msg_pool, op, promote_users);
              
              result.then((retval) => {
                if (retval.ok) {
                  var html = `<script>
                                alert("User(s) are promoted successfully"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/message';
                              </script>`;
                  
                  res.send(html);                                
                }
                else {
                  var html = `<script>
                                alert("Error ${retval.msg}: Unable to promote selected user(s)."); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/promote_user?op=${op}';
                              </script>`;
                  
                  res.send(html);              
                }
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error ${error}: Unable to promote selected user(s)."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/promote_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `promote_confirm_user: User ${user_id} tries to use this function to promote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }        
}); 


app.get('/demote_user', (req, res) => {
  var op = (typeof(req.query.op) == "undefined")? 1 : req.query.op; 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printDemoteSelectOperationForm(op);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error ${error}: Unable to create web page."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);              
            });             
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `demote_user: User ${user_id} tries to use this function to demote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }      
});


app.post('/demote_select_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Demotion user type is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/demote_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = smslib.printDemoteSelectUserForm(msg_pool, op, user_id);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error ${error}: Unable to create user selection list page."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/demote_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `demote_select_user: User ${user_id} tries to use this function to demote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }      
});


app.post('/demote_confirm_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  var demote_users = [];    
    
  //-- Collect user ID to be demoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/dm_user_id_/)) {
      var this_user_id = req.body[this_key];
      if (parseInt(this_user_id, 10) > 0) {
        demote_users.push(parseInt(this_user_id, 10)); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Demotion user type is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/demote_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = msglib.confirmDemoteSelectedUsers(msg_pool, op, demote_users);
              
              result.then((retval) => {
                if (retval.ok) {
                  //-- Note: It needs websocket connection to send "force logout" command to demoted user. If he/she     --//
                  //--       locates in a page which is no websocket connection, then he/she won't be forced logout      --//
                  //--       immediately. However, since his/her session record has been deleted, he/she can't perform   --//
                  //--       further action, and once he/she switch page, he/she will be sent to login page immediately. --// 
                  var result = smslib.buildForceLogoutHTML(msg_pool, demote_users, "Users are demoted successfully.", "/message");
                  
                  result.then((html) => {
                    res.send(html);
                  }).catch((error) => {
                    smslib.consoleLog(error);
                    
                    var html = `<script>
                                  alert("User(s) are demoted successfully. However, this error prevents the system to log them out: \n${error}"); 
                                  var url = window.location.href;
                                  var host = url.split('/');
                                  location.href = host[0] + '//' + host[2] + '/message';
                                </script>`;
                    
                    res.send(html);                       
                  });                    
                }
                else {
                  var html = `<script>
                                alert("Error ${retval.msg}: Unable to demote selected user(s)."); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/demote_user?op=${op}';
                              </script>`;
                  
                  res.send(html);              
                }
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error ${error}: Unable to demote selected user(s)."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/demote_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `demote_confirm_user: User ${user_id} tries to use this function to demote user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }          
});


app.get('/lock_user', (req, res) => {
  var op = (typeof(req.query.op) == "undefined")? 1 : req.query.op; 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printLockUnlockOptionForm(op);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Error ${error}: Unable to create web page."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);              
            });             
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `lock_user: User ${user_id} tries to use this function to lock or unlock user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }        
});


app.post('/lock_select_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Operation option is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/lock_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = smslib.printLockUnlockSelectUserForm(msg_pool, op, user_id);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error ${error}: Unable to create user selection list page."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/lock_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `lock_select_user: User ${user_id} tries to use this function to lock or unlock user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }        
});


app.post('/lock_confirm_user', (req, res) => {
  var op = (typeof(req.body.op) == "undefined")? 0 : parseInt(req.body.op, 10); 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  var select_users = [];    
    
  //-- Collect user ID to be demoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/op_user_id_/)) {
      var this_user_id = req.body[this_key];
      if (parseInt(this_user_id, 10) > 0) {
        select_users.push(parseInt(this_user_id, 10)); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op != 1 && op != 2) {
              var html = `<script>
                            alert("Operation type is lost, please start it over."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/lock_user';
                          </script>`;
              
              res.send(html);              
            }
            else {
              var result = msglib.confirmLockUnlockSelectedUsers(msg_pool, op, select_users);
              
              result.then((retval) => {
                if (retval.ok) {
                  if (op == 1) {
                    //-- Note: It needs websocket connection to send "force logout" command to locked user. If he/she      --//
                    //--       locates in a page which is no websocket connection, then he/she won't be forced logout      --//
                    //--       immediately. However, since his/her session record has been deleted, he/she can't perform   --//
                    //--       further action, and once he/she switch page, he/she will be sent to login page immediately. --// 
                    var result = smslib.buildForceLogoutHTML(msg_pool, select_users, "Users are locked successfully.", "/message");
                    
                    result.then((html) => {
                      res.send(html);
                    }).catch((error) => {
                      smslib.consoleLog(error);
                      
                      var html = `<script>
                                    alert("User(s) are locked successfully. However, this error prevents the system to kick them out: \n${error}"); 
                                    var url = window.location.href;
                                    var host = url.split('/');
                                    location.href = host[0] + '//' + host[2] + '/message';
                                  </script>`;
                      
                      res.send(html);                       
                    });                    
                  }
                  else {
                    var html = `<script>
                                  alert("User(s) are unlocked successfully"); 
                                  var url = window.location.href;
                                  var host = url.split('/');
                                  location.href = host[0] + '//' + host[2] + '/message';
                                </script>`;
                    
                    res.send(html); 
                  }                               
                }
                else {
                  var operate = (op == 1)? "lock" : "unlock";
                  var html = `<script>
                                alert("Error ${retval.msg}: Unable to ${operate} selected user(s)."); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/lock_user?op=${op}';
                              </script>`;
                  
                  res.send(html);              
                }
              }).catch((error) => {
                smslib.consoleLog(error);
                var operate = (op == 1)? "lock" : "unlock";
                var html = `<script>
                              alert("Error ${error}: Unable to ${operate} selected user(s)."); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/lock_user?op=${op}';
                            </script>`;
                
                res.send(html);              
              });                             
            }                        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `lock_confirm_user: User ${user_id} tries to use this function to lock or unlock user(s), but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');            
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                    
  }            
});


app.get('/system_setup', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printSystemSetupMenu();
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to build system configuration menu. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);                        
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `system_config: User ${user_id} tries to use this function to amend system settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                              
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);          
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                  
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');    
  }
});


app.get('/admin/maintain_main_sites', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printMainSitesMaintainForm(msg_pool);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create main sites maintenance web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `maintain_main_sites: User ${user_id} tries to use this function to amend main sites settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }
});


app.post('/admin/save_main_sites', (req, res) => {
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;
  var decoy_site = (typeof(req.body.decoy_site) != "string")? "" : req.body.decoy_site;
  var message_site = (typeof(req.body.message_site) != "string")? "" : req.body.message_site;   
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S" && decoy_site != "" && message_site != "") {
              var result = msglib.saveMainSites(msg_pool, decoy_site, message_site);
              
              result.then((retval) => {
                if (retval.ok) {
                  var html = `<script>
                                alert("Update successful"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/system_setup';
                              </script>`;
                  
                  res.send(html);                                                                                  
                }
                else {
                  var html = `<script>
                                alert("Update failure, please try again. Error: ${retval.msg}"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_main_sites';
                              </script>`;
                  
                  res.send(html);                                                                
                }                
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Error is found during data update, please try again. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_main_sites';
                            </script>`;
                
                res.send(html);                                              
              });              
            }
            else {
              var html = `<script>
                            alert("Given data is invalid, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_main_sites';
                          </script>`;
              
              res.send(html);                              
            } 
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `save_main_sites: User ${user_id} tries to use this function to update main sites settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                      
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                              
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');            
  }
});


app.get('/admin/maintain_email_senders', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printEmailSenderList(msg_pool, sess_code);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create email worker maintenance web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `maintain_email_senders: User ${user_id} tries to use this function to amend email worker settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }  
});


app.post('/admin/new_email_senders', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printNewEmailSenderForm(msg_pool, op, sess_code);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to build new email worker adding page, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                          </script>`;
              
              res.send(html);                                            
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `new_email_senders: User ${user_id} tries to use this function to add new email worker, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                      
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                      </script>`;
          
          res.send(html);                              
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');            
  }
});


app.post('/get_email_sender_data', (req, res) => {
  let op = (typeof(req.body.op) != "string")? "" : req.body.op;  
  let ms_id = (parseInt(req.body.ms_id, 10) <= 0 || isNaN(parseInt(req.body.ms_id, 10)))? 0 : req.body.ms_id;     // ID of mail sender
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
						if (op == "E" && ms_id > 0) {
							let result = smslib.getEmailSenderDetails(msg_pool, ms_id, user_id, sess_code);
							
							result.then((enc_email_worker) => {
								//-- Note: All data on 'enc_email_worker' are encrypted (except the port number) by session AES key of requested user --//  
								let ret_val = {ok: "1", msg: "", data: enc_email_worker};
								res.send(JSON.stringify(ret_val));																
							}).catch((error) => {
								let ret_val = {ok: "0", msg: error, data: {}};
								res.send(JSON.stringify(ret_val));								
							});							
						}
						else {
							let ret_val = {ok: "0", msg: "Invalid parameters", data: {}};
							res.send(JSON.stringify(ret_val));
						}						
					}
	        else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `get_email_sender_data: User ${user_id} tries to use this function to get email worker profile, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                              						
					}
				}).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                      </script>`;
          
          res.send(html);                                                  					
				});
			}
			else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                                    				
			}
		}).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                          			
		});
	}
	else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                    		
	}
});


app.post('/admin/edit_email_senders', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;  
  var ms_id = (parseInt(req.body.ms_id, 10) <= 0 || isNaN(parseInt(req.body.ms_id, 10)))? 0 : req.body.ms_id;     // ID of mail sender
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
    
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op == "E" && ms_id > 0) {
              var result = smslib.printEmailSenderEditForm(msg_pool, op, ms_id, sess_code);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Unable to build email worker editing form. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                            </script>`;
                
                res.send(html);                                                                  
              });            
            }
            else {
              var html = `<script>
                            alert("Invalid parameters are given, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                          </script>`;
              
              res.send(html);                                                  
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `edit_email_senders: User ${user_id} tries to use this function to amend email worker, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                              
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                      </script>`;
          
          res.send(html);                                                  
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                          
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                    
  }  
});


app.post('/admin/save_email_senders', (req, res) => {
  let op = (typeof(req.body.op) != "string")? "" : req.body.op;                                                   // A = Add, E = Edit, D = Delete.  
  let oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;                              // S = Save, others are invalid.
  let ms_id = (parseInt(req.body.ms_id, 10) <= 0 || isNaN(parseInt(req.body.ms_id, 10)))? 0 : req.body.ms_id;     // ID of mail sender
  let algorithm = (typeof(req.body.algorithm) != "string")? "" : req.body.algorithm;                              // AES encryption algorithm used
  let iv_email = (typeof(req.body.iv_email) != "string")? "" : req.body.iv_email;                                 // IV of encrypted email sender address
  let e_email = (typeof(req.body.e_email) != "string")? "" : req.body.e_email;                                    // Encrypted email sender address
  let iv_m_user = (typeof(req.body.iv_m_user) != "string")? "" : req.body.iv_m_user;                              // IV of encrypted username of email
  let e_m_user = (typeof(req.body.e_m_user) != "string")? "" : req.body.e_m_user;                                 // Encrypted username of email
  let iv_m_pass = (typeof(req.body.iv_m_pass) != "string")? "" : req.body.iv_m_pass;                              // IV of encrypted password of email  
  let e_m_pass = (typeof(req.body.e_m_pass) != "string")? "" : req.body.e_m_pass;                                 // Encrypted password of email
  let iv_smtp_server = (typeof(req.body.iv_smtp_server) != "string")? "" : req.body.iv_smtp_server;               // IV of encrypted SMTP server of the email  
  let e_smtp_server = (typeof(req.body.e_smtp_server) != "string")? "" : req.body.e_smtp_server;                  // Encrypted SMTP server of the email 
  let port = (parseInt(req.body.e_port, 10) <= 0 || isNaN(parseInt(req.body.e_port, 10)))? 0 : req.body.e_port;   // Port number used by the SMTP server (NOT encrypted)
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  let email, m_user, m_pass, smtp_server;  
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S") {
							if (op == "D") {
								let result = msglib.saveEmailSender(msg_pool, op, ms_id, email, m_user, m_pass, smtp_server, port);
								
	              result.then((retval) => {
	                if (retval.ok) {
	                  let html = `<script>
	                                alert("The email worker is delete successfully"); 
	                                var url = window.location.href;
	                                var host = url.split('/');
	                                location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
	                              </script>`;
	                  
	                  res.send(html);                                                                                            
	                }
	                else {
	                  let html = `<script>
	                                alert("Unable to delete email worker. Error: ${retval.msg}"); 
	                                var url = window.location.href;
	                                var host = url.split('/');
	                                location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
	                              </script>`;
	                  
	                  res.send(html);                                                                          
	                }                
	              }).catch((error) => {
	                smslib.consoleLog(error);
	                
	                let html = `<script>
	                              alert("Unable to delete email worker. Error: ${error}"); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
	                            </script>`;
	                
	                res.send(html);                                                        
	              });              									
							} 
							else {
								let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
								result.then((aes_key) => {
									let data = {iv_email: iv_email, e_email: e_email, iv_m_user: iv_m_user, e_m_user: e_m_user, iv_m_pass: iv_m_pass, e_m_pass: e_m_pass, iv_smtp_server: iv_smtp_server, e_smtp_server: e_smtp_server};
									let result = smslib.decryptEmailAccountDataSet(algorithm, aes_key, data);
									
									result.then((dec_obj) => {
				            email = dec_obj.email;
				            m_user = dec_obj.m_user;
				            m_pass = dec_obj.m_pass; 						
										smtp_server = dec_obj.smtp_server;
										
			              let result = msglib.saveEmailSender(msg_pool, op, ms_id, email, m_user, m_pass, smtp_server, port);
			              
			              result.then((retval) => {
			                if (retval.ok) {
			                  let action = (op == "A")? "added" : "amended";
			                  
			                  let html = `<script>
			                                alert("The email worker is ${action} successfully"); 
			                                var url = window.location.href;
			                                var host = url.split('/');
			                                location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
			                              </script>`;
			                  
			                  res.send(html);                                                                                            
			                }
			                else {
			                  let action = (op == "A")? "add" : "amend";
			                  
			                  let html = `<script>
			                                alert("Unable to ${action} email worker. Error: ${retval.msg}"); 
			                                var url = window.location.href;
			                                var host = url.split('/');
			                                location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
			                              </script>`;
			                  
			                  res.send(html);                                                                          
			                }                
			              }).catch((error) => {
			                smslib.consoleLog(error);
			                
			                let action = (op == "A")? "add" : "amend";
			                
			                let html = `<script>
			                              alert("Unable to ${action} email worker. Error: ${error}"); 
			                              var url = window.location.href;
			                              var host = url.split('/');
			                              window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
			                            </script>`;
			                
			                res.send(html);                                                        
			              });              									
									}).catch((error) => {
										smslib.consoleLog(error);
										
		                let html = `<script>
		                              alert("At least one data is lost during decryption, operation is failure."); 
		                              var url = window.location.href;
		                              var host = url.split('/');
		                              window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
		                            </script>`;
		                
		                res.send(html);                                                        																		
									});									
								}).catch((error) => {
									smslib.consoleLog(error);
									
	                let html = `<script>
	                              alert("Unable to get the secure key on the server. Error: " + error); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
	                            </script>`;
	                
	                res.send(html);                                                        																	
								});	
						  }
            }
            else {
              //-- Something is abnormal, return user to email worker maintenance page. --//
              let html = `<script>
                            alert("Something is abnormal, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                          </script>`;
              
              res.send(html); 
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `save_email_senders: User ${user_id} tries to use this function to create, amend or delete email worker, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          let html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        window.location.href = host[0] + '//' + host[2] + '/admin/maintain_email_senders';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }  
});


app.get('/admin/maintain_decoy_sites', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printDecoySiteList(msg_pool);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create decoy sites maintenance web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `maintain_decoy_sites: User ${user_id} tries to use this function to amend decoy sites settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }    
});


app.post('/admin/add_new_decoy_site', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printNewDecoySiteForm(op);
            
            result.then((html) => {              
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to build new decoy site adding page, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                          </script>`;
              
              res.send(html);                                            
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_new_decoy_site: User ${user_id} tries to use this function to add new decoy site, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                      
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                      </script>`;
          
          res.send(html);                              
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');            
  }  
});


app.post('/admin/modify_decoy_site', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;  
  var site_url = (typeof(req.body.site_url) != "string")? "" : req.body.site_url;                                 // Decoy site URL
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
    
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op == "E" && wev.allTrim(site_url) != "") {
              var result = smslib.printDecoySiteEditForm(msg_pool, op, site_url);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Unable to build decoy site editing form. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                            </script>`;
                
                res.send(html);                                                                  
              });            
            }
            else {
              var html = `<script>
                            alert("Invalid parameters are given, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                          </script>`;
              
              res.send(html);                                                  
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `modify_decoy_site: User ${user_id} tries to use this function to amend decoy site, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                              
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                      </script>`;
          
          res.send(html);                                                  
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                          
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                    
  }    
});


app.post('/admin/save_decoy_site', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                                                   // A = Add, E = Edit, D = Delete.  
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;                              // S = Save, others are invalid.
  var site_url_old = (typeof(req.body.site_url_old) != "string")? "" : req.body.site_url_old;                     // Original decoy site URL
  var site_url = (typeof(req.body.site_url) != "string")? "" : req.body.site_url;                                 // Updated or new decoy site URL
  var key_words = (typeof(req.body.key_words) != "string")? "" : req.body.key_words;                              // Site searching key words
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S") {            
              var result = msglib.saveDecoySite(msg_pool, op, site_url_old, site_url, key_words);
              
              result.then((retval) => {
                if (retval.ok) {
                  var action = (op == "A")? "added" : (op == "E")? "amended" : "deleted";
                  
                  var html = `<script>
                                alert("The decoy site is ${action} successfully"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                              </script>`;
                  
                  res.send(html);                                                                                            
                }
                else {
                  var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                  
                  var html = `<script>
                                alert("Unable to ${action} decoy site. Error: ${retval.msg}"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                              </script>`;
                  
                  res.send(html);                                                                          
                }                
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                
                var html = `<script>
                              alert("Unable to ${action} decoy site. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                            </script>`;
                
                res.send(html);                                                        
              })              
            }
            else {
              //-- Something is abnormal, return user to decoy site maintenance page. --//
              var html = `<script>
                            alert("Something is abnormal, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                          </script>`;
              
              res.send(html); 
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `save_decoy_site: User ${user_id} tries to use this function to create, amend or delete decoy sites, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_decoy_sites';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }    
});


app.get('/admin/maintain_file_types', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printFileTypeList(msg_pool);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create file type maintenance web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `maintain_file_types: User ${user_id} tries to use this function to amend file type settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }      
});


app.post('/admin/add_new_file_type', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printNewFileTypeForm(msg_pool, op);
            
            result.then((html) => {              
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to build new file type adding page, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                          </script>`;
              
              res.send(html);                                            
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_new_file_type: User ${user_id} tries to use this function to add new file type, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                      
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                      </script>`;
          
          res.send(html);                              
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');            
  }    
});


app.post('/admin/modify_file_type', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;  
  var ftype_id = (isNaN(parseInt(req.body.ftype_id, 10)))? 0 : parseInt(req.body.ftype_id, 10);                        // File type ID.
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
    
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op == "E" && ftype_id > 0) {
              var result = smslib.printFileTypeEditForm(msg_pool, op, ftype_id);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Unable to build file type editing form. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                            </script>`;
                
                res.send(html);                                                                  
              });            
            }
            else {
              var html = `<script>
                            alert("Invalid parameters are given, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                          </script>`;
              
              res.send(html);                                                  
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `modify_file_type: User ${user_id} tries to use this function to amend file type, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                              
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                      </script>`;
          
          res.send(html);                                                  
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                          
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                    
  }    
});


app.post('/admin/save_file_type', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                                                   // A = Add, E = Edit, D = Delete.  
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;                              // S = Save, others are invalid.
  var ftype_id = (typeof(req.body.ftype_id) == "undefined")? 0 : req.body.ftype_id;                               // Unique ID of file type.
  var file_ext = (typeof(req.body.file_ext) != "string")? "" : req.body.file_ext;                                 // File extension.
  var file_type = (typeof(req.body.file_type) != "string")? "" : req.body.file_type;                              // File type.
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S") {            
              var result = msglib.saveFileTypes(msg_pool, op, ftype_id, file_ext, file_type);
              
              result.then((retval) => {
                if (retval.ok) {
                  var action = (op == "A")? "added" : (op == "E")? "amended" : "deleted";
                  
                  var html = `<script>
                                alert("The file type is ${action} successfully"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                              </script>`;
                  
                  res.send(html);                                                                                            
                }
                else {
                  var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                  
                  var html = `<script>
                                alert("Unable to ${action} file type. Error: ${retval.msg}"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                              </script>`;
                  
                  res.send(html);                                                                          
                }                
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                
                var html = `<script>
                              alert("Unable to ${action} file type. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                            </script>`;
                
                res.send(html);                                                        
              })              
            }
            else {
              //-- Something is abnormal, return user to file type maintenance page. --//
              var html = `<script>
                            alert("Something is abnormal, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                          </script>`;
              
              res.send(html); 
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `save_file_type: User ${user_id} tries to use this function to create, amend or delete file type, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_file_types';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }      
});


app.get('/admin/maintain_sys_settings', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printSysSettingList(msg_pool);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create misc. system settings maintenance web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `maintain_sys_settings: User ${user_id} tries to use this function to amend misc. system settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }        
});


app.post('/admin/modify_sys_setting', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;  
  var sys_key = (typeof(req.body.sys_key) != "string")? "" : wev.allTrim(req.body.sys_key);                     // System key.
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
    
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (op == "E" && sys_key != "") {
              var result = smslib.printSysSettingEditForm(msg_pool, op, sys_key);
              
              result.then((html) => {
                res.send(html);
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Unable to build system setting editing form. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                            </script>`;
                
                res.send(html);                                                                  
              });            
            }
            else {
              var html = `<script>
                            alert("Invalid parameters are given, process is aborted."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                          </script>`;
              
              res.send(html);                                                  
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `modify_sys_setting: User ${user_id} tries to use this function to amend system settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                              
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                      </script>`;
          
          res.send(html);                                                  
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                          
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                    
  }      
});


app.post('/admin/save_sys_setting', (req, res) => {
  var op = (typeof(req.body.op) != "string")? "" : req.body.op;                                // A = Add, E = Edit, D = Delete.
  var oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;           // S = Save, others are invalid.
  var sys_key_old = (typeof(req.body.sys_key_old) != "string")? "" : req.body.sys_key_old;     // Original system key. It is used for system settings amendment operation.
  var sys_key = (typeof(req.body.sys_key) != "string")? "" : req.body.sys_key;                 // System key.
  var sys_value = (typeof(req.body.sys_value) != "string")? "" : req.body.sys_value;           // Value of system key.
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S") {            
              var result = msglib.saveSystemSetting(msg_pool, op, sys_key_old, sys_key, sys_value);
              
              result.then((retval) => {
                if (retval.ok) {
                  var action = (op == "A")? "added" : (op == "E")? "amended" : "deleted";
                  
                  var html = `<script>
                                alert("The system setting is ${action} successfully"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                              </script>`;
                  
                  res.send(html);                                                                                            
                }
                else {
                  var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                  
                  var html = `<script>
                                alert("Unable to ${action} system setting. Error: ${retval.msg}"); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                              </script>`;
                  
                  res.send(html);                                                                          
                }                
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var action = (op == "A")? "add" : (op == "E")? "amend" : "delete";
                
                var html = `<script>
                              alert("Unable to ${action} system setting. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                            </script>`;
                
                res.send(html);                                                        
              })              
            }
            else {
              //-- Something is abnormal, return user to misc. system settings maintenance page. --//
              var html = `<script>
                            alert("Something is abnormal, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                          </script>`;
              
              res.send(html); 
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `save_sys_setting: User ${user_id} tries to use this function to create, amend or delete misc. system settings, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/maintain_sys_settings';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }        
});


app.get('/admin/telegram_bot_maintain', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = smslib.printTelegramBotProfileInputForm(msg_pool, sess_code);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              
              var html = `<script>
                            alert("Unable to create Telegram bot profile input form. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/system_setup';
                          </script>`;
              
              res.send(html);                                  
            });            
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `telegram_bot_maintain: User ${user_id} tries to use this function to amend Telegram bot profile, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                          
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/system_setup';
                      </script>`;
          
          res.send(html);                    
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');        
  }          
});


app.post('/get_telegram_bot_profile', (req, res) => {
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
						let result = smslib.getTelegramBotProfileSMSLIB(msg_pool, user_id, sess_code);
						
						result.then((tg_bot_profile) => {
		          let ret_val = {ok: "1", msg: "", data: tg_bot_profile};          
		          res.send(JSON.stringify(ret_val));                                        																			
						}).catch((error) => {
		          smslib.consoleLog(error);          
		          let ret_val = {ok: "0", msg: "Unable to get Telegram bot profile, process is aborted.", data: {}};          
		          res.send(JSON.stringify(ret_val));                                        												
						});						
					}
					else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `get_telegram_bot_profile: User ${user_id} tries to use this function to get Telegram bot profile, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  						
					}
				}).catch((error) => {
          smslib.consoleLog(error);          
          let ret_val = {ok: "0", msg: "Unable to check whether you are system administrator, process is aborted.", data: {}};          
          res.send(JSON.stringify(ret_val));                                        					
				});
			}
			else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            				
			}
		}).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    			
		});
	}
	else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                		
	}	
});


app.post('/admin/save_telegram_bot', (req, res) => {
  let oper_mode = (typeof(req.body.oper_mode) != "string")? "" : req.body.oper_mode;              // S = Save, others are invalid.
  let algorithm = req.body.algorithm;
  let iv_bot_name = req.body.iv_bot_name;
  let e_bot_name = req.body.e_bot_name;                                                           // Encrypted Telegram bot name.
  let iv_bot_username = req.body.iv_bot_username;                                                         
  let e_bot_username = req.body.e_bot_username;                                                   // Encrypted Telegram bot username. 
  let iv_http_api_token = req.body.iv_http_api_token;
  let e_http_api_token = req.body.e_http_api_token;                                               // Encrypted Telegram bot HTTP API token.
  let bot_name = "";
  let bot_username = "";
  let http_api_token = "";  
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            if (oper_mode == "S") {            
							let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
							result.then((aes_key) => {
								let data = {iv_bot_name: iv_bot_name, e_bot_name: e_bot_name, iv_bot_username: iv_bot_username, e_bot_username: e_bot_username, iv_http_api_token: iv_http_api_token, e_http_api_token: e_http_api_token};
								let result = smslib.decryptTelegramProfileData(algorithm, aes_key, data);
								
								result.then((dec_obj) => {
									bot_name = dec_obj.bot_name;
									bot_username = dec_obj.bot_username;
									http_api_token = dec_obj.http_api_token;
									
		              var result = msglib.saveTelegramBotProfile(msg_pool, bot_name, bot_username, http_api_token);
		              
		              result.then((retval) => {
		                if (retval.ok) {
		                  var html = `<script>
		                                alert("The Telegram bot profile is updated successfully"); 
		                                var url = window.location.href;
		                                var host = url.split('/');
		                                location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
		                              </script>`;
		                  
		                  res.send(html);                                                                                            
		                }
		                else {
		                  var html = `<script>
		                                alert("Unable to update Telegram bot profile. Error: ${retval.msg}"); 
		                                var url = window.location.href;
		                                var host = url.split('/');
		                                location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
		                              </script>`;
		                  
		                  res.send(html);                                                                          
		                }                
		              }).catch((error) => {
		                smslib.consoleLog(error);
		                
		                var html = `<script>
		                              alert("Unable to update Telegram bot profile. Error: ${error}"); 
		                              var url = window.location.href;
		                              var host = url.split('/');
		                              location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
		                            </script>`;
		                
		                res.send(html);                                                        
		              });
								}).catch((error) => {
									smslib.consoleLog(error);
									
                  var html = `<script>
                                alert("At lease one data is lost during data decryption, Telegram bot profile amendment is failure."); 
                                var url = window.location.href;
                                var host = url.split('/');
                                location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
                              </script>`;
                  
                  res.send(html);                                                                          																		
								})													
              }).catch((error) => {
                smslib.consoleLog(error);
                
                var html = `<script>
                              alert("Unable to get secure key in server, Telegram bot profile can't be updated. Error: ${error}"); 
                              var url = window.location.href;
                              var host = url.split('/');
                              location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
                            </script>`;
                
                res.send(html);                                                        								
							});                
            }
            else {
              //-- Something is abnormal, return user to Telegram bot profile maintenance page. --//
              var html = `<script>
                            alert("Something is abnormal, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
                          </script>`;
              
              res.send(html); 
            }
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `save_telegram_bot: User ${user_id} tries to use this function to modify Telegram bot profile, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/admin/telegram_bot_maintain';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }          
});


app.get('/create_msg_user', (req, res) => {
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
      
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        let checker = msglib.isTrustedUser(msg_pool, user_id);
        
        checker.then((is_trusted_user) => {
          if (is_trusted_user) {
            let result = smslib.printCreateUserForm();
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
                        
              let html = `<script>
                            alert("Unable to create user account adding web page. Error: ${error}"); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
              
              res.send(html);                                        
            });              
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            let msg = `create_msg_user (1): User ${user_id} tries to create new user account manually, but he/she has no corresponding right! Check for it.`;          
            smslib.consoleLog(msg);
            let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                        
          }
        }).catch((error) => {
          smslib.consoleLog(error);
                    
          let html = `<script>
                        alert("create_msg_user (GET): Unable to check whether you are trusted user, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);                        
        });          
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                        
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                            
  }  
});


app.post('/create_msg_user', (req, res) => {
	let algorithm = req.body.algorithm;                // Algorithm of AES-256 encryption used.
	let iv_name = req.body.iv_name;                    // All passwd parameters with name started with 'iv_' are IV of corresponding encrypted data. 
  let e_name = req.body.e_name;                      // All passed parameters with name started with 'e_' are encrypted. 
  let iv_user = req.body.iv_user;
  let e_user = req.body.e_user;
  let iv_alias = req.body.iv_alias;
  let e_alias = req.body.e_alias;
  let iv_email = req.body.iv_email;
  let e_email = req.body.e_email;
  let iv_happy_passwd = req.body.iv_happy_passwd;
  let e_happy_passwd = req.body.e_happy_passwd;
  let iv_unhappy_passwd = req.body.iv_unhappy_passwd;
  let e_unhappy_passwd = req.body.e_unhappy_passwd;
  let oper_mode = req.body.oper_mode;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;  
  let name = '';
  let user = '';
  let alias = '';
  let email = '';
  let happy_passwd = '';
  let unhappy_passwd = ''; 
  
  if (sess_code != '' && user_id > 0) {
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
          let checker = msglib.isTrustedUser(msg_pool, user_id);
          
          checker.then((is_trusted_user) => {
            if (is_trusted_user) {
							let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);				
							result.then((aes_key) => {
	              //-- Decrypt data set in here --//
	              let data = {iv_name: iv_name, e_name: e_name, iv_user: iv_user, e_user: e_user, iv_alias: iv_alias, e_alias: e_alias, 
									          iv_email: iv_email, e_email: e_email, iv_happy_passwd: iv_happy_passwd, e_happy_passwd: e_happy_passwd, 
									          iv_unhappy_passwd: iv_unhappy_passwd, e_unhappy_passwd: e_unhappy_passwd};
	              
	              let result = smslib.decryptUserAccountDataSet(algorithm, aes_key, data);
	              result.then((dec_obj) => {
									name = dec_obj.name;
									user = dec_obj.user;
									alias = dec_obj.alias;
									email = dec_obj.email;
									happy_passwd = dec_obj.happy_passwd;
									unhappy_passwd = dec_obj.unhappy_passwd;
									
	                let result = msglib.createUserAccount(msg_pool, user_id, name, user, alias, email, happy_passwd, unhappy_passwd);	                
	                result.then((retval) => {
	                  let html = ''; 
	                                 
	                  if (retval.ok) {
	                    //-- Create a private group for the new user, which give him/her an initial communication channel. --//
	                    let group_name = "Welcome " + name;
	                    let member = alias;
	                    let auto_delete = 1;
	                    let delete_after = 10;
	                    
	                    let grp_result = msglib.createPrivateMessageGroup(msg_pool, user_id, group_name, member, auto_delete, delete_after, http_user_agent, ip_addr);
	                    
	                    grp_result.then((retval) => {
	                      if (retval.ok) {
	                        //-- The system assume you need to create another user account --//
	                        html = `<script>
	                                  var url = window.location.href;
	                                  var host = url.split('/');
	                                  if (confirm('User account for ${name} is created successfully. Do you want to create more account?')) {
	                                    location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                                  }
	                                  else {
	                                    location.href = host[0] + '//' + host[2] + '/message';
	                                  }
	                                </script>`;
	                        
	                        res.send(html);
	                      }
	                      else {
	                        html = `<script>
	                                  alert("Although user account for ${name} is created successfully, it fails to create a private group for you and him/her. Reason: ${retval.msg}");
	                                  var url = window.location.href;
	                                  var host = url.split('/');
	                                  if (confirm('Do you want to create more account?')) {
	                                    location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                                  }
	                                  else {
	                                    location.href = host[0] + '//' + host[2] + '/message';
	                                  }
	                                </script>`;
	                        
	                        res.send(html);                        
	                      }                      
	                    }).catch((error) => {
	                      smslib.consoleLog(error);

	                      html = `<script>
	                                alert("Although user account for ${name} is created successfully, it fails to create a private group for you and him/her. Error: ${error}"); 
	                                var url = window.location.href;
	                                var host = url.split('/');
	                                if (confirm('Do you want to create more account?')) {
	                                  location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                                }
	                                else {
	                                  location.href = host[0] + '//' + host[2] + '/message';
	                                }
	                              </script>`;
	                      
	                      res.send(html);                                              
	                    });
	                  }
	                  else {
	                    html = `<script>
	                              alert("${retval.msg}"); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                            </script>`;
	                                      
	                    res.send(html);                                                                                
	                  }                    
	                }).catch((error) => {
	                  smslib.consoleLog(error);
	  
	                  var html = `<script>
	                                alert("Unable to create user account. Error: ${error}"); 
	                                var url = window.location.href;
	                                var host = url.split('/');
	                                location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                              </script>`;
	                  
	                  res.send(html);                                                          
	                });									
								}).catch((error) => {
									smslib.consoleLog(error);
									
	                let html = `<script>
	                              alert("At least one data is lost during decryption process, please try again."); 
	                              var url = window.location.href;
	                              var host = url.split('/');
	                              location.href = host[0] + '//' + host[2] + '/create_msg_user';
	                            </script>`;
	                
	                res.send(html);                                                                          									
								});	              
						  }).catch((error) => {
								smslib.consoleLog(error);

								var html = `<script>
															alert("Unable to get session key to decrypt data set, operation is failure. Error: ${error}"); 
															var url = window.location.href;
															var host = url.split('/');
															location.href = host[0] + '//' + host[2] + '/create_msg_user';
														</script>`;
								
								res.send(html);                                                          								
							});
            }
            else {
              //-- It is a suspicious activity, log it down and logout this user. --//
              var msg = `create_msg_user (2): User ${user_id} tries to create new user account manually, but he/she has no corresponding right! Check for it.`;          
              smslib.consoleLog(msg);
              var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
              result.then((ok) => {
                res.redirect('/logout_msg');  
              }).catch((error) => {
                smslib.consoleLog(error);
                res.redirect('/logout_msg');
              });                                                                                        
            }
          }).catch((error) => {
            smslib.consoleLog(error);
                      
            var html = `<script>
                          alert("create_msg_user (POST): Unable to check whether you are trusted user, process is aborted."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
            
            res.send(html);                                      
          });
        }
        else {
          //-- Something is not right, may be a hacking activity of insider. Just turn him/her back. --//
          res.redirect('/message');                                
        }
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                                              
  }
});

 
app.get('/do_sms', (req, res) => {
  var group_id = (typeof(req.query.g_id) == 'undefined')? 0 : parseInt(req.query.g_id, 10);        // Message group ID
  var f_m_id = (typeof(req.query.f_m_id) == 'undefined')? '' : req.query.f_m_id;                   // The ID of the first message which has already loaded.    
  var top_id = (typeof(req.query.top_id) == 'undefined')? '' : req.query.top_id;                   // The ID of the first message of this group and this user. 
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var client_device_info = req.device;                 // Defined in the client device detection middleware
  var http_user_agent = req.useragent;                 // Defined in the client device detection middleware

  if (sess_code != '' && user_id > 0 && group_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isUserGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {          
            var result = smslib.showDoSMSpage(msg_pool, user_id, group_id, f_m_id, top_id, client_device_info, http_user_agent);
        
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
          
              var html = `<script>
                            alert("Error is found, please try again."); 
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/message';
                          </script>`;
    
              res.send(html);           
            });
          }
          else {
            //-- An insider may try to hack the system, in order to access messages of another group. --//
            var html = `<script>
                          alert("You are not member of this message group, please leave."); 
                          var url = window.location.href;
                          var host = url.split('/');
                          location.href = host[0] + '//' + host[2] + '/message';
                        </script>`;
                        
            var detail_msg = `User ${user_id} tries to break in message group ${group_id}, check for it.`;
            var result = smslib.logSystemEvent(msg_pool, user_id, detail_msg, 'Alert', http_user_agent);
            result.then((value) => {
              res.send(html);  
            }).catch((error) => {
              res.send(html);
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Error is found, please try again."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
    
          res.send(html);                     
        });
      }
      else {
        var html = `<script>
                      alert("Session has expired, please login again."); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/';
                    </script>`;
    
        res.send(html);         
      }
    }).catch((error) => {
      smslib.consoleLog(error);

      var html = `<script>
                    alert("Unable to verify your identity, please login again."); 
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/';
                  </script>`;
    
      res.send(html);                        
    });
  }
  else {
    //-- No session cookie is found or invalid group ID is given, return to login page immediately. --//
    res.redirect('/');    
  }  
});


//-- 2023-12-10 DW: Freeze this function until it is used later --//
/*
app.post('/push_aes_key', (req, res) => {
  let curr_user_id = req.body.user_id;
  let aes_key = req.body.aes_key;
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
    
  if (sess_code != '' && user_id > 0) { 
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, false, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (curr_user_id == user_id) {
					let result = smslib.updateSessionSecureKey(msg_pool, user_id, sess_code, aes_key);
					
					result.then((ret_val) => {
						res.send(JSON.stringify(ret_val));
					}).catch((error) => {
						smslib.consoleLog(error);
						let data = {ok: "0", msg: error};
						res.send(JSON.stringify(data)); 
					});
				}
				else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          var msg = `push_aes_key: User ${user_id} tries to amend AES key from another user ${curr_user_id}! Check for it.`;          
          smslib.consoleLog(msg);
          var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          					
				}
			}
			else {
				res.redirect('/');
			}
		}).catch((error) => {
      smslib.consoleLog(error);
      res.redirect('/');			
		});        		
	}
	else {
    //-- No session cookie is found or invalid user ID is given, return to login page immediately. --//
    res.redirect('/');        		
	}  	
});
*/

app.post('/load_message', (req, res) => {
  var group_id = req.body.group_id;
  var curr_user_id = req.body.user_id;
  var m_params = JSON.parse(req.body.m_params);
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var client_device_info = req.device;                 // Defined in the client device detection middleware    
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
      
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, false, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (curr_user_id == user_id) {        
          var result = msglib.loadGroupMessages(msg_pool, group_id, user_id, m_params, sess_code, client_device_info, http_user_agent);
          
          result.then((data) => {
            res.send(JSON.stringify(data));          
          }).catch((error) => {
            smslib.consoleLog(error);
            var data = {update_token: 'error', message: []};
            res.send(JSON.stringify(data));                                        
          });        
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          var msg = `load_message: User ${user_id} tries to steal messages from another user ${curr_user_id}! Check for it.`;          
          smslib.consoleLog(msg);
          var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        res.redirect('/');
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      res.redirect('/');                              
    });
  }
  else {
    //-- No session cookie is found or invalid user ID is given, return to login page immediately. --//
    res.redirect('/');        
  }
});


app.post('/check_message_update_token', (req, res) => {
  var group_id = req.body.group_id;
  var curr_user_id = req.body.user_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);  
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
    
  group_id = (typeof(group_id) == 'undefined' || group_id == null)? 0 : parseInt(group_id, 10);
  user_id = (typeof(user_id) == 'undefined' || user_id == null)? 0 : parseInt(user_id, 10);
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, false, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (curr_user_id == user_id) {
          var checker = msglib.checkMessageUpdateToken(msg_pool, group_id, user_id);
          
          checker.then((token) => {
            res.send(JSON.stringify(token));          
          }).catch((error) => {
            smslib.consoleLog(error);
            var result = {mg_status: {update_token: 'error'}};
            res.send(JSON.stringify(result));                                        
          });
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          var msg = `check_message_update_token: User ${user_id} tries to pretend another user ${curr_user_id}! Check for it.`;          
          smslib.consoleLog(msg);
          var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });
        }        
      }
      else {
        var result = {mg_status: {update_token: 'expired'}};
        res.send(JSON.stringify(result));
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      var result = {mg_status: {update_token: 'error'}};
      res.send(JSON.stringify(result));                              
    });
  }
  else {
    //-- No session cookie is found or invalid user ID is given, return to login page immediately. --//
    res.redirect('/');        
  }
});


app.post('/pull_new_message', (req, res) => {
  var group_id = req.body.group_id;
  var receiver_id = req.body.receiver_id;
  var last_sent_msg_only = (parseInt(req.body.last_sent_msg_only, 10) == 1)? true : false;
  var omid_list = req.body.omid_list;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var client_device_info = req.device;                 // Defined in the client device detection middleware
  var http_user_agent = req.useragent;                 // Defined in the client device detection middleware  
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    if (user_id == receiver_id) {    
      var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, false, 'MSG');
      sess_checker.then((sess_valid) => {
        if (sess_valid) {
          if (last_sent_msg_only) {
            //-- Get your last sent message only, since you just send a message --//
            var result = msglib.getLastSentMessage(msg_pool, group_id, receiver_id, sess_code, client_device_info, http_user_agent);
            
            result.then((message) => {
              //-- Note: 'message' is an array --//
              res.send(JSON.stringify(message));
            }).catch((error) => {
              smslib.consoleLog(error);
              var err_msg = {msg_status: 'error', message: error};
              var err_arr = [];
              err_arr.push(err_msg);
              res.send(JSON.stringify(err_arr));
            });          
          }
          else {
            //-- Get only those messages you don't read before --//
            var m_params = {new_msg_only: 1};
            var result = msglib.getGroupMessageViaDbPool(msg_pool, group_id, receiver_id, m_params, sess_code, client_device_info, http_user_agent);      
            
            result.then((message) => {
              //-- Note: 'message' is an array --//
              if (message.length == 0) {
                //-- It means that another group member just delete his/her message(s), NOT add new message(s). --//
                //-- Note: For private groups, the system may delete messages automatically, include your       --//
                //-- messages. Therefore, 'omid_list' should include messages ID belong to you.                --// 
                var result = msglib.getDeletedMessageIdList(msg_pool, receiver_id, omid_list);
                
                result.then((message) => {
                  res.send(JSON.stringify(message));  
                }).catch((error) => {
                  smslib.consoleLog(error);
                  var err_msg = {msg_status: 'error', message: error};
                  var err_arr = [];
                  err_arr.push(err_msg);
                  res.send(JSON.stringify(err_arr));                  
                });
              }
              else {
                res.send(JSON.stringify(message));                          
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              var err_msg = {msg_status: 'error', message: error};
              var err_arr = [];
              err_arr.push(err_msg);
              res.send(JSON.stringify(err_arr));            
            });
          }
        }
        else {
          //-- The session is invalid, return to login page immediately. --//
          res.redirect('/');            
        }
      }).catch((error) => {
        //-- The session checking process is failure, return to login page immediately. --//
        smslib.consoleLog(error);
        res.redirect('/');          
      });    
    }
    else {
      //-- Potential hacking activity is performed by insider --//
      var detail_msg = `pull_new_message: User ${user_id} is trying to steal message(s) from user ${receiver_id}.`;      
      var result = smslib.logSystemEvent(msg_pool, user_id, detail_msg, 'Alert', http_user_agent);
      
      result.then((value) => {
        smslib.consoleLog(detail_msg);
        //-- Kick this guy out immediately --//
        res.redirect('/logout_msg');               
      }).catch((error) => {
        smslib.consoleLog(detail_msg);
        smslib.consoleLog('Unable to log this event. Error: ' + error);
        //-- Kick this guy out immediately, even his action can't be logged down. --// 
        res.redirect('/logout_msg');                       
      });
    }
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');        
  }  
});


app.post('/pull_prev_message', (req, res) => {
  var group_id = req.body.group_id;
  var receiver_id = req.body.receiver_id;
  var first_msg_id = req.body.first_msg_id;
  var rows_limit = req.body.rows_limit;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie); 
  var client_device_info = req.device;                 // Defined in the client device detection middleware   
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    if (receiver_id == user_id) {
      var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
      sess_checker.then((sess_valid) => {
        if (sess_valid) {
          var result = msglib.getPrevGroupMessage(msg_pool, group_id, user_id, first_msg_id, rows_limit, sess_code, client_device_info, http_user_agent, ip_addr);
          
          result.then((message) => {
            //-- 'message' is an array with structure {msg_status: 'xxxxx', message: stringified_message_array} --//
            res.send(JSON.stringify(message));
          }).catch((error) => {
            smslib.consoleLog(error);
            var err_msg = {msg_status: 'error', message: error};
            var err_arr = [];
            err_arr.push(err_msg);
            res.send(JSON.stringify(err_arr));                  
          });
        }
        else {
          var html = `<script>
                        alert("Session has expired, please login again."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/';                     
                      </script>`;
                      
          res.send(html);                      
        }
      }).catch((error) => {
        var html = `<script>
                      alert("Unable to verify your session, please login again."); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/';                     
                    </script>`;
                    
        res.send(html);            
      });      
    }
    else {
      //-- Potential hacking activity is performed by insider --//
      var detail_msg = `pull_prev_message: User ${user_id} is trying to steal message(s) from user ${receiver_id}.`;      
      var result = smslib.logSystemEvent(msg_pool, user_id, detail_msg, 'Alert', http_user_agent);
      
      result.then((value) => {
        smslib.consoleLog(brief_msg + ': ' + detail_msg);
        //-- Kick this guy out immediately --//
        res.redirect('/logout_msg');               
      }).catch((error) => {
        smslib.consoleLog(brief_msg + ': ' + detail_msg);
        smslib.consoleLog('Unable to log this event. Error: ' + error);
        //-- Kick this guy out immediately, even his action can't be logged down. --// 
        res.redirect('/logout_msg');                       
      });
    }
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');        
  }  
});


app.post('/send_message', (req, res) => {
  let group_id = req.body.group_id;
  let sender_id = req.body.sender_id;
  let algorithm = req.body.algorithm;       // AES algorithm used for message encryption and decryption. 
  let msg_iv = req.body.msg_iv;             // IV of encrypted message in stringified JSON format.
  let message = req.body.message;           // Note: 'message' is encrypted and in stringified JSON format, so it needs to be decrypted before using. 
  let op_flag = req.body.op_flag;
  let op_user_id = req.body.op_user_id;
  let op_iv = req.body.op_iv;               // IV of encrypted OP message in stringified JSON format.
  let op_msg = req.body.op_msg;             // Note: 'op_msg' is encrypted and in stringified JSON format.
  
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  
  let decrypted_msg, decrypted_op_msg;

  group_id = (typeof(group_id) == 'undefined' || group_id == null)? 0 : parseInt(group_id, 10);
  sender_id = (typeof(sender_id) == 'undefined' || sender_id == null)? 0 : parseInt(sender_id, 10);
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
				let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
				
				result.then((aes_key) => {
				  //-- Decrypt 'message' and 'op_msg' in here --// 
	        let result = cipher.aesDecryptJSON(algorithm, aes_key, msg_iv, message);
	        result.then((dec_msg) => {
						decrypted_msg = dec_msg;
						
						let result = cipher.aesDecryptJSON(algorithm, aes_key, op_iv, op_msg);						
						result.then((dec_op_msg) => {
							decrypted_op_msg = dec_op_msg;
							
							let result = msglib.sendMessage(msg_pool, group_id, sender_id, decrypted_msg, '', op_flag, op_user_id, decrypted_op_msg, http_user_agent, ip_addr);
							
			        result.then((mg_status) => {
			          res.send(JSON.stringify(mg_status));
			        }).catch((error) => {
			          smslib.consoleLog(error);
			          res.send(JSON.stringify({mg_status: {update_token: 'error'}}));
			        });        							
						}).catch((error) => {
							smslib.consoleLog(error);
							res.send(JSON.stringify({mg_status: {update_token: 'error'}}));							
						});						
					}).catch((error) => {
						smslib.consoleLog(error);
						res.send(JSON.stringify({mg_status: {update_token: 'error'}}));
					});
			  }).catch((error) => {
	        smslib.consoleLog(error);
	        res.send(JSON.stringify({mg_status: {update_token: 'error'}}));					
				});
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');          
    });    
  }  
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');            
  }  
});


function _returnToMessageGroup(group_id, err_msg) {
  var html, say_alert;
 
  if (typeof(err_msg) == 'string') {
    if (err_msg.trim() != '') {  
      say_alert = `alert("${err_msg}")`;
    }
    else {
      say_alert = '';
    }
  }
  else {
    say_alert = '';
  }
 
  html = `
  <script src="/js/js.cookie.min.js"></script>
  <script src="/js/common_lib.js"></script>
  
  <script>
    ${say_alert}
    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
    var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");        // Defined on common_lib.js : js.cookie.min.js
    var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");
    window.location.href = "/do_sms?g_id=${group_id}&f_m_id=" + f_m_id + "&top_id=" + top_id;
  </script>`;
  
  return html;
}


//-- For group name update --//
app.post('/change_group_name', (req, res) => {
  var group_id = req.body.g_id;
  var group_name = req.body.group_name;  
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);  
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  
  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (parseInt(group_id, 10) > 0 && wev.allTrim(group_name) != '') {         
          var result = msglib.isGroupMember(msg_pool, user_id, group_id);
          
          result.then((is_member) => {
            if (is_member) {
              var result = smslib.updateGroupName(msg_pool, group_id, group_name);
              
              result.then(() => {
                res.send(_returnToMessageGroup(group_id));
              }).catch((error) => {
                smslib.consoleLog(error);
                res.send(_returnToMessageGroup(group_id, 'Fail to change group name. Error: ' + error));
              });             
            }
            else {
              res.send(_returnToMessageGroup(group_id, 'You are not group member!'));
            }
          }).catch((error) => {
            smslib.consoleLog(error);
            res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
          });
        }
        else {
          res.send(_returnToMessageGroup(group_id, 'Invalid data is found, no update.'));          
        }        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });    
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                    
  }
});


//-- Show group name amendment page --//
app.get('/change_group_name', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = smslib.showGroupNameAmendPage(msg_pool, group_id);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
            });             
          }
          else {
            res.send(_returnToMessageGroup(group_id, 'You are not group member!'));
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }
});


app.get('/list_group_member', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = smslib.listGroupMember(msg_pool, group_id);
            
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
            });             
          }
          else {
            res.send(_returnToMessageGroup(group_id, 'You are not group member!'));
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }
});


app.get('/exit_group', (req, res) => {
  var group_id = req.query.g_id;
  var member_id = req.query.member_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {        
        if (member_id == user_id) {     // Only you can make yourself to quit a message group via this function.
          var result = smslib.quitMessageGroup(msg_pool, group_id, member_id);
          
          result.then(() => {
            var html = `
              <script src="/js/js.cookie.min.js"></script>
              <script src="/js/common_lib.js"></script>
              
              <script>
                var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
                
                if (is_iOS) {
                  Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
                  Cookies.remove("u_id");
                  Cookies.remove("m_id");
                }
                else {
                  deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
                  deleteLocalStoredItem("u_id");                             
                  deleteLocalStoredItem("m_id");                             
                }
                
                window.location.href = "/message";
              </script>`;
            
            res.send(html);
          }).catch((error) => {
            smslib.consoleLog(error);
            res.send(_returnToMessageGroup(group_id, 'Fail to exit group. Error: ' + error));
          });             
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          var msg = `exit_group: User ${user_id} tries to use this function to kick out user ${member_id} from group ${group_id}! Check for it.`;          
          smslib.consoleLog(msg);
          var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });
        }        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }
});


//-- Save added group member(s) --//
app.post('/add_group_member', (req, res) => {
  var group_id = req.body.g_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  var new_members = [];    // Note: Since we can't verify given user alias at this moment, so it is just a proposed list, not the finalized list.
  
  //-- Collect alias of all proposed new members here --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/new_member_/)) {
      var this_member = req.body[this_key];
      if (this_member.trim() != '') {
        new_members.push(this_member); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.addNewMemberToGroup(msg_pool, group_id, user_id, new_members, http_user_agent, ip_addr);
                
                result.then((msg) => {
                  res.send(_returnToMessageGroup(group_id, msg));
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to add new member(s). Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to add member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to add group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_group_member (2): User ${user_id} tries to use this function to add member to group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }  
});


//-- Show group member adding web page --//
app.get('/add_group_member', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = smslib.showAddGroupMemberPage(group_id);
                
                result.then((html) => {
                  res.send(html);
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to add member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to add group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `add_group_member (1): User ${user_id} tries to use this function to add member to group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }  
});


//-- Group member deletion update --//
app.post('/delete_group_member', (req, res) => {
  var group_id = req.body.g_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  var delete_members = [];    
    
  //-- Collect user ID of all members to be deleted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/dm_id_/)) {
      var this_member = req.body[this_key];
      if (parseInt(this_member, 10) != 0) {
        delete_members.push(parseInt(this_member, 10)); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.removeMemberFromGroup(msg_pool, group_id, delete_members);
                
                result.then(() => {
                  res.send(_returnToMessageGroup(group_id, 'Success'));
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to delete member(s). Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to remove member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to remove group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `delete_group_member (2): User ${user_id} tries to use this function to delete member from group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }    
});


//-- Show group member deletion web page --//
app.get('/delete_group_member', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = smslib.showDeleteGroupMemberPage(msg_pool, group_id, user_id);
                
                result.then((html) => {
                  res.send(html);
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to remove member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to remove group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `delete_group_member (1): User ${user_id} tries to use this function to delete member from group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }    
});


//-- Group member promotion update --//
app.post('/promote_group_member', (req, res) => {
  var group_id = req.body.g_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  var promote_members = [];    
    
  //-- Collect user ID of all members to be promoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/pm_id_/)) {
      var this_member = req.body[this_key];
      if (parseInt(this_member, 10) != 0) {
        promote_members.push(parseInt(this_member, 10)); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.promoteGroupMember(msg_pool, group_id, promote_members);
                
                result.then(() => {
                  res.send(_returnToMessageGroup(group_id, 'Success'));
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to promote member(s). Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to promote member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to promote group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `promote_group_member (2): User ${user_id} tries to use this function to promote member in group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }      
});


//-- Show group member promotion web page --//
app.get('/promote_group_member', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = smslib.showPromoteGroupMemberPage(msg_pool, group_id, user_id);
                
                result.then((html) => {
                  res.send(html);
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to promote member!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to promote group member'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `promote_group_member (1): User ${user_id} tries to use this function to promote member in group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }      
});


// Group admin demote update --//
app.post('/demote_group_admin', (req, res) => {
  var group_id = req.body.g_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  var demote_admin = [];    
    
  //-- Collect user ID of all administrators to be demoted --//  
  var keys = Object.keys(req.body);
  for (var i = 0; i < keys.length; i++) {
    var this_key = keys[i];
    if (this_key.match(/da_id_/)) {
      var this_member = req.body[this_key];
      if (parseInt(this_member, 10) != 0) {
        demote_admin.push(parseInt(this_member, 10)); 
      }
    }    
  }
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.demoteGroupAdmin(msg_pool, group_id, demote_admin);
                
                result.then(() => {
                  res.send(_returnToMessageGroup(group_id, 'Success'));
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to demote admin(s). Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to demote group administrator!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to demote group administrator'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `demote_group_admin (2): User ${user_id} tries to use this function to demote administrator in group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }        
});


//-- Show group admin demote web page --//
app.get('/demote_group_admin', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = smslib.showDemoteGroupAdminPage(msg_pool, group_id, user_id);
                
                result.then((html) => {
                  res.send(html);
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to demote group administrator!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to demote group administrator'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `demote_group_member (1): User ${user_id} tries to use this function to demote group administrator in group ${group_id} which he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }        
});


app.post('/inform_member', (req, res) => {
  var group_id = req.body.g_id;
  var inform_message = req.body.inform_message
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
      
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.sendGroupInformMessage(msg_pool, group_id, inform_message);
                
                result.then((msg) => {
                  res.send(_returnToMessageGroup(group_id, msg));
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to inform members. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to inform group member manually!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to inform group member manually'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `inform_member (2): User ${user_id} tries to use this function to inform all group ${group_id} members manually but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }          
});


app.get('/inform_member', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = smslib.showManualInformMemberPage(group_id);
                
                result.then((html) => {
                  res.send(html);
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to generate web page. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to inform group member manually!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to inform group member manually'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `inform_member (1): User ${user_id} tries to use this function to inform all group ${group_id} members manually but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }          
});


app.get('/delete_group', (req, res) => {
  var group_id = req.query.group_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;
  var members = [];

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.hasRightToMgtMember(msg_pool, group_id, user_id);
            
            result.then((has_right) => {
              if (has_right) {
                var result = msglib.getMessageGroupMembersViaPool(msg_pool, group_id);
                
                result.then((group_members) => {
                  members = group_members;
                  
                  //-- Delete all messages, delivery transactions and attached files of --//
                  //-- the message group.                                               --// 
                  var result = msglib.deleteMessageGroup(msg_pool, group_id);
                  
                  result.then((ok) => {
                    if (ok) {
                      //-- Build a web page to inform all group members the group has been --//
                      //-- deleted via websocket.                                          --// 
                      var result = smslib.buildGroupDeletedInformHTML(msg_pool, group_id, members);
                      
                      result.then((html) => {
                        res.send(html);                      
                      }).catch((error) => {
                        smslib.consoleLog(error);
                        res.redirect('/message');
                      }); 
                    }
                    else {
                      res.send(_returnToMessageGroup(group_id, 'Unable to delete message group.'));
                    }
                  }).catch((error) => {
                    smslib.consoleLog(error);
                    res.send(_returnToMessageGroup(group_id, 'Fail to delete message group. Error: ' + error));                    
                  });
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Fail to get group members, operation is aborted. Error: ' + error));
                });             
              }
              else {
                //-- It is a suspicious activity, but not very serious. So, just turn him/her back. --// 
                res.send(_returnToMessageGroup(group_id, 'You have no right to delete group!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether you have right to delete group'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `delete_group: User ${user_id} tries to use this function to delete message group ${group_id} but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }            
});


//-- Save auto delete setup data --//
app.post('/auto_delete_setup', (req, res) => {
  var group_id = req.body.g_id;
  var auto_delete = req.body.auto_delete;
  var delete_after = req.body.delete_after;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;  
  
  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.isPrivateGroup(null, group_id);
                        
            result.then((is_private_group) => {
              if (is_private_group) {
                var result = msglib.updateAutoDeleteSettings(msg_pool, group_id, auto_delete, delete_after);
                
                result.then(() => {
                  res.send(_returnToMessageGroup(group_id, 'Updated!'));                      
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Unable to save auto delete settings. Error: ' + error));
                });             
              }
              else {
                res.send(_returnToMessageGroup(group_id, 'It is not a private group!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether it is a private group'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `auto_delete_setup (2): User ${user_id} tries to use this function to change message auto delete settings of private group ${group_id} but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }            
});


//-- Show auto delete setup web page for a private group --//
app.get('/auto_delete_setup', (req, res) => {
  var group_id = req.query.g_id;                             // Message group ID
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.isPrivateGroup(null, group_id);
                        
            result.then((is_private_group) => {
              if (is_private_group) {
                var result = smslib.showAutoDeleteSetupForm(msg_pool, group_id);
                
                result.then((html) => {
                  res.send(html);                      
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send(_returnToMessageGroup(group_id, 'Unable to create auto delete setup web page. Error: ' + error));
                });             
              }
              else {
                res.send(_returnToMessageGroup(group_id, 'It is not a private group!'));
              }
            }).catch((error) => {
              smslib.consoleLog(error);
              res.send(_returnToMessageGroup(group_id, 'Unable to determine whether it is a private group'));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `auto_delete_setup (1): User ${user_id} tries to use this function to change message auto delete settings of private group ${group_id} but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          res.send(_returnToMessageGroup(group_id, 'Unable to verify your group membership'));
        });        
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                    
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }            
});


//-- Show message forwarding page only --//
app.get('/forward_message', (req, res) => {
  var from_group_id = req.query.from_group_id;
  var msg_id = req.query.msg_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  from_group_id = (typeof(from_group_id) == 'undefined' || from_group_id == null)? 0 : parseInt(from_group_id, 10);

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, from_group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = smslib.showForwardMessageForm(msg_pool, from_group_id, user_id, msg_id, sess_code, http_user_agent, ip_addr);        
            result.then((html) => {
              res.send(html);
            }).catch((error) => {
              //-- Error is found, return to calling message group. --//
              smslib.consoleLog(error);          
              var html = `<script src="/js/js.cookie.min.js"></script>
                          <script src="/js/common_lib.js"></script>
                          <script>
                            alert("Unable to forward message, error is found.");
                            var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
                            var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
                            var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
                            var url = window.location.href;
                            var host = url.split('/');
                            location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
                          </script>`;
              
              res.send(html);
            });        
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `forward_message (1): User ${user_id} tries to use this function to forward message from group ${from_group_id} but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        });
      }
      else {
        //-- The session has expired, force logout immediately. --//
        var html = `<script>
                      alert("Session expired!"); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/logout_msg';
                    </script>`;
        
        res.send(html);        
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to calling message group. --//
      smslib.consoleLog(error);
      var html = `<script src="/js/js.cookie.min.js"></script>
                  <script src="/js/common_lib.js"></script>
                  <script>
                    alert("Unable to verify session status, message forwarding process is aborted."); 
                    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
                    var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
                    var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
                  </script>`;
      
      res.send(html);
    });    
  }  
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');            
  }  
});


//-- Use for message forwarding saving process only --//
app.post('/forward_message', (req, res) => {
  let oper_mode = wev.allTrim(req.body.oper_mode);
  let from_group_id = req.body.from_group_id;
  let to_group_id = req.body.to_group_id;
  let msg_id = req.body.msg_id;
  let algorithm = req.body.algorithm;
  let a_iv = req.body.a_iv;                             // IV of the encrypted 'a_message' in JSON string format.
  let a_message = req.body.a_enc_msg;                   // Note: 'a_message' is encrypted and in JSON string format, so it needs to be decrypted before using.
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;  
  
  if (sess_code != '' && user_id > 0) {  
    let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (oper_mode == 'S') {
					//-- Make sure the user is the member of both message groups --//
          let result = msglib.isGroupMember(msg_pool, user_id, from_group_id);
          
          result.then((is_member) => {
            if (is_member) {
              let result = msglib.isGroupMember(msg_pool, user_id, to_group_id);
              
              result.then((is_member) => {
                if (is_member) {
									let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
									
									result.then((aes_key) => {
                    //-- Decrypt 'a_message' here --//
                    let result = cipher.aesDecryptJSON(algorithm, aes_key, a_iv, a_message);
                    
                    result.then((decrypt_msg) => {
		                  let result = msglib.forwardMessage(msg_pool, from_group_id, to_group_id, user_id, msg_id, decrypt_msg, http_user_agent, ip_addr);
		                  result.then((html) => {
		                    res.send(html);
		                  }).catch((error) => {
		                    //-- Error is found, return to calling message group. --//
		                    smslib.consoleLog(error);          
		                    let html = `<script src="/js/js.cookie.min.js"></script>
		                                <script src="/js/common_lib.js"></script>
		                                <script>
		                                  alert("Error #3: Unable to forward message, error is found.");
		                                  var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
		                                  var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
		                                  var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
		                                  var url = window.location.href;
		                                  var host = url.split('/');
		                                  location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
		                                </script>`;
		                    
		                    res.send(html);            
		                  });                       											
										}).catch((error) => {
											smslib.consoleLog(error);
	                    let html = `<script src="/js/js.cookie.min.js"></script>
	                                <script src="/js/common_lib.js"></script>
	                                <script>
	                                  alert("Error #2: Additional forward message is lost on decryption process, error is found.");
	                                  var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
	                                  var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
	                                  var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
	                                  var url = window.location.href;
	                                  var host = url.split('/');
	                                  location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
	                                </script>`;
	                    
	                    res.send(html);            											
										});                    																		
								  }).catch((error) => {
                    //-- Unable to get the session AES key stored on server to decrypt forward message, return to calling message group. --//
                    smslib.consoleLog(error);          
                    let html = `<script src="/js/js.cookie.min.js"></script>
                                <script src="/js/common_lib.js"></script>
                                <script>
                                  alert("Error #1: Unable to forward message, error is found.");
                                  var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
                                  var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
                                  var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
                                  var url = window.location.href;
                                  var host = url.split('/');
                                  location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
                                </script>`;
                    
                    res.send(html);            										
									});   
                }
                else {
                  //-- It is a suspicious activity, log it down and logout this user. --//
                  var msg = `forward_message (2): User ${user_id} tries to use this function to forward message to group ${to_group_id} but he/she is not member! Check for it.`;          
                  smslib.consoleLog(msg);
                  var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
                  result.then((ok) => {
                    res.redirect('/logout_msg');  
                  }).catch((error) => {
                    smslib.consoleLog(error);
                    res.redirect('/logout_msg');
                  });
                }
              });            
            }
            else {
              //-- It is a suspicious activity, log it down and logout this user. --//
              var msg = `forward_message (2): User ${user_id} tries to use this function to forward message from group ${from_group_id} but he/she is not member! Check for it.`;          
              smslib.consoleLog(msg);
              var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
              result.then((ok) => {
                res.redirect('/logout_msg');  
              }).catch((error) => {
                smslib.consoleLog(error);
                res.redirect('/logout_msg');
              });
            }
          });
        }
        else {
          //-- Invalid oper_mode is found, return to message forwarding landing page --// 
          //-- Warning: Normally user is unable to reach this point when value of oper_mode is not 'S', so it --//
          //--          might be a sign of hacking activity.                                                  --//
          var detail_msg = `forward_message (2): User ${user_id} is able to get into message forwarding function by improper way, check for it.`;
          var result = smslib.logSystemEvent(msg_pool, user_id, detail_msg, 'Alert', http_user_agent);
          result.then((value) => {
            res.send("/forward_message?from_group_id=" + from_group_id + "&msg_id=" + msg_id);  
          }).catch((error) => {
            res.send("/forward_message?from_group_id=" + from_group_id + "&msg_id=" + msg_id);
          });
        }
      }
      else {
        //-- The session has expired, force logout immediately. --//
        var html = `<script>
                      alert("Session expired!"); 
                      var url = window.location.href;
                      var host = url.split('/');
                      location.href = host[0] + '//' + host[2] + '/logout_msg';
                    </script>`;
        
        res.send(html);                
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to calling message group. --//
      smslib.consoleLog(error);
      var html = `<script src="/js/js.cookie.min.js"></script>
                  <script src="/js/common_lib.js"></script>
                  <script>
                    alert("Unable to verify session status, message forwarding process is aborted."); 
                    var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);
                    var f_m_id = (is_iOS == false)? getLocalStoredItem("m_id") : Cookies.get("m_id");         // Defined on common_lib.js : js.cookie.min.js
                    var top_id = (is_iOS == false)? getLocalStoredItem("top_id") : Cookies.get("top_id");                         
                    var url = window.location.href;
                    var host = url.split('/');
                    location.href = host[0] + '//' + host[2] + '/do_sms?g_id=' + ${from_group_id} + '&f_m_id=' + f_m_id + '&top_id=' + top_id;
                  </script>`;
      
      res.send(html);
    });    
  }  
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');                
  }
});


app.post('/upload_files', (req, res) => {
  let group_id = req.body.group_id;
  let sender_id = req.body.sender_id;
  let ul_ftype = req.body.ul_ftype;
  let upload_file = req.files;                 // Note: The upload file object is handled by 'fileUpload', not 'bodyParser'.
  let algorithm = req.body.algorithm;
  let caption_iv = req.body.caption_iv;        // IV of encrypted caption in JSON string format.
  let caption = req.body.caption;              // caption is encrypted and in JSON string format.
  let op_flag = req.body.op_flag;
  let op_user_id = req.body.op_user_id;
  let op_iv = req.body.op_iv;                  // IV of encrypted op_msg in JSON string format.
  let op_msg = req.body.op_msg;                // op_msg is encrypted and in JSON string format.
  let cookie = req.cookies.MSG_USER;
  let user_id = wev.getSessionUserId(cookie);
  let sess_code = wev.getSessionCode(cookie);  
  let http_user_agent = req.headers['user-agent'];
  let ip_addr = req.ip;
  let decrypt_caption = '';
  let decrypt_op_msg = '';
    
  group_id = (typeof(group_id) == 'undefined' || group_id == null)? 0 : parseInt(group_id, 10);
  sender_id = (typeof(sender_id) == 'undefined' || sender_id == null)? 0 : parseInt(sender_id, 10);
  
  if (sess_code != '' && user_id > 0) {
    if (!upload_file || Object.keys(upload_file).length == 0) {
      smslib.consoleLog("Warning: No files were uploaded.");
      res.send('error');  
    }
    else {  
      let sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
      sess_checker.then((sess_valid) => {
        if (sess_valid) {
          let result = msglib.isGroupMember(msg_pool, user_id, group_id);
          
          result.then((is_member) => {
            if (is_member) {
              if (user_id == sender_id) {
								let result = msglib.getSessionSecureKey(msg_pool, user_id, sess_code);
								
								result.then((aes_key) => {
								  //-- Decrypt 'caption' and 'op_msg' here --//							
							    let result = cipher.aesDecryptJSON(algorithm, aes_key, caption_iv, caption);
							    result.then((dec_caption) => {
										decrypt_caption = dec_caption;
										
										let result = cipher.aesDecryptJSON(algorithm, aes_key, op_iv, op_msg);
										result.then((dec_op_msg) => {
											decrypt_op_msg = dec_op_msg;
											
			                let result = msglib.uploadFileToMessageGroup(msg_pool, group_id, sender_id, ul_ftype, upload_file, decrypt_caption, op_flag, op_user_id, decrypt_op_msg, http_user_agent, ip_addr);
			                result.then((token) => {
			                  res.send(token);
			                }).catch((error) => {
			                  smslib.consoleLog(error);
			                  res.send('error');
			                });											
										}).catch((error) => {
		                  smslib.consoleLog(error);
		                  res.send('error');																					
										});
									}).catch((error) => {
	                  smslib.consoleLog(error);
	                  res.send('error');										
									});
							  }).catch((error) => {
                  smslib.consoleLog(error);
                  res.send('error');									
								});
              }
              else {
                //-- It is a suspicious activity, log it down and logout this user. --//
                let msg = `upload_files: User ${user_id} tries to pretend another user ${sender_id} to upload file to group ${group_id}! Check for it.`;          
                smslib.consoleLog(msg);
                let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
                result.then((ok) => {
                  res.redirect('/logout_msg');  
                }).catch((error) => {
                  smslib.consoleLog(error);
                  res.redirect('/logout_msg');
                });                
              }
            }
            else {
              //-- It is a suspicious activity, log it down and logout this user. --//
              let msg = `upload_files: User ${user_id} tries to use this function to upload file to group ${group_id} but he/she is not member! Check for it.`;          
              smslib.consoleLog(msg);
              let result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
              result.then((ok) => {
                res.redirect('/logout_msg');  
              }).catch((error) => {
                smslib.consoleLog(error);
                res.redirect('/logout_msg');
              });
            }
          });
        }
        else {
          res.send('sess_expired');        
        }
      }).catch((error) => {
        smslib.consoleLog(error);
        res.send('error');              
      });
    }
  }  
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');            
  }  
});


app.post('/delete_message', (req, res) => {
  var group_id = req.body.group_id;
  var msg_id = req.body.msg_id;
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);
  var http_user_agent = req.headers['user-agent'];
  var ip_addr = req.ip;

  group_id = (typeof(group_id) == 'undefined' || group_id == null)? 0 : parseInt(group_id, 10);

  if (sess_code != '' && user_id > 0) {  
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var result = msglib.isGroupMember(msg_pool, user_id, group_id);
        
        result.then((is_member) => {
          if (is_member) {
            var result = msglib.deleteMessage(msg_pool, group_id, user_id, msg_id, http_user_agent, ip_addr);
            result.then((token) => {
              var ret_data = {mg_status: {update_token: token}};
              res.send(JSON.stringify(ret_data));
            }).catch((error) => {
              smslib.consoleLog(error);
              var ret_data = {mg_status: {update_token: 'error'}};
              res.send(JSON.stringify(ret_data));
            });
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `delete_message: User ${user_id} tries to use this function to delete message for another group ${group_id} but he/she is not member! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });
          }
        });
      }
      else {
        var ret_data = {mg_status: {update_token: 'sess_expired'}};
        res.send(JSON.stringify(ret_data));        
      }
    }).catch((error) => {
      smslib.consoleLog(error);
      var ret_data = {mg_status: {update_token: 'error'}};
      res.send(JSON.stringify(ret_data));              
    });
  }  
  else {
    //-- No session cookie is found, return to login page immediately. --//
    res.redirect('/');            
  }  
});


app.get('/read_news', (req, res) => {
  // Note: Received parameters are unescape automatically, and token stored in 'login_token_queue' is in escaped format.
  //       Therefore, it must be escaped 'token' before passed to function 'loginAgent'. Otherwise, incorrect result 
  //       will be obtained. 
  let token = escape(req.query.tk);    
  //-- Note: Original token contains no space characters, so that all '%20' are actually '+'. --//
  token = token.replace(/%20/g, '+');
    
  let result = smslib.loginAgent(msg_pool, token);
  result.then((url) => {
    res.redirect(url);
  }).catch((error) => {
    smslib.consoleLog(error);
    res.redirect('https://www.microsoft.com');    
  });
});


app.post('/check_new_message_count', (req, res) => {
  var user_id = parseInt(req.body.user_id, 10);
  var cookie = req.cookies.MSG_USER;
  var curr_user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, false, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        if (curr_user_id == user_id) {          
          var result = smslib.checkNewMessageCount(msg_pool, user_id, sess_code);
          result.then((data) => {
            res.send(JSON.stringify(data));
          }).catch((error) => {
            smslib.consoleLog(error);
            var data = [];
            res.send(JSON.stringify(data));
          });
        }
        else {
          //-- It is a suspicious activity, log it down and logout this user. --//
          var msg = `check_new_message_count: User ${curr_user_id} tries to extract group information which belongs to another user ${user_id}! Check for it.`;          
          smslib.consoleLog(msg);
          var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
          result.then((ok) => {
            res.redirect('/logout_msg');  
          }).catch((error) => {
            smslib.consoleLog(error);
            res.redirect('/logout_msg');
          });          
        }
      }
      else {
        res.redirect('/');        
      }
    }).catch((error) => {
      res.redirect('/');              
    });
  }
  else {
    res.redirect('/');                  
  }
});


app.get('/logout_msg', (req, res) => {
  let cookie = req.cookies.MSG_USER;    
  //-- Check 'cookie' before perform JSON parsing to prevent runtime error, in case the cookie is lost. --//
  let session = (typeof(cookie) != 'string' || wev.allTrim(cookie) == '')? {user_id: 0, sess_code: ''} : JSON.parse(cookie);   
  let user_id = parseInt(session.user_id, 10);
  let sess_code = session.sess_code.trim();

  //-- Prepare an empty cookie which will be expired immediately to replace the current session cookie. --//
  let options = {path:'/', maxAge:0, httpOnly:true, secure:true};                 
  let values = {user_id: 0, sess_code: ''};
  values = JSON.stringify(values);
  res.cookie(COOKIE_MSG, values, options);                          // Note: COOKIE_MSG = 'MSG_USER'     

  //-- Remove websocket record of logout user --//
  clients.remove(user_id);

  let html = '';
  let result = smslib.deleteSession(msg_pool, sess_code, 'MSG'); 
  result.then((url) => {
		html = `
		<script src="/js/js.cookie.min.js"></script>		
		<script src="/js/common_lib.js"></script>
		<script>
      var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);		  
		
			if (is_iOS) {
				Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
				Cookies.remove("u_id");
				Cookies.remove("m_id");
				Cookies.remove("aes_key");
				Cookies.remove("top_id");
			}
			else {
				deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
				deleteLocalStoredItem("u_id");                             
				deleteLocalStoredItem("m_id");
				deleteLocalStoredItem("aes_key");                             
				deleteLocalStoredItem("top_id");                                   
			}      
		  
			location.href = "${url}";
		</script>		
		`;
		
    res.send(html);    
  }).catch((error) => {
    smslib.consoleLog(error);
    
		html = `
		<script src="/js/js.cookie.min.js"></script>
		<script src="/js/common_lib.js"></script>		
		<script>
      var is_iOS = (navigator.userAgent.match(/(iPad|iPhone|iPod)/g)? true : false);		  
		
			if (is_iOS) {
				Cookies.remove("g_id");                                    // Defined on js.cookie.min.js
				Cookies.remove("u_id");
				Cookies.remove("m_id");
				Cookies.remove("aes_key");
				Cookies.remove("top_id");
			}
			else {
				deleteLocalStoredItem("g_id");                             // Defined on common_lib.js
				deleteLocalStoredItem("u_id");                             
				deleteLocalStoredItem("m_id");
				deleteLocalStoredItem("aes_key");                             
				deleteLocalStoredItem("top_id");                                   
			}      
		  
			location.href = "https://www.microsoft.com";
		</script>		
		`;
    
    res.send(html);
  });  
});


app.get('/logout_pda', (req, res) => {
  var cookie = req.cookies.PDA_USER;    
  //-- Check 'cookie' before perform JSON parsing to prevent runtime error, in case the cookie is lost. --//
  var session = (typeof(cookie) != 'string' || wev.allTrim(cookie) == '')? {user_id: 0, sess_code: ''} : JSON.parse(cookie);   
  var user_id = parseInt(session.user_id, 10);
  var sess_code = session.sess_code.trim();

  //-- Prepare an empty cookie which will be expired immediately to replace the current session cookie. --//
  var options = {path:'/', maxAge:0, httpOnly:true, secure:true};                 
  var values = {user_id: 0, sess_code: ''};
  values = JSON.stringify(values);
  res.cookie(COOKIE_PDA, values, options);                          // Note: COOKIE_PDA = 'PDA_USER'     

  var result = smslib.deleteSession(pda_pool, sess_code, 'PDA'); 
  result.then((url) => {
    res.redirect(url);    
  }).catch((error) => {
    smslib.consoleLog(error);
    res.redirect("/");
  });    
});


app.get('/destroy_entire_system', (req, res) => {
  var cookie = req.cookies.MSG_USER;
  var user_id = wev.getSessionUserId(cookie);
  var sess_code = wev.getSessionCode(cookie);

  if (sess_code != '' && user_id > 0) {
    var sess_checker = smslib.isSessionValid(msg_pool, user_id, sess_code, true, 'MSG');
    sess_checker.then((sess_valid) => {
      if (sess_valid) {
        var checker = msglib.isSystemAdmin(msg_pool, user_id);
        
        checker.then((is_sys_admin) => {
          if (is_sys_admin) {
            var result = msglib.destroyEntireSystem(msg_pool, pda_pool);
            
            result.then((ok) => {
              res.redirect("https://www.microsoft.com");
            }).catch((error) => {
              res.redirect("https://www.microsoft.com");
            })
          }
          else {
            //-- It is a suspicious activity, log it down and logout this user. --//
            var msg = `destroy_entire_system: User ${user_id} tries to use this function to wipe out the entire system, but he/she is not system administrator! Check for it.`;          
            smslib.consoleLog(msg);
            var result = smslib.logSystemEvent(msg_pool, user_id, msg, 'Alert', http_user_agent);
            result.then((ok) => {
              res.redirect('/logout_msg');  
            }).catch((error) => {
              smslib.consoleLog(error);
              res.redirect('/logout_msg');
            });                                                                                  
          }
        }).catch((error) => {
          smslib.consoleLog(error);
          
          var html = `<script>
                        alert("Unable to check whether you are system administrator, process is aborted."); 
                        var url = window.location.href;
                        var host = url.split('/');
                        location.href = host[0] + '//' + host[2] + '/message';
                      </script>`;
          
          res.send(html);                                        
        });
      }
      else {
        //-- The session is invalid, return to login page immediately. --//
        res.redirect('/');                                                                                            
      }
    }).catch((error) => {
      //-- The session checking process is failure, return to login page immediately. --//
      smslib.consoleLog(error);
      res.redirect('/');                                    
    });
  }
  else {
    //-- No session cookie is found, return to login page immediately. --//    
    res.redirect('/');                
  }          
});


const wss = new ws.Server({
  // 'noServer: true' means do not setup an HTTP server alongside this websocket server. The advantage to doing this 
  // is that we can share a single HTTP server (i.e. our Express server) across multiple websocket connections.  
  noServer: true,
  // Note: Client calling path and Nginx reverse proxy location name must match this path. i.e. Client calling path is
  //       'ws://<host name>:<port number>/ws' or 'wss://<host name>:<port number>/ws', and WebSocket location defined
  //       on Nginx reverse proxy server should be 'location /ws { .... }'.   
  path: "/ws",
  verifyClient: function(info, callback) {
    // 1. 'info' has the following properties: origin, secure and req. 'secure' is 'true' if 'req.connection.authorized' 
    //    or 'req.connection.encrypted' are not all null.
    // 2. Put 'true' on callback function means WebSocket connection is permitted, 'false' otherwise. 
    //
    // 'info.secure' value checking is for network security only. i.e. Does it go through a secure encrypted tunnel? If it is 
    // not, no WebSocket connection is allowed. Note: If you put the WebSocket server behind a reverse proxy server, usually 
    // you don't need to encrypt the connection between them, so this checking should be avoided. Otherwise, 'info.secure'
    // will return a 'false' value, and WebSocket connection will fail. 
    /*
    if (info.secure !== true) {
      callback(false);
      return;
    }
    */ 

    // Then a further checking is to verify whether the current user who request a WebSocket is a authorized user (by
    // value stored on the cookie). If it is not, no WebSocket connection is allowed.    
    if (typeof(info.req.headers['cookie']) == 'string') {   
      //-- Note: Ensure the argument which pass into 'cookie.parse' is a string, or else it will cause a runtime error --//
      //--       to crash the application.                                                                             --//      
      var parsed_cookie = cookie.parse(info.req.headers['cookie']);
      var cookie_value = JSON.parse(parsed_cookie.MSG_USER);
      var user_id = parseInt(cookie_value.user_id, 10);
      var sess_code = cookie_value.sess_code.trim();  

      if (user_id > 0 && sess_code != '') {
        smslib.checkSession(msg_pool, user_id, sess_code, (error, is_valid) => {
          callback(is_valid);
        });  
      }
      else {
        callback(false);
      }        
    }
    else {
      callback(false);
    }
  }
});


function wsSend(user_id, type, content) {  
  try {
    var this_client = clients.get(user_id);
    var clientSocket = this_client.socket;
    
    if (typeof(clientSocket) != 'undefined') {     
      if (clientSocket.readyState == ws.OPEN) {
        smslib.consoleLog(`User ${user_id} informed`);
        clientSocket.send(JSON.stringify({
          type: type,
          content: content
        }));
      }
    } 
  }
  catch(e) {
    smslib.consoleLog(e.message);
  }
}


function informUserToRefreshMessage(type, op, group_id, my_user_id) {
  try {
    msglib.getOtherGroupMembers(msg_pool, group_id, my_user_id, (error, members) => {
      if (!error) {
        if (Array.isArray(members)) {
          for (var i = 0; i < members.length; i++) {
            if (clients.containsKey(members[i])) {
              smslib.consoleLog(`${host}: Inform user ${members[i]} to refresh message group ${group_id}`); 
              var this_content = {op: op, group_id: group_id};
              wsSend(members[i], type, this_content); 
            }
          } 
        }
      }
    });    
  }
  catch(e) {
    smslib.consoleLog(e); 
  }
}


function informUserGroupDeleted(type, op, group_id, members) {
  try {
    if (Array.isArray(members)) {
      for (var i = 0; i < members.length; i++) {
        if (clients.containsKey(members[i].user_id)) {
          var this_content = {op: op, group_id: group_id};
          smslib.consoleLog(`${host}: Inform user ` + members[i].user_id + ` the message group ${group_id} has been deleted.`);
          wsSend(members[i].user_id, type, this_content); 
        }      
      }  
    }
  }
  catch(e) {
    smslib.consoleLog(e);
  }
}


function informUserForceLogout(type, op, users) {
  try {
    if (Array.isArray(users)) {
      for (var i = 0; i < users.length; i++) {
        if (clients.containsKey(users[i])) {
          var this_content = {op: op};
          smslib.consoleLog(`${host}: Inform user ` + users[i] + ` to logout.`);
          wsSend(users[i], type, this_content);            
        }
      }
    }
  }
  catch(e) {
    smslib.consoleLog(e);
  }
}


async function runNotificator() {
  await notificator.init();
  //-- Start listening notificator channel and install notice handler --//
  notificator.receive(noticeHandler);
}


function noticeHandler(notice) {
  if (typeof(notice) == 'object') {
    var op = notice.op;
    var content = notice.content;
    
    if (op == 'msg_refresh') {
      var type = content.type;
      var group_id = content.group_id;
      var my_user_id = content.my_user_id;
      
      informUserToRefreshMessage(type, op, group_id, my_user_id);
    }    
    else if (op == 'group_deleted') {
      var type = content.type;
      var group_id = content.group_id;
      var members = content.members;
      
      informUserGroupDeleted(type, op, group_id, members);
    }
    else if (op == 'force_logout') {
      var type = content.type;
      var users = content.users;
      
      informUserForceLogout(type, op, users);
    }
  }   
}

//-- Start notificator (notices are via RabbitMQ message broker) --//
runNotificator();

wss.on('connection', (socket, request) => {
  var parsed_cookie = cookie.parse(request.headers['cookie']);
  var cookie_value = JSON.parse(parsed_cookie.MSG_USER);
  //-- Note: Don't create any variables named 'user_id' or 'sess_code' within this block (even they are in different scope), or else --//
  //--       the value stored on 'user_id' or 'sess_code' will be lost.                                                              --//
  var user_id = cookie_value.user_id;
  var sess_code = cookie_value.sess_code;
    
  //-- Save current websocket and session details to a hash table --//
  //-- Note: User id is the record key.                           --//               
  var session = {sess_code: sess_code, socket: socket};
  clients.put(user_id, session);
  
  //-- Acknowledge client side with session code, it will be used for data encryption later.  --//
  //-- Notes: 1. It also triggers the messages loading when client enter a message group.     --//
  //--        2. The data encryption key is the secure key stored in web session now, session --//
  //--           code is no longer used for data encryption.                                  --// 
  var content = {op: 'sess_code', content: sess_code};
  wsSend(user_id, 'cmd', content); 
  
  smslib.consoleLog('Websocket is connected: user_id = ' + user_id);
  //*************  
  //smslib.consoleLog(clients.get(user_id));
  //*************  
           
  socket.on('message', (message) => {
    var msg = JSON.parse(message);

    if (msg.type == 'cmd') {
      var msg_content = msg.content;
      
      if (typeof(msg_content) == 'string') {      
        if (msg.content.trim() == 'ping') {        
          // Note: The WebSocket server just needs to response the user who issues the 'ping'
          //       request, no other users should be involved. 
          //***********
          //smslib.consoleLog('Get ping by user ' + user_id);
          //***********
                  
          socket.send(JSON.stringify({
            type: msg.type, 
            content: {op: 'pong', content: ''}
          }));
        }
        else if (msg.content.trim() == 'check_timeout') {
          // Check whether user session has been timeout. Note: Just current requested user //
          // should be response, no other users should be involved.                         //
          smslib.checkSession(msg_pool, user_id, sess_code, (error, is_valid) => {
            if (!error) {
              if (!is_valid) {
                smslib.consoleLog('Session has been timeout for user ' + user_id);
                
                socket.send(JSON.stringify({
                  type: msg.type, 
                  content: {op: 'timeout', content: 'YES'}
                }));
              }              
            }
          });         
        }
      }
      else if (typeof(msg_content) == 'object') {
        if (msg_content.op == 'group_deleted') {
          var group_id = msg_content.group_id;
          var members = msg_content.members;      // members is an array
          
          var notice = {op: msg_content.op, content: {type: msg.type, group_id: group_id, members: members}};
          notificator.notify(notice);
          smslib.consoleLog("group_deleted: User " + user_id + " has sent 'group_deleted' to notificator");
        }
        else if (msg_content.op == 'force_logout') {
          var users = msg_content.users;          // users is an array
          
          var notice = {op: msg_content.op, content: {type: msg.type, users: users}};
          notificator.notify(notice);
          smslib.consoleLog("force_logout: User " + user_id + " has sent 'force_logout' to notificator");
        }
      }
    }
    else if (msg.type == 'msg') {
      //-- Process message related operations in here. Note: 'content' is usually an object, not plain text. --//
      var content = msg.content;
      
      if (content.op == 'msg_refresh') {
        var group_id = content.group_id;
        var my_user_id = content.user_id;
        
        //-- Inform users on all app servers to handle message refresh operation which is initiated by --//
        //-- user of this app server.                                                                  --//
        var notice = {op: content.op, content: {type: msg.type, group_id: group_id, my_user_id: my_user_id}};
        notificator.notify(notice);
        smslib.consoleLog("User " + my_user_id + " has sent 'msg_refresh' to notificator");
        
        //-- Handle message refresh operation which is initiated by user of this app server --//
        //informUserToRefreshMessage(msg.type, content.op, group_id, my_user_id);                        
      }
    }
    else {
      //-- Anything else --//
      
    }    
  });
      
  var closeSocket = function(customMessage) {
    smslib.consoleLog('User ' + user_id + ' has disconnected');    
    clients.remove(user_id);     // Remove disconnected user from the hash table of clients.
  }
  
  socket.on('close', () => {
    closeSocket();
  });    
});


const server = app.listen(port, host, () => {
  smslib.consoleLog("Listening " + host + ":" + port + " ...."); 
});

// Handle WebSocket upgrade request in here
server.on('upgrade', (request, socket, head) => {  
  if (typeof(request.headers['cookie']) == "string") {
		let parsed_cookie = cookie.parse(request.headers['cookie']);
		let cookie_value = JSON.parse(parsed_cookie.MSG_USER);
		let user_id = parseInt(cookie_value.user_id, 10);
		let sess_code = cookie_value.sess_code.trim();
		
		if (user_id > 0 && sess_code != '') {
			smslib.checkSession(msg_pool, user_id, sess_code, (error, is_valid) => {
			  if (is_valid) {  
					smslib.consoleLog('Upgrade to use WebSocket');

				  wss.handleUpgrade(request, socket, head, (websocket) => {
				    wss.emit('connection', websocket, request);
				  });
			  }
			  else {
					smslib.consoleLog('Invalid session is found, reject websocket upgrade request.');
					return socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n", "ascii");
				}
			});  
		}
  }
  else {
		smslib.consoleLog('No session cookie is found, reject websocket upgrade request.');
		return socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n", "ascii");
	}  
});
