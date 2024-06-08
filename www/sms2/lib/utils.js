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

//###
//# Acknowledge: It is forked from https://github.com/unsigned6/notificator
//###

//#################################################################################################################################
// File name: PubSub.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2020-07-20      Yurii Vlasiuk   Commonly used utility library for Notificator.js    
// V1.0.01       2022-08-09      DW              Add license section
//#################################################################################################################################


function formatMessage(message) {
    let messageStr;

    if (typeof message === 'string') {
        messageStr = message;
    } else if (typeof message === 'object') {
        messageStr = JSON.stringify(message);
    }

    return messageStr;
}

function parseMessage(message) {
    try {
        return JSON.parse(message);
    } catch (error) {
        console.warn(`message ${message} an not be parsed as JSON`);

        return message;
    }
}

module.exports = {
    formatMessage,
    parseMessage
};
