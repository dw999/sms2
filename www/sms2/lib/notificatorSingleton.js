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
// File name: notificatorSingleton.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2020-07-20      Yurii Vlasiuk   It is used to save us from filename conflicts in case-insensitive OS.
// V1.0.01       2022-08-09      DW              Add license section
//#################################################################################################################################


const { pubsub }   = require('../etc/config');
const PubSub       = require('./PubSub');
const Notificator  = require('./Notificator');
const RabbitDriver = require('./drivers/Rabbit');

const rabbitDriver = new RabbitDriver({
    endpoint : pubsub.endpoint,
    login    : pubsub.login,
    password : pubsub.password
});

const notificator = new Notificator({
    pubsub : new PubSub({
        driver : rabbitDriver
    })
});

module.exports = notificator;
