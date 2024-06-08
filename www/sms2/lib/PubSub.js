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
// V1.0.00       2020-07-20      Yurii Vlasiuk   To define an abstraction for the PubSub provider, we need to create a class that 
//                                               will call methods directly from a driver. This driver will give the implementation 
//                                               of the interaction with the RabbitMQ broker. Note: It can be any queue message
//                                               broker, provided that corresponding driver is implemented.   
// V1.0.01       2022-08-09      DW              Add license section
//#################################################################################################################################


const PubSubDriverInterface = require('./drivers/PubSubDriverInterface');

class PubSub {
    constructor(args) {
        if (!args.driver) throw new Error('"driver" is required');
        if (!(args.driver instanceof PubSubDriverInterface)) throw new Error('Driver does not implement interface of "PubSubDriverInterface"');
        this.driver = args.driver;
    }

    async connect() {
        this.connection = await this.driver.connect();

        return this.connection;
    }

    async createChannel(channel) {
        return this.driver.createChannel(channel);
    }

    publish(channel, message) {
        return this.driver.publish(channel, message);
    }

    subscribe(channel, messageHandler) {
        return this.driver.subscribe(channel, messageHandler);
    }

    close() {
        return this.driver.close();
    }
}

module.exports = PubSub;
