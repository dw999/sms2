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
// File name: PubSubDriverInterface.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2020-07-20      Yurii Vlasiuk   The main role of this interface is to enumerate methods and their signatures. They 
//                                               will become sort of “contract” between our application and PubSub service.
// V1.0.01       2022-08-09      DW              Add license section
//#################################################################################################################################

/* eslint-disable no-unused-vars */
class PubSubDriverInterface {
    constructor(args) {
        this.channels = {};
        this.handlers = {};
    }

    async connect() {
        throw new Error('"connect" method not implemented');
    }

    async createChannel(channel) {
        throw new Error('"createChannel" method not implemented');
    }

    publish(topic, message) {
        throw new Error('"publish" method not implemented');
    }

    subscribe(topic) {
        throw new Error('"subscribe" method not implemented');
    }

    close() {
        throw new Error('"close" method not implemented');
    }
}

module.exports = PubSubDriverInterface;
