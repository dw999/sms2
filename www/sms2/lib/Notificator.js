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
// File name: Notificator.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2020-07-20      Yurii Vlasiuk   The notificator class use to communicate multiple Node.js app instances via RabbitMQ broker.
// V1.0.01       2022-08-09      DW              Add license section
//#################################################################################################################################


class Notificator {
    constructor(args) {
        this.pubsub = args.pubsub;
        this.isInited = false;
    }

    async init() {
        if (this.isInited) return;
        try {
            console.info('Notificator initialization started...');
            await this.pubsub.connect();
            await this.pubsub.createChannel('notifications');
            this.isInited = true;
            console.info('Notificator initialization completed.');
        } catch (error) {
            console.error('Notificator initialization failed.');
            console.error(error.message);
        }
    }

    notify(message) {
        if (!this.isInited) {
            console.warn('Can not notify. Notificator not inited');

            return;
        }
        try {
            this.pubsub.publish('notifications', message);
        } catch (error) {
            console.error('Failed to notify');
            console.error(error.message);
        }
    }

    receive(messageHandler) {
        if (!this.isInited) {
            console.warn('Can not receive. Notificator not inited');

            return;
        }
        this.pubsub.subscribe('notifications', messageHandler);
    }
}

module.exports = Notificator;
